# (c) Copyright 2015 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import functools
import io
import time
from unittest import mock

import ddt

from os_brick import exception
from os_brick.tests import base
from os_brick import utils


class WrongException(exception.BrickException):
    pass


class TestRetryDecorator(base.TestCase):

    def test_no_retry_required(self):
        self.counter = 0

        with mock.patch.object(utils, '_time_sleep') as mock_sleep:
            @utils.retry(exception.VolumeDeviceNotFound,
                         interval=2,
                         retries=3,
                         backoff_rate=2)
            def succeeds():
                self.counter += 1
                return 'success'

            ret = succeeds()
            self.assertFalse(mock_sleep.called)
            self.assertEqual('success', ret)
            self.assertEqual(1, self.counter)

    def test_retries_once(self):
        self.counter = 0
        interval = 2
        backoff_rate = 2
        retries = 3

        with mock.patch.object(utils, '_time_sleep') as mock_sleep:
            @utils.retry(exception.VolumeDeviceNotFound,
                         interval,
                         retries,
                         backoff_rate)
            def fails_once():
                self.counter += 1
                if self.counter < 2:
                    raise exception.VolumeDeviceNotFound(device='fake')
                else:
                    return 'success'

            ret = fails_once()
            self.assertEqual('success', ret)
            self.assertEqual(2, self.counter)
            self.assertEqual(1, mock_sleep.call_count)
            mock_sleep.assert_called_with(interval)

    def test_limit_is_reached(self):
        self.counter = 0
        retries = 3
        interval = 2
        backoff_rate = 4

        with mock.patch.object(utils, '_time_sleep') as mock_sleep:
            @utils.retry(exception.VolumeDeviceNotFound,
                         interval,
                         retries,
                         backoff_rate)
            def always_fails():
                self.counter += 1
                raise exception.VolumeDeviceNotFound(device='fake')

            self.assertRaises(exception.VolumeDeviceNotFound,
                              always_fails)
            self.assertEqual(retries, self.counter)

            expected_sleep_arg = []

            for i in range(retries):
                if i > 0:
                    interval *= (backoff_rate ** (i - 1))
                    expected_sleep_arg.append(float(interval))

            mock_sleep.assert_has_calls(
                list(map(mock.call, expected_sleep_arg)))

    def test_wrong_exception_no_retry(self):

        with mock.patch.object(utils, '_time_sleep') as mock_sleep:
            @utils.retry(exception.VolumeDeviceNotFound)
            def raise_unexpected_error():
                raise WrongException("wrong exception")

            self.assertRaises(WrongException, raise_unexpected_error)
            self.assertFalse(mock_sleep.called)

    @mock.patch('tenacity.nap.sleep')
    def test_retry_exit_code(self, sleep_mock):
        exit_code = 5
        exception = utils.processutils.ProcessExecutionError

        @utils.retry(retry=utils.retry_if_exit_code, retry_param=exit_code)
        def raise_retriable_exit_code():
            raise exception(exit_code=exit_code)
        self.assertRaises(exception, raise_retriable_exit_code)
        self.assertEqual(0, sleep_mock.call_count)

    @mock.patch('tenacity.nap.sleep')
    def test_retry_exit_code_non_retriable(self, sleep_mock):
        exit_code = 5
        exception = utils.processutils.ProcessExecutionError

        @utils.retry(retry=utils.retry_if_exit_code, retry_param=exit_code)
        def raise_non_retriable_exit_code():
            raise exception(exit_code=exit_code + 1)
        self.assertRaises(exception, raise_non_retriable_exit_code)
        sleep_mock.assert_not_called()


class LogTracingTestCase(base.TestCase):
    """Test out the log tracing."""

    def test_utils_trace_method_default_logger(self):
        mock_log = self.mock_object(utils, 'LOG')

        @utils.trace
        def _trace_test_method_custom_logger(*args, **kwargs):
            return 'OK'

        result = _trace_test_method_custom_logger()

        self.assertEqual('OK', result)
        self.assertEqual(2, mock_log.debug.call_count)

    def test_utils_trace_method_inner_decorator(self):
        mock_logging = self.mock_object(utils, 'logging')
        mock_log = mock.Mock()
        mock_log.isEnabledFor = lambda x: True
        mock_logging.getLogger = mock.Mock(return_value=mock_log)

        def _test_decorator(f):
            def blah(*args, **kwargs):
                return f(*args, **kwargs)
            return blah

        @_test_decorator
        @utils.trace
        def _trace_test_method(*args, **kwargs):
            return 'OK'

        result = _trace_test_method(self)

        self.assertEqual('OK', result)
        self.assertEqual(2, mock_log.debug.call_count)
        # Ensure the correct function name was logged
        for call in mock_log.debug.call_args_list:
            self.assertIn('_trace_test_method', str(call))
            self.assertNotIn('blah', str(call))

    def test_utils_trace_method_outer_decorator(self):
        mock_logging = self.mock_object(utils, 'logging')
        mock_log = mock.Mock()
        mock_log.isEnabledFor = lambda x: True
        mock_logging.getLogger = mock.Mock(return_value=mock_log)

        def _test_decorator(f):
            def blah(*args, **kwargs):
                return f(*args, **kwargs)
            return blah

        @utils.trace
        @_test_decorator
        def _trace_test_method(*args, **kwargs):
            return 'OK'

        result = _trace_test_method(self)

        self.assertEqual('OK', result)
        self.assertEqual(2, mock_log.debug.call_count)
        # Ensure the incorrect function name was logged
        for call in mock_log.debug.call_args_list:
            self.assertNotIn('_trace_test_method', str(call))
            self.assertIn('blah', str(call))

    def test_utils_trace_method_outer_decorator_with_functools(self):
        mock_log = mock.Mock()
        mock_log.isEnabledFor = lambda x: True
        self.mock_object(utils.logging, 'getLogger', mock_log)
        mock_log = self.mock_object(utils, 'LOG')

        def _test_decorator(f):
            @functools.wraps(f)
            def wraps(*args, **kwargs):
                return f(*args, **kwargs)
            return wraps

        @utils.trace
        @_test_decorator
        def _trace_test_method(*args, **kwargs):
            return 'OK'

        result = _trace_test_method()

        self.assertEqual('OK', result)
        self.assertEqual(2, mock_log.debug.call_count)
        # Ensure the incorrect function name was logged
        for call in mock_log.debug.call_args_list:
            self.assertIn('_trace_test_method', str(call))
            self.assertNotIn('wraps', str(call))

    def test_utils_trace_method_with_exception(self):
        self.LOG = self.mock_object(utils, 'LOG')

        @utils.trace
        def _trace_test_method(*args, **kwargs):
            raise exception.VolumeDeviceNotFound('test message')

        self.assertRaises(exception.VolumeDeviceNotFound, _trace_test_method)

        exception_log = self.LOG.debug.call_args_list[1]
        self.assertIn('exception', str(exception_log))
        self.assertIn('test message', str(exception_log))

    def test_utils_trace_method_with_time(self):
        mock_logging = self.mock_object(utils, 'logging')
        mock_log = mock.Mock()
        mock_log.isEnabledFor = lambda x: True
        mock_logging.getLogger = mock.Mock(return_value=mock_log)

        mock_time = mock.Mock(side_effect=[3.1, 6])
        self.mock_object(time, 'time', mock_time)

        @utils.trace
        def _trace_test_method(*args, **kwargs):
            return 'OK'

        result = _trace_test_method(self)

        self.assertEqual('OK', result)
        return_log = mock_log.debug.call_args_list[1]
        self.assertIn('2900', str(return_log))

    def test_utils_trace_method_with_password_dict(self):
        mock_logging = self.mock_object(utils, 'logging')
        mock_log = mock.Mock()
        mock_log.isEnabledFor = lambda x: True
        mock_logging.getLogger = mock.Mock(return_value=mock_log)

        @utils.trace
        def _trace_test_method(*args, **kwargs):
            return {'something': 'test',
                    'password': 'Now you see me'}

        result = _trace_test_method(self)
        expected_unmasked_dict = {'something': 'test',
                                  'password': 'Now you see me'}

        self.assertEqual(expected_unmasked_dict, result)
        self.assertEqual(2, mock_log.debug.call_count)
        self.assertIn("'password': '***'",
                      str(mock_log.debug.call_args_list[1]))

    def test_utils_trace_method_with_password_str(self):
        mock_logging = self.mock_object(utils, 'logging')
        mock_log = mock.Mock()
        mock_log.isEnabledFor = lambda x: True
        mock_logging.getLogger = mock.Mock(return_value=mock_log)

        @utils.trace
        def _trace_test_method(*args, **kwargs):
            return "'adminPass': 'Now you see me'"

        result = _trace_test_method(self)
        expected_unmasked_str = "'adminPass': 'Now you see me'"

        self.assertEqual(expected_unmasked_str, result)
        self.assertEqual(2, mock_log.debug.call_count)
        self.assertIn("'adminPass': '***'",
                      str(mock_log.debug.call_args_list[1]))

    def test_utils_trace_method_with_password_in_formal_params(self):
        mock_logging = self.mock_object(utils, 'logging')
        mock_log = mock.Mock()
        mock_log.isEnabledFor = lambda x: True
        mock_logging.getLogger = mock.Mock(return_value=mock_log)

        @utils.trace
        def _trace_test_method(*args, **kwargs):
            self.assertEqual('verybadpass',
                             kwargs['connection']['data']['auth_password'])
            pass

        connector_properties = {
            'data': {
                'auth_password': 'verybadpass'
            }
        }
        _trace_test_method(self, connection=connector_properties)

        self.assertEqual(2, mock_log.debug.call_count)
        self.assertIn("'auth_password': '***'",
                      str(mock_log.debug.call_args_list[0]))


@ddt.ddt
class GetDevPathTestCase(base.TestCase):
    """Test the get_dev_path method."""
    @ddt.data({'con_props': {}, 'dev_info': {'path': '/dev/sda'}},
              {'con_props': {}, 'dev_info': {'path': b'/dev/sda'}},
              {'con_props': None, 'dev_info': {'path': '/dev/sda'}},
              {'con_props': None, 'dev_info': {'path': b'/dev/sda'}},
              {'con_props': {'device_path': b'/dev/sdb'},
               'dev_info': {'path': '/dev/sda'}},
              {'con_props': {'device_path': '/dev/sdb'},
               'dev_info': {'path': b'/dev/sda'}})
    @ddt.unpack
    def test_get_dev_path_device_info(self, con_props, dev_info):
        self.assertEqual('/dev/sda', utils.get_dev_path(con_props, dev_info))

    @ddt.data({'con_props': {'device_path': '/dev/sda'},
               'dev_info': {'path': None}},
              {'con_props': {'device_path': b'/dev/sda'},
               'dev_info': {'path': None}},
              {'con_props': {'device_path': '/dev/sda'},
               'dev_info': {'path': ''}},
              {'con_props': {'device_path': b'/dev/sda'},
               'dev_info': {'path': ''}},
              {'con_props': {'device_path': '/dev/sda'},
               'dev_info': {}},
              {'con_props': {'device_path': b'/dev/sda'},
               'dev_info': {}},
              {'con_props': {'device_path': '/dev/sda'},
               'dev_info': None},
              {'con_props': {'device_path': b'/dev/sda'},
               'dev_info': None})
    @ddt.unpack
    def test_get_dev_path_conn_props(self, con_props, dev_info):
        self.assertEqual('/dev/sda', utils.get_dev_path(con_props, dev_info))

    @ddt.data({'con_props': {'device_path': ''}, 'dev_info': {'path': None}},
              {'con_props': {'device_path': None}, 'dev_info': {'path': ''}},
              {'con_props': {}, 'dev_info': {}},
              {'con_props': {}, 'dev_info': None})
    @ddt.unpack
    def test_get_dev_path_no_path(self, con_props, dev_info):
        self.assertEqual('', utils.get_dev_path(con_props, dev_info))


@ddt.ddt
class ConnectionPropertiesDecoratorsTestCase(base.TestCase):
    def test__symlink_name_from_device_path(self):
        """Get symlink for non replicated device."""
        dev_name = '/dev/nvme0n1'
        res = utils._symlink_name_from_device_path(dev_name)
        self.assertEqual('/dev/disk/by-id/os-brick+dev+nvme0n1', res)

    def test__symlink_name_from_device_path_raid(self):
        """Get symlink for replicated device."""
        dev_name = '/dev/md/alias'
        res = utils._symlink_name_from_device_path(dev_name)
        self.assertEqual('/dev/disk/by-id/os-brick+dev+md+alias', res)

    def test__device_path_from_symlink(self):
        """Get device name for non replicated symlink."""
        symlink = '/dev/disk/by-id/os-brick+dev+nvme0n1'
        res = utils._device_path_from_symlink(symlink)
        self.assertEqual('/dev/nvme0n1', res)

    def test__device_path_from_symlink_raid(self):
        """Get device name for replicated symlink."""
        symlink = '/dev/disk/by-id/os-brick+dev+md+alias'
        res = utils._device_path_from_symlink(symlink)
        self.assertEqual('/dev/md/alias', res)

    def test__device_path_from_symlink_file_handle(self):
        """Get device name for a file handle (eg: RBD)."""
        handle = io.StringIO()
        res = utils._device_path_from_symlink(handle)
        self.assertEqual(handle, res)

    @ddt.data(({}, {'type': 'block', 'path': '/dev/sda'}),
              ({'encrypted': False}, {'type': 'block', 'path': '/dev/sda'}),
              ({'encrypted': False}, {'type': 'block', 'path': b'/dev/sda'}),
              ({'encrypted': True}, {'type': 'block', 'path': io.StringIO()}))
    @ddt.unpack
    @mock.patch('os_brick.utils._symlink_name_from_device_path')
    @mock.patch('os.path.realpath')
    @mock.patch('os_brick.privileged.rootwrap.link_root')
    def test_connect_volume_prepare_result_non_encrypted(
            self, conn_props, result, mock_link, mock_path, mock_get_symlink):
        """Test decorator for non encrypted devices or non host devices."""
        testing_self = mock.Mock()
        testing_self.connect_volume.return_value = result
        func = utils.connect_volume_prepare_result(testing_self.connect_volume)

        res = func(testing_self, conn_props)
        self.assertEqual(testing_self.connect_volume.return_value, res)

        testing_self.connect_volume.assert_called_once_with(testing_self,
                                                            conn_props)
        mock_path.assert_not_called()
        mock_get_symlink.assert_not_called()
        mock_link.assert_not_called()

    @ddt.data('/dev/md/alias', b'/dev/md/alias')
    @mock.patch('os_brick.utils._symlink_name_from_device_path')
    @mock.patch('os.path.realpath')
    @mock.patch('os_brick.privileged.rootwrap.link_root')
    def test_connect_volume_prepare_result_encrypted(
            self, connector_path, mock_link, mock_path, mock_get_symlink):
        """Test decorator for encrypted device."""
        real_device = '/dev/md-6'
        expected_symlink = '/dev/disk/by-id/os-brick_dev_md_alias'
        mock_path.return_value = real_device
        mock_get_symlink.return_value = expected_symlink
        testing_self = mock.Mock()
        testing_self.connect_volume.return_value = {'type': 'block',
                                                    'path': connector_path}
        conn_props = {'encrypted': True}
        func = utils.connect_volume_prepare_result(testing_self.connect_volume)

        res = func(testing_self, conn_props)
        self.assertEqual({'type': 'block', 'path': expected_symlink}, res)

        testing_self.connect_volume.assert_called_once_with(testing_self,
                                                            conn_props)
        expected_connector_path = utils.convert_str(connector_path)
        mock_get_symlink.assert_called_once_with(expected_connector_path)
        mock_link.assert_called_once_with(real_device, expected_symlink,
                                          force=True)

    @ddt.data({}, {'encrypted': False}, {'encrypted': True})
    @mock.patch('os_brick.utils._symlink_name_from_device_path')
    @mock.patch('os.path.realpath')
    @mock.patch('os_brick.privileged.rootwrap.link_root')
    def test_connect_volume_prepare_result_connect_fail(
            self, conn_props, mock_link, mock_path, mock_get_symlink):
        """Test decorator when decorated function fails."""
        testing_self = mock.Mock()
        testing_self.connect_volume.side_effect = ValueError

        func = utils.connect_volume_prepare_result(testing_self.connect_volume)
        self.assertRaises(ValueError, func, testing_self, conn_props)
        mock_link.assert_not_called()
        mock_path.assert_not_called()
        mock_get_symlink.assert_not_called()

    @mock.patch('os_brick.utils._symlink_name_from_device_path')
    @mock.patch('os.path.realpath')
    @mock.patch('os_brick.privileged.rootwrap.link_root')
    def test_connect_volume_prepare_result_symlink_fail(
            self, mock_link, mock_path, mock_get_symlink):
        """Test decorator for encrypted device failing on the symlink."""
        real_device = '/dev/md-6'
        connector_path = '/dev/md/alias'
        expected_symlink = '/dev/disk/by-id/os-brick_dev_md_alias'
        mock_path.return_value = real_device
        mock_get_symlink.return_value = expected_symlink
        testing_self = mock.Mock()
        connect_result = {'type': 'block', 'path': connector_path}
        mock_link.side_effect = ValueError

        testing_self.connect_volume.return_value = connect_result
        conn_props = {'encrypted': True}
        func = utils.connect_volume_prepare_result(testing_self.connect_volume)

        self.assertRaises(ValueError, func, testing_self, conn_props)

        testing_self.connect_volume.assert_called_once_with(testing_self,
                                                            conn_props)
        mock_get_symlink.assert_called_once_with(connector_path)
        mock_link.assert_called_once_with(real_device, expected_symlink,
                                          force=True)
        testing_self.disconnect_volume.assert_called_once_with(
            connect_result, force=True, ignore_errors=True)

    @ddt.data(({'device_path': '/dev/md/alias'}, {}),
              ({'device_path': '/dev/md/alias', 'encrypted': False}, None),
              ({'device_path': '/dev/md/alias'}, {'path': '/dev/md/alias'}),
              ({'device_path': '/dev/md/alias', 'encrypted': False},
               {'path': '/dev/md/alias'}),
              ({'device_path': io.StringIO(), 'encrypted': True}, None),
              ({'device_path': '/dev/disk/by-id/wwn-...', 'encrypted': True},
               None))
    @ddt.unpack
    @mock.patch('os_brick.utils._device_path_from_symlink')
    @mock.patch('os_brick.privileged.rootwrap.unlink_root')
    def test_connect_volume_undo_prepare_result_non_custom_link(
            outer_self, conn_props, dev_info, mock_unlink, mock_dev_path):

        class Test(object):
            @utils.connect_volume_undo_prepare_result(unlink_after=True)
            def disconnect_volume(self, connection_properties, device_info,
                                  force=False, ignore_errors=False):
                outer_self.assertEqual(conn_props, connection_properties)
                outer_self.assertEqual(dev_info, device_info)
                return 'disconnect_volume'

            @utils.connect_volume_undo_prepare_result
            def extend_volume(self, connection_properties):
                outer_self.assertEqual(conn_props, connection_properties)
                return 'extend_volume'

        path = conn_props['device_path']
        mock_dev_path.return_value = path

        t = Test()

        res = t.disconnect_volume(conn_props, dev_info)
        outer_self.assertEqual('disconnect_volume', res)

        res = t.extend_volume(conn_props)
        outer_self.assertEqual('extend_volume', res)

        if conn_props.get('encrypted'):
            outer_self.assertEqual(2, mock_dev_path.call_count)
            mock_dev_path.assert_has_calls((mock.call(path), mock.call(path)))
        else:
            mock_dev_path.assert_not_called()
        mock_unlink.assert_not_called()

    @mock.patch('os_brick.utils._device_path_from_symlink')
    @mock.patch('os_brick.privileged.rootwrap.unlink_root')
    def test_connect_volume_undo_prepare_result_encrypted_disconnect(
            outer_self, mock_unlink, mock_dev_path):
        connector_path = '/dev/md/alias'
        mock_dev_path.return_value = connector_path
        symlink_path = '/dev/disk/by-id/os-brick_dev_md_alias'
        mock_unlink.side_effect = ValueError

        class Test(object):
            @utils.connect_volume_undo_prepare_result(unlink_after=True)
            def disconnect_volume(self, connection_properties, device_info,
                                  force=False, ignore_errors=False):
                outer_self.assertEqual(connector_path,
                                       connection_properties['device_path'])
                outer_self.assertEqual(connector_path,
                                       device_info['path'])
                return 'disconnect_volume'

        conn_props = {'target_portal': '198.72.124.185:3260',
                      'target_iqn': 'iqn.2010-10.org.openstack:volume-uuid',
                      'target_lun': 0,
                      'encrypted': True,
                      'device_path': symlink_path}
        dev_info = {'type': 'block', 'path': symlink_path}

        t = Test()
        res = t.disconnect_volume(conn_props, dev_info)

        outer_self.assertEqual('disconnect_volume', res)
        mock_dev_path.assert_called_once_with(symlink_path)
        mock_unlink.assert_called_once_with(symlink_path)

    @mock.patch('os_brick.utils._device_path_from_symlink')
    @mock.patch('os_brick.privileged.rootwrap.unlink_root')
    def test_connect_volume_undo_prepare_result_encrypted_extend(
            outer_self, mock_unlink, mock_dev_path):
        connector_path = '/dev/md/alias'
        mock_dev_path.return_value = connector_path
        symlink_path = '/dev/disk/by-id/os-brick_dev_md_alias'
        mock_unlink.side_effect = ValueError

        class Test(object):
            @utils.connect_volume_undo_prepare_result
            def extend_volume(self, connection_properties):
                outer_self.assertEqual(connector_path,
                                       connection_properties['device_path'])
                return 'extend_volume'

        conn_props = {'target_portal': '198.72.124.185:3260',
                      'target_iqn': 'iqn.2010-10.org.openstack:volume-uuid',
                      'target_lun': 0,
                      'encrypted': True,
                      'device_path': symlink_path}

        t = Test()
        res = t.extend_volume(conn_props)

        outer_self.assertEqual('extend_volume', res)
        mock_dev_path.assert_called_once_with(symlink_path)
        mock_unlink.assert_not_called()
