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
import time
from unittest import mock

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
