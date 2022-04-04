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

from unittest import mock

import ddt
from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick import privileged
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests import base


@ddt.ddt
class PrivRootwrapTestCase(base.TestCase):
    def setUp(self):
        super(PrivRootwrapTestCase, self).setUp()

        # Bypass privsep and run these simple functions in-process
        # (allows reading back the modified state of mocks)
        privileged.default.set_client_mode(False)
        self.addCleanup(privileged.default.set_client_mode, True)

    @mock.patch('os_brick.privileged.rootwrap.execute_root')
    @mock.patch('oslo_concurrency.processutils.execute')
    def test_execute(self, mock_putils_exec, mock_exec_root):
        priv_rootwrap.execute('echo', 'foo', run_as_root=False)
        self.assertFalse(mock_exec_root.called)

        priv_rootwrap.execute('echo', 'foo', run_as_root=True,
                              root_helper='baz', check_exit_code=0)
        mock_exec_root.assert_called_once_with(
            'echo', 'foo', check_exit_code=0)

    @mock.patch('oslo_concurrency.processutils.execute')
    def test_execute_root(self, mock_putils_exec):
        priv_rootwrap.execute_root('echo', 'foo', check_exit_code=0)
        mock_putils_exec.assert_called_once_with(
            'echo', 'foo', check_exit_code=0, shell=False, run_as_root=False,
            delay_on_retry=False, on_completion=mock.ANY, on_execute=mock.ANY)

        # Exact exception isn't particularly important, but these
        # should be errors:
        self.assertRaises(TypeError,
                          priv_rootwrap.execute_root, 'foo', shell=True)
        self.assertRaises(TypeError,
                          priv_rootwrap.execute_root, 'foo', run_as_root=True)

    @mock.patch('oslo_concurrency.processutils.execute',
                side_effect=OSError(42, 'mock error'))
    def test_oserror_raise(self, mock_putils_exec):
        self.assertRaises(putils.ProcessExecutionError,
                          priv_rootwrap.execute, 'foo')

    @mock.patch.object(priv_rootwrap.execute_root.privsep_entrypoint,
                       'client_mode', False)
    @mock.patch.object(priv_rootwrap, 'custom_execute')
    def test_execute_as_root(self, exec_mock):
        res = priv_rootwrap.execute(mock.sentinel.cmds, run_as_root=True,
                                    root_helper=mock.sentinel.root_helper,
                                    keyword_arg=mock.sentinel.kwarg)
        self.assertEqual(exec_mock.return_value, res)
        exec_mock.assert_called_once_with(mock.sentinel.cmds, shell=False,
                                          run_as_root=False,
                                          keyword_arg=mock.sentinel.kwarg)

    @mock.patch('threading.Timer')
    def test_custom_execute_default_timeout(self, mock_timer):
        """Confirm timeout defaults to 600 and the thread timer is started."""
        priv_rootwrap.custom_execute('echo', 'hola')
        mock_timer.assert_called_once_with(600, mock.ANY, mock.ANY)
        mock_timer.return_value.start.assert_called_once_with()

    def test_custom_execute_callbacks(self):
        """Confirm execute callbacks are called on execute."""
        on_execute = mock.Mock()
        on_completion = mock.Mock()
        msg = 'hola'
        out, err = priv_rootwrap.custom_execute('echo', msg,
                                                on_execute=on_execute,
                                                on_completion=on_completion)
        self.assertEqual(msg + '\n', out)
        self.assertEqual('', err)
        on_execute.assert_called_once_with(mock.ANY)
        proc = on_execute.call_args[0][0]
        on_completion.assert_called_once_with(proc)

    @mock.patch('os_brick.utils._time_sleep')
    def test_custom_execute_timeout_raises_with_retries(self, sleep_mock):
        on_execute = mock.Mock()
        on_completion = mock.Mock()
        self.assertRaises(exception.ExecutionTimeout,
                          priv_rootwrap.custom_execute,
                          'sleep', '2', timeout=0.05, raise_timeout=True,
                          interval=2, backoff_rate=3, attempts=3,
                          on_execute=on_execute, on_completion=on_completion)
        sleep_mock.assert_has_calls([mock.call(0), mock.call(6), mock.call(0),
                                     mock.call(18), mock.call(0)])
        expected_calls = [mock.call(args[0][0])
                          for args in on_execute.call_args_list]
        on_execute.assert_has_calls(expected_calls)
        on_completion.assert_has_calls(expected_calls)

    def test_custom_execute_timeout_no_raise(self):
        out, err = priv_rootwrap.custom_execute('sleep', '2', timeout=0.05,
                                                raise_timeout=False)
        self.assertEqual('', out)
        self.assertIsInstance(err, str)

    def test_custom_execute_check_exit_code(self):
        self.assertRaises(putils.ProcessExecutionError,
                          priv_rootwrap.custom_execute,
                          'ls', '-y', check_exit_code=True)

    def test_custom_execute_no_check_exit_code(self):
        out, err = priv_rootwrap.custom_execute('ls', '-y',
                                                check_exit_code=False)
        self.assertEqual('', out)
        self.assertIsInstance(err, str)

    @mock.patch.object(priv_rootwrap.unlink_root.privsep_entrypoint,
                       'client_mode', False)
    @mock.patch('os.unlink', side_effect=IOError)
    def test_unlink_root(self, unlink_mock):
        links = ['/dev/disk/by-id/link1', '/dev/disk/by-id/link2']
        priv_rootwrap.unlink_root(*links, no_errors=True)
        unlink_mock.assert_has_calls([mock.call(links[0]),
                                      mock.call(links[1])])

    @mock.patch.object(priv_rootwrap.unlink_root.privsep_entrypoint,
                       'client_mode', False)
    @mock.patch('os.unlink', side_effect=IOError)
    def test_unlink_root_raise(self, unlink_mock):
        links = ['/dev/disk/by-id/link1', '/dev/disk/by-id/link2']
        self.assertRaises(IOError,
                          priv_rootwrap.unlink_root,
                          *links, no_errors=False)
        unlink_mock.assert_called_once_with(links[0])

    @mock.patch.object(priv_rootwrap.unlink_root.privsep_entrypoint,
                       'client_mode', False)
    @mock.patch('os.unlink', side_effect=IOError)
    def test_unlink_root_raise_at_end(self, unlink_mock):
        links = ['/dev/disk/by-id/link1', '/dev/disk/by-id/link2']
        self.assertRaises(exception.ExceptionChainer,
                          priv_rootwrap.unlink_root,
                          *links, raise_at_end=True)
        unlink_mock.assert_has_calls([mock.call(links[0]),
                                      mock.call(links[1])])

    @mock.patch.object(priv_rootwrap.unlink_root.privsep_entrypoint,
                       'client_mode', False)
    @mock.patch('os.symlink')
    @mock.patch('os.remove')
    def test_link_root_no_force(self, mock_remove, mock_link):
        priv_rootwrap.link_root(mock.sentinel.target, mock.sentinel.link_name,
                                force=False)
        mock_remove.assert_not_called()
        mock_link.assert_called_once_with(mock.sentinel.target,
                                          mock.sentinel.link_name)

    @ddt.data(None, FileNotFoundError)
    @mock.patch.object(priv_rootwrap.unlink_root.privsep_entrypoint,
                       'client_mode', False)
    @mock.patch('os.symlink')
    @mock.patch('os.remove')
    def test_link_root_force(self, remove_effect, mock_remove, mock_link):
        mock_remove.side_effect = remove_effect
        priv_rootwrap.link_root(mock.sentinel.target, mock.sentinel.link_name)
        mock_remove.assert_called_once_with(mock.sentinel.link_name)
        mock_link.assert_called_once_with(mock.sentinel.target,
                                          mock.sentinel.link_name)

    @mock.patch.object(priv_rootwrap.unlink_root.privsep_entrypoint,
                       'client_mode', False)
    @mock.patch('os.symlink')
    @mock.patch('os.remove', side_effect=IndexError)  # Non not found error
    def test_link_root_force_fail(self, mock_remove, mock_link):
        self.assertRaises(IndexError,
                          priv_rootwrap.link_root,
                          mock.sentinel.target, mock.sentinel.link_name)
        mock_remove.assert_called_once_with(mock.sentinel.link_name)
        mock_link.assert_not_called()
