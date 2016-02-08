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

import mock

from oslo_concurrency import processutils as putils

from os_brick import privileged
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests import base


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
            'echo', 'foo', check_exit_code=0, shell=False, run_as_root=False)

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
