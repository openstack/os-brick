# Copyright (c) 2021, Red Hat, Inc.
# All Rights Reserved.
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
import builtins
import errno
from unittest import mock

import ddt
from oslo_concurrency import processutils as putils

import os_brick.privileged as privsep_brick
import os_brick.privileged.nvmeof as privsep_nvme
from os_brick.privileged import rootwrap
from os_brick.tests import base


@ddt.ddt
class PrivNVMeTestCase(base.TestCase):
    def setUp(self):
        super(PrivNVMeTestCase, self).setUp()

        # Disable privsep server/client mode
        privsep_brick.default.set_client_mode(False)
        self.addCleanup(privsep_brick.default.set_client_mode, True)

    @mock.patch('os.chmod')
    @mock.patch.object(builtins, 'open', new_callable=mock.mock_open)
    @mock.patch('os.makedirs')
    @mock.patch.object(rootwrap, 'custom_execute')
    def test_create_hostnqn(self, mock_exec, mock_mkdirs, mock_open,
                            mock_chmod):
        hostnqn = mock.Mock()
        mock_exec.return_value = (hostnqn, mock.sentinel.err)

        res = privsep_nvme.create_hostnqn()

        mock_mkdirs.assert_called_once_with('/etc/nvme',
                                            mode=0o755,
                                            exist_ok=True)
        mock_exec.assert_called_once_with('nvme', 'show-hostnqn')
        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'w')
        stripped_hostnqn = hostnqn.strip.return_value
        mock_open().write.assert_called_once_with(stripped_hostnqn)
        mock_chmod.assert_called_once_with('/etc/nvme/hostnqn', 0o644)
        self.assertEqual(stripped_hostnqn, res)

    @mock.patch('os.chmod')
    @mock.patch.object(builtins, 'open', new_callable=mock.mock_open)
    @mock.patch('os.makedirs')
    @mock.patch.object(rootwrap, 'custom_execute')
    def test_create_hostnqn_generate(self, mock_exec, mock_mkdirs, mock_open,
                                     mock_chmod):
        hostnqn = mock.Mock()
        mock_exec.side_effect = [
            putils.ProcessExecutionError(exit_code=errno.ENOENT,
                                         stdout="totally exist sub-command"),
            (hostnqn, mock.sentinel.err)
        ]

        res = privsep_nvme.create_hostnqn()

        mock_mkdirs.assert_called_once_with('/etc/nvme',
                                            mode=0o755,
                                            exist_ok=True)
        self.assertEqual(2, mock_exec.call_count)
        mock_exec.assert_has_calls([mock.call('nvme', 'show-hostnqn'),
                                    mock.call('nvme', 'gen-hostnqn')])

        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'w')
        stripped_hostnqn = hostnqn.strip.return_value
        mock_open().write.assert_called_once_with(stripped_hostnqn)
        mock_chmod.assert_called_once_with('/etc/nvme/hostnqn', 0o644)
        self.assertEqual(stripped_hostnqn, res)

    @mock.patch('os.chmod')
    @mock.patch.object(builtins, 'open', new_callable=mock.mock_open)
    @mock.patch('os.makedirs')
    @mock.patch.object(rootwrap, 'custom_execute')
    def test_create_hostnqn_generate_old_nvme_cli(self, mock_exec, mock_mkdirs,
                                                  mock_open, mock_chmod):
        hostnqn = mock.Mock()
        mock_exec.side_effect = [
            putils.ProcessExecutionError(
                exit_code=231,
                stdout="error: Invalid sub-command\n"),
            (hostnqn, mock.sentinel.err)
        ]

        res = privsep_nvme.create_hostnqn()

        mock_mkdirs.assert_called_once_with('/etc/nvme',
                                            mode=0o755,
                                            exist_ok=True)
        self.assertEqual(2, mock_exec.call_count)
        mock_exec.assert_has_calls([mock.call('nvme', 'show-hostnqn'),
                                    mock.call('nvme', 'gen-hostnqn')])

        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'w')
        stripped_hostnqn = hostnqn.strip.return_value
        mock_open().write.assert_called_once_with(stripped_hostnqn)
        mock_chmod.assert_called_once_with('/etc/nvme/hostnqn', 0o644)
        self.assertEqual(stripped_hostnqn, res)

    @ddt.data(OSError(errno.ENOENT),  # nvme not present in system
              putils.ProcessExecutionError(exit_code=123))  # nvme error
    @mock.patch('os.makedirs')
    @mock.patch.object(rootwrap, 'custom_execute')
    def test_create_hostnqn_nvme_not_present(self, exception,
                                             mock_exec, mock_mkdirs):
        mock_exec.side_effect = exception
        res = privsep_nvme.create_hostnqn()
        mock_mkdirs.assert_called_once_with('/etc/nvme',
                                            mode=0o755,
                                            exist_ok=True)
        mock_exec.assert_called_once_with('nvme', 'show-hostnqn')
        self.assertEqual('', res)
