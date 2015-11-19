# Copyright (c) 2013 The Johns Hopkins University/Applied Physics Laboratory
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


import mock

from os_brick.encryptors import luks
from os_brick.tests.encryptors import test_cryptsetup
from oslo_concurrency import processutils as putils


class LuksEncryptorTestCase(test_cryptsetup.CryptsetupEncryptorTestCase):
    def _create(self, root_helper, connection_info, keymgr, execute):
        return luks.LuksEncryptor(root_helper=root_helper,
                                  connection_info=connection_info,
                                  keymgr=keymgr,
                                  execute=execute)

    def test_is_luks(self):
        luks.is_luks(self.root_helper, self.dev_path)

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      run_as_root=True, root_helper=self.root_helper,
                      check_exit_code=True),
        ], any_order=False)
        self.assertEqual(1, self.mock_execute.call_count)

    @mock.patch('os_brick.encryptors.luks.LOG')
    def test_is_luks_with_error(self, mock_log):
        error_msg = "Device %s is not a valid LUKS device." % self.dev_path
        self.mock_execute.side_effect = \
            putils.ProcessExecutionError(exit_code=1,
                                         stderr=error_msg)

        luks.is_luks(self.root_helper, self.dev_path)

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      run_as_root=True, root_helper=self.root_helper,
                      check_exit_code=True),
        ])
        self.assertEqual(1, self.mock_execute.call_count)

        self.assertEqual(1, mock_log.warning.call_count)  # warning logged

    def test_is_luks_with_execute(self):
        mock_execute = mock.Mock()
        luks.is_luks(self.root_helper, self.dev_path, execute=mock_execute)
        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      run_as_root=True, root_helper=self.root_helper,
                      check_exit_code=True),
        ])

    def test__format_volume(self):
        self.encryptor._format_volume("passphrase")

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', '--batch-mode', 'luksFormat',
                      '--key-file=-', self.dev_path,
                      process_input='passphrase',
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True, attempts=3),
        ])
        self.assertEqual(1, self.mock_execute.call_count)

    def test__open_volume(self):
        self.encryptor._open_volume("passphrase")

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input='passphrase',
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ])
        self.assertEqual(1, self.mock_execute.call_count)

    def test_attach_volume(self):
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = (
            test_cryptsetup.fake__get_key(None))

        self.encryptor.attach_volume(None)

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input='0' * 32,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('ln', '--symbolic', '--force',
                      '/dev/mapper/%s' % self.dev_name, self.symlink_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ])
        self.assertEqual(2, self.mock_execute.call_count)

    def test_attach_volume_not_formatted(self):
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = (
            test_cryptsetup.fake__get_key(None))

        self.mock_execute.side_effect = [
            putils.ProcessExecutionError(exit_code=1),  # luksOpen
            putils.ProcessExecutionError(exit_code=1),  # isLuks
            mock.DEFAULT,  # luksFormat
            mock.DEFAULT,  # luksOpen
            mock.DEFAULT,  # ln
        ]

        self.encryptor.attach_volume(None)

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input='0' * 32,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', '--batch-mode', 'luksFormat',
                      '--key-file=-', self.dev_path, process_input='0' * 32,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True, attempts=3),
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input='0' * 32,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('ln', '--symbolic', '--force',
                      '/dev/mapper/%s' % self.dev_name, self.symlink_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ], any_order=False)
        self.assertEqual(5, self.mock_execute.call_count)

    def test_attach_volume_fail(self):
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = (
            test_cryptsetup.fake__get_key(None))

        self.mock_execute.side_effect = [
            putils.ProcessExecutionError(exit_code=1),  # luksOpen
            mock.DEFAULT,  # isLuks
        ]

        self.assertRaises(putils.ProcessExecutionError,
                          self.encryptor.attach_volume, None)

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input='0' * 32,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ], any_order=False)
        self.assertEqual(2, self.mock_execute.call_count)

    def test__close_volume(self):
        self.encryptor.detach_volume()

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksClose', self.dev_name,
                      root_helper=self.root_helper,
                      attempts=3, run_as_root=True, check_exit_code=True),
        ])
        self.assertEqual(1, self.mock_execute.call_count)

    def test_detach_volume(self):
        self.encryptor.detach_volume()

        self.mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksClose', self.dev_name,
                      root_helper=self.root_helper,
                      attempts=3, run_as_root=True, check_exit_code=True),
        ])
        self.assertEqual(1, self.mock_execute.call_count)
