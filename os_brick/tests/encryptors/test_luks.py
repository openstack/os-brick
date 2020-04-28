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

import binascii
from unittest import mock

from castellan.common.objects import symmetric_key as key
from os_brick.encryptors import luks
from os_brick.tests.encryptors import test_cryptsetup
from oslo_concurrency import processutils as putils


class LuksEncryptorTestCase(test_cryptsetup.CryptsetupEncryptorTestCase):
    def _create(self):
        return luks.LuksEncryptor(root_helper=self.root_helper,
                                  connection_info=self.connection_info,
                                  keymgr=self.keymgr)

    @mock.patch('os_brick.executor.Executor._execute')
    def test_is_luks(self, mock_execute):
        luks.is_luks(self.root_helper, self.dev_path, execute=mock_execute)

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      run_as_root=True, root_helper=self.root_helper,
                      check_exit_code=True),
        ], any_order=False)

    @mock.patch('os_brick.executor.Executor._execute')
    @mock.patch('os_brick.encryptors.luks.LOG')
    def test_is_luks_with_error(self, mock_log, mock_execute):
        error_msg = "Device %s is not a valid LUKS device." % self.dev_path
        mock_execute.side_effect = putils.ProcessExecutionError(
            exit_code=1, stderr=error_msg)

        luks.is_luks(self.root_helper, self.dev_path, execute=mock_execute)

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      run_as_root=True, root_helper=self.root_helper,
                      check_exit_code=True),
        ])

        self.assertEqual(1, mock_log.warning.call_count)  # warning logged

    @mock.patch('os_brick.executor.Executor._execute')
    def test__format_volume(self, mock_execute):
        self.encryptor._format_volume("passphrase")

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', '--batch-mode', 'luksFormat',
                      '--type', 'luks1', '--key-file=-', self.dev_path,
                      process_input='passphrase',
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True, attempts=3),
        ])

    @mock.patch('os_brick.executor.Executor._execute')
    def test__open_volume(self, mock_execute):
        self.encryptor._open_volume("passphrase")

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input='passphrase',
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ])

    @mock.patch('os_brick.executor.Executor._execute')
    def test_attach_volume(self, mock_execute):
        fake_key = '0c84146034e747639b698368807286df'
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = (
            test_cryptsetup.fake__get_key(None, fake_key))

        self.encryptor.attach_volume(None)

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('ln', '--symbolic', '--force',
                      '/dev/mapper/%s' % self.dev_name, self.symlink_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ])

    @mock.patch('os_brick.executor.Executor._execute')
    def test_attach_volume_not_formatted(self, mock_execute):
        fake_key = 'bc37c5eccebe403f9cc2d0dd20dac2bc'
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = (
            test_cryptsetup.fake__get_key(None, fake_key))

        mock_execute.side_effect = [
            putils.ProcessExecutionError(exit_code=1),  # luksOpen
            putils.ProcessExecutionError(exit_code=1),  # isLuks
            mock.DEFAULT,  # luksFormat
            mock.DEFAULT,  # luksOpen
            mock.DEFAULT,  # ln
        ]

        self.encryptor.attach_volume(None)

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', '--batch-mode', 'luksFormat',
                      '--type', 'luks1', '--key-file=-', self.dev_path,
                      process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True, attempts=3),
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('ln', '--symbolic', '--force',
                      '/dev/mapper/%s' % self.dev_name, self.symlink_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ], any_order=False)

    @mock.patch('os_brick.executor.Executor._execute')
    def test_attach_volume_fail(self, mock_execute):
        fake_key = 'ea6c2e1b8f7f4f84ae3560116d659ba2'
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = (
            test_cryptsetup.fake__get_key(None, fake_key))

        mock_execute.side_effect = [
            putils.ProcessExecutionError(exit_code=1),  # luksOpen
            mock.DEFAULT,  # isLuks
        ]

        self.assertRaises(putils.ProcessExecutionError,
                          self.encryptor.attach_volume, None)

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ], any_order=False)

    @mock.patch('os_brick.executor.Executor._execute')
    def test__close_volume(self, mock_execute):
        self.encryptor.detach_volume()

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksClose', self.dev_name,
                      root_helper=self.root_helper,
                      attempts=3, run_as_root=True, check_exit_code=[0, 4]),
        ])

    @mock.patch('os_brick.executor.Executor._execute')
    def test_detach_volume(self, mock_execute):
        self.encryptor.detach_volume()

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksClose', self.dev_name,
                      root_helper=self.root_helper,
                      attempts=3, run_as_root=True, check_exit_code=[0, 4]),
        ])

    def test_get_mangled_passphrase(self):
        # Confirm that a mangled passphrase is provided as per bug#1633518
        unmangled_raw_key = bytes(binascii.unhexlify('0725230b'))
        symmetric_key = key.SymmetricKey('AES', len(unmangled_raw_key) * 8,
                                         unmangled_raw_key)
        unmangled_encoded_key = symmetric_key.get_encoded()
        self.assertEqual(self.encryptor._get_mangled_passphrase(
            unmangled_encoded_key), '72523b')

    @mock.patch('os_brick.executor.Executor._execute')
    def test_attach_volume_unmangle_passphrase(self, mock_execute):
        fake_key = '0725230b'
        fake_key_mangled = '72523b'
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = \
            test_cryptsetup.fake__get_key(None, fake_key)

        mock_execute.side_effect = [
            putils.ProcessExecutionError(exit_code=2),  # luksOpen
            mock.DEFAULT,  # luksOpen
            mock.DEFAULT,  # luksClose
            mock.DEFAULT,  # luksAddKey
            mock.DEFAULT,  # luksOpen
            mock.DEFAULT,  # luksClose
            mock.DEFAULT,  # luksRemoveKey
            mock.DEFAULT,  # luksOpen
            mock.DEFAULT,  # ln
        ]

        self.encryptor.attach_volume(None)

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=True),
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key_mangled,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=True),
            mock.call('cryptsetup', 'luksClose', self.dev_name,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=[0, 4], attempts=3),
            mock.call('cryptsetup', 'luksAddKey', self.dev_path,
                      '--force-password',
                      process_input=''.join([fake_key_mangled,
                                             '\n', fake_key,
                                             '\n', fake_key]),
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=True),
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=True),
            mock.call('cryptsetup', 'luksClose', self.dev_name,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=[0, 4], attempts=3),
            mock.call('cryptsetup', 'luksRemoveKey', self.dev_path,
                      process_input=fake_key_mangled,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=True),
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=True),
            mock.call('ln', '--symbolic', '--force',
                      '/dev/mapper/%s' % self.dev_name, self.symlink_path,
                      root_helper=self.root_helper, run_as_root=True,
                      check_exit_code=True),
        ], any_order=False)
        self.assertEqual(9, mock_execute.call_count)


class Luks2EncryptorTestCase(LuksEncryptorTestCase):
    def _create(self):
        return luks.Luks2Encryptor(root_helper=self.root_helper,
                                   connection_info=self.connection_info,
                                   keymgr=self.keymgr)

    @mock.patch('os_brick.executor.Executor._execute')
    def test__format_volume(self, mock_execute):
        self.encryptor._format_volume("passphrase")

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', '--batch-mode', 'luksFormat',
                      '--type', 'luks2', '--key-file=-', self.dev_path,
                      process_input='passphrase',
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True, attempts=3),
        ])

    @mock.patch('os_brick.executor.Executor._execute')
    def test_attach_volume_not_formatted(self, mock_execute):
        fake_key = 'bc37c5eccebe403f9cc2d0dd20dac2bc'
        self.encryptor._get_key = mock.MagicMock()
        self.encryptor._get_key.return_value = (
            test_cryptsetup.fake__get_key(None, fake_key))

        mock_execute.side_effect = [
            putils.ProcessExecutionError(exit_code=1),  # luksOpen
            putils.ProcessExecutionError(exit_code=1),  # isLuks
            mock.DEFAULT,  # luksFormat
            mock.DEFAULT,  # luksOpen
            mock.DEFAULT,  # ln
        ]

        self.encryptor.attach_volume(None)

        mock_execute.assert_has_calls([
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', 'isLuks', '--verbose', self.dev_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('cryptsetup', '--batch-mode', 'luksFormat',
                      '--type', 'luks2', '--key-file=-', self.dev_path,
                      process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True, attempts=3),
            mock.call('cryptsetup', 'luksOpen', '--key-file=-', self.dev_path,
                      self.dev_name, process_input=fake_key,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
            mock.call('ln', '--symbolic', '--force',
                      '/dev/mapper/%s' % self.dev_name, self.symlink_path,
                      root_helper=self.root_helper,
                      run_as_root=True, check_exit_code=True),
        ], any_order=False)
