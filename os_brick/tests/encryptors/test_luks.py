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
import copy
from unittest import mock

from castellan.common.objects import symmetric_key as key
from castellan.tests.unit.key_manager import fake
from oslo_concurrency import processutils as putils

from os_brick.encryptors import luks
from os_brick import exception
from os_brick.tests.encryptors import test_base


def fake__get_key(context, passphrase):
    raw = bytes(binascii.unhexlify(passphrase))
    symmetric_key = key.SymmetricKey('AES', len(raw) * 8, raw)
    return symmetric_key


class LuksEncryptorTestCase(test_base.VolumeEncryptorTestCase):

    def setUp(self):
        super().setUp()

        self.dev_path = self.connection_info['data']['device_path']
        self.dev_name = 'crypt-%s' % self.dev_path.split('/')[-1]

        self.symlink_path = self.dev_path

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
        self.encryptor._get_key.return_value = fake__get_key(None, fake_key)

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
        self.encryptor._get_key.return_value = fake__get_key(None, fake_key)

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
        self.encryptor._get_key.return_value = fake__get_key(None, fake_key)

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

    def test_init_volume_encryption_not_supported(self):
        # Tests that creating a CryptsetupEncryptor fails if there is no
        # device_path key.
        type = 'unencryptable'
        data = dict(volume_id='a194699b-aa07-4433-a945-a5d23802043e')
        connection_info = dict(driver_volume_type=type, data=data)
        exc = self.assertRaises(exception.VolumeEncryptionNotSupported,
                                luks.LuksEncryptor,
                                root_helper=self.root_helper,
                                connection_info=connection_info,
                                keymgr=fake.fake_api())
        self.assertIn(type, str(exc))

    @mock.patch('os_brick.executor.Executor._execute')
    @mock.patch('os.path.exists', return_value=True)
    def test_init_volume_encryption_with_old_name(self, mock_exists,
                                                  mock_execute):
        # If an old name crypt device exists, dev_path should be the old name.
        old_dev_name = self.dev_path.split('/')[-1]
        encryptor = luks.LuksEncryptor(
            root_helper=self.root_helper,
            connection_info=self.connection_info,
            keymgr=self.keymgr)
        self.assertFalse(encryptor.dev_name.startswith('crypt-'))
        self.assertEqual(old_dev_name, encryptor.dev_name)
        self.assertEqual(self.dev_path, encryptor.dev_path)
        self.assertEqual(self.symlink_path, encryptor.symlink_path)
        mock_exists.assert_called_once_with('/dev/mapper/%s' % old_dev_name)
        mock_execute.assert_called_once_with(
            'cryptsetup', 'status', old_dev_name, run_as_root=True)

    @mock.patch('os_brick.executor.Executor._execute')
    @mock.patch('os.path.exists', side_effect=[False, True])
    def test_init_volume_encryption_with_wwn(self, mock_exists, mock_execute):
        # If an wwn name crypt device exists, dev_path should be based on wwn.
        old_dev_name = self.dev_path.split('/')[-1]
        wwn = 'fake_wwn'
        connection_info = copy.deepcopy(self.connection_info)
        connection_info['data']['multipath_id'] = wwn
        encryptor = luks.LuksEncryptor(
            root_helper=self.root_helper,
            connection_info=connection_info,
            keymgr=fake.fake_api())
        self.assertFalse(encryptor.dev_name.startswith('crypt-'))
        self.assertEqual(wwn, encryptor.dev_name)
        self.assertEqual(self.dev_path, encryptor.dev_path)
        self.assertEqual(self.symlink_path, encryptor.symlink_path)
        mock_exists.assert_has_calls([
            mock.call('/dev/mapper/%s' % old_dev_name),
            mock.call('/dev/mapper/%s' % wwn)])
        mock_execute.assert_called_once_with(
            'cryptsetup', 'status', wwn, run_as_root=True)

    @mock.patch('os_brick.utils.get_device_size')
    @mock.patch.object(luks.LuksEncryptor, '_execute')
    @mock.patch.object(luks.LuksEncryptor, '_get_passphrase')
    @mock.patch.object(luks.LuksEncryptor, '_get_key')
    def test_extend_volume(self, mock_key, mock_pass, mock_exec, mock_size):
        encryptor = self.encryptor
        res = encryptor.extend_volume(mock.sentinel.context)
        self.assertEqual(mock_size.return_value, res)

        mock_key.assert_called_once_with(mock.sentinel.context)
        mock_key.return_value.get_encoded.assert_called_once_with()
        key = mock_key.return_value.get_encoded.return_value
        mock_pass.assert_called_once_with(key)
        mock_exec.assert_called_once_with(
            'cryptsetup', 'resize', encryptor.dev_path,
            process_input=mock_pass.return_value, run_as_root=True,
            check_exit_code=True, root_helper=encryptor._root_helper)
        mock_size.assert_called_once_with(encryptor, encryptor.dev_path)


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
        self.encryptor._get_key.return_value = fake__get_key(None, fake_key)

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
