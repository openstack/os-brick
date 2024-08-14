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

from castellan.common import objects as castellan_objects
from castellan.tests.unit.key_manager import fake

from os_brick import encryptors
from os_brick.tests import base


def fake__get_key_symmetric(passphrase):
    raw = bytes(binascii.unhexlify(passphrase))
    symmetric_key = castellan_objects.symmetric_key.SymmetricKey(
        'AES', len(raw) * 8, raw)
    return symmetric_key


def fake__get_key_passphrase(passphrase):
    raw = passphrase.encode('utf-8')
    passphrase_key = castellan_objects.passphrase.Passphrase(raw)
    return passphrase_key


class BaseVolumeEncryptor(encryptors.base.VolumeEncryptor):

    def attach_volume(self, context, **kwargs):
        pass

    def detach_volume(self, **kwargs):
        pass

    def extend_volume(self, context, **kwargs):
        pass


class VolumeEncryptorTestCase(base.TestCase):
    def _create(self):
        pass

    def setUp(self):
        super(VolumeEncryptorTestCase, self).setUp()
        self.connection_info = {
            "data": {
                "device_path": "/dev/disk/by-path/"
                "ip-192.0.2.0:3260-iscsi-iqn.2010-10.org.openstack"
                ":volume-fake_uuid-lun-1",
            },
        }
        self.root_helper = None
        self.keymgr = fake.fake_api()
        self.encryptor = self._create()


class BaseEncryptorTestCase(VolumeEncryptorTestCase):

    def _test_get_encryptor(self, provider, expected_provider_class):
        encryption = {'control_location': 'front-end',
                      'provider': provider}
        encryptor = encryptors.get_volume_encryptor(
            root_helper=self.root_helper,
            connection_info=self.connection_info,
            keymgr=self.keymgr,
            **encryption)
        self.assertIsInstance(encryptor, expected_provider_class)

    def test_get_encryptors(self):

        self._test_get_encryptor('luks',
                                 encryptors.luks.LuksEncryptor)
        # TODO(lyarwood): Remove the following in Pike
        self._test_get_encryptor('LuksEncryptor',
                                 encryptors.luks.LuksEncryptor)
        self._test_get_encryptor('os_brick.encryptors.luks.LuksEncryptor',
                                 encryptors.luks.LuksEncryptor)
        self._test_get_encryptor('nova.volume.encryptors.luks.LuksEncryptor',
                                 encryptors.luks.LuksEncryptor)

        self._test_get_encryptor('plain',
                                 encryptors.cryptsetup.CryptsetupEncryptor)
        # TODO(lyarwood): Remove the following in Pike
        self._test_get_encryptor('CryptsetupEncryptor',
                                 encryptors.cryptsetup.CryptsetupEncryptor)
        self._test_get_encryptor(
            'os_brick.encryptors.cryptsetup.CryptsetupEncryptor',
            encryptors.cryptsetup.CryptsetupEncryptor)
        self._test_get_encryptor(
            'nova.volume.encryptors.cryptsetup.CryptsetupEncryptor',
            encryptors.cryptsetup.CryptsetupEncryptor)

        self._test_get_encryptor(None,
                                 encryptors.nop.NoOpEncryptor)
        # TODO(lyarwood): Remove the following in Pike
        self._test_get_encryptor('NoOpEncryptor',
                                 encryptors.nop.NoOpEncryptor)
        self._test_get_encryptor('os_brick.encryptors.nop.NoOpEncryptor',
                                 encryptors.nop.NoOpEncryptor)
        self._test_get_encryptor('nova.volume.encryptors.nop.NoopEncryptor',
                                 encryptors.nop.NoOpEncryptor)

    @mock.patch('os_brick.encryptors.base.VolumeEncryptor._get_key')
    def test__get_encryption_key_as_passphrase_hexlify(self, mock_key):
        """Test passphrase retrieval for secret type 'symmetric'.

        This should hexlify the secret in _get_encryption_key_as_passphrase.
        """
        base_enc = BaseVolumeEncryptor(
            root_helper=self.root_helper,
            connection_info=self.connection_info,
            keymgr=self.keymgr
        )
        fake_key_plain = 'passphrase-in-clear-text'
        fake_key_hexlified = binascii.hexlify(fake_key_plain.encode('utf-8'))

        mock_key.return_value = fake__get_key_symmetric(fake_key_hexlified)
        passphrase = base_enc._get_encryption_key_as_passphrase(
            mock.sentinel.context)
        mock_key.assert_called_once_with(mock.sentinel.context)
        self.assertEqual(passphrase, fake_key_hexlified.decode('utf-8'))

    @mock.patch('os_brick.encryptors.base.VolumeEncryptor._get_key')
    def test__get_encryption_key_as_passphrase(self, mock_key):
        """Test passphrase retrieval for secret type 'passphrase'.

        This should skip the hexlify step in _get_encryption_key_as_passphrase.
        """
        base_enc = BaseVolumeEncryptor(
            root_helper=self.root_helper,
            connection_info=self.connection_info,
            keymgr=self.keymgr
        )
        fake_key_plain = 'passphrase-in-clear-text'

        mock_key.return_value = fake__get_key_passphrase(fake_key_plain)
        passphrase = base_enc._get_encryption_key_as_passphrase(
            mock.sentinel.context)
        mock_key.assert_called_once_with(mock.sentinel.context)
        self.assertEqual(passphrase, fake_key_plain)

    def test_get_error_encryptors(self):
        encryption = {'control_location': 'front-end',
                      'provider': 'ErrorEncryptor'}
        self.assertRaises(ValueError,
                          encryptors.get_volume_encryptor,
                          root_helper=self.root_helper,
                          connection_info=self.connection_info,
                          keymgr=self.keymgr,
                          **encryption)

    @mock.patch('os_brick.encryptors.LOG')
    def test_error_log(self, log):
        encryption = {'control_location': 'front-end',
                      'provider': 'TestEncryptor'}
        provider = 'TestEncryptor'
        try:
            encryptors.get_volume_encryptor(
                root_helper=self.root_helper,
                connection_info=self.connection_info,
                keymgr=self.keymgr,
                **encryption)
        except Exception as e:
            log.error.assert_called_once_with("Error instantiating "
                                              "%(provider)s: "
                                              "%(exception)s",
                                              {'provider': provider,
                                               'exception': e})

    @mock.patch('os_brick.encryptors.LOG')
    def test_get_missing_out_of_tree_encryptor_log(self, log):
        provider = 'TestEncryptor'
        encryption = {'control_location': 'front-end',
                      'provider': provider}
        try:
            encryptors.get_volume_encryptor(
                root_helper=self.root_helper,
                connection_info=self.connection_info,
                keymgr=self.keymgr,
                **encryption)
        except Exception as e:
            log.error.assert_called_once_with("Error instantiating "
                                              "%(provider)s: "
                                              "%(exception)s",
                                              {'provider': provider,
                                               'exception': e})
            log.warning.assert_called_once_with("Use of the out of tree "
                                                "encryptor class %(provider)s "
                                                "will be blocked with the "
                                                "Queens release of os-brick.",
                                                {'provider': provider})

    @mock.patch('os_brick.encryptors.LOG')
    def test_get_direct_encryptor_log(self, log):
        encryption = {'control_location': 'front-end',
                      'provider': 'LuksEncryptor'}
        encryptors.get_volume_encryptor(
            root_helper=self.root_helper,
            connection_info=self.connection_info,
            keymgr=self.keymgr,
            **encryption)

        encryption = {'control_location': 'front-end',
                      'provider': 'os_brick.encryptors.luks.LuksEncryptor'}
        encryptors.get_volume_encryptor(
            root_helper=self.root_helper,
            connection_info=self.connection_info,
            keymgr=self.keymgr,
            **encryption)

        encryption = {'control_location': 'front-end',
                      'provider': 'nova.volume.encryptors.luks.LuksEncryptor'}
        encryptors.get_volume_encryptor(
            root_helper=self.root_helper,
            connection_info=self.connection_info,
            keymgr=self.keymgr,
            **encryption)

        log.warning.assert_has_calls([
            mock.call("Use of the in tree encryptor class %(provider)s by "
                      "directly referencing the implementation class will be "
                      "blocked in the Queens release of os-brick.",
                      {'provider': 'LuksEncryptor'}),
            mock.call("Use of the in tree encryptor class %(provider)s by "
                      "directly referencing the implementation class will be "
                      "blocked in the Queens release of os-brick.",
                      {'provider':
                       'os_brick.encryptors.luks.LuksEncryptor'}),
            mock.call("Use of the in tree encryptor class %(provider)s by "
                      "directly referencing the implementation class will be "
                      "blocked in the Queens release of os-brick.",
                      {'provider':
                       'nova.volume.encryptors.luks.LuksEncryptor'})])
