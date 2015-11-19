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

import array
from castellan.tests.unit.key_manager import fake
import codecs
import mock

from os_brick import encryptors
from os_brick.tests import base


class VolumeEncryptorTestCase(base.TestCase):
    def _create(self, root_helper, connection_info, keymgr, execute):
        pass

    def setUp(self):
        super(VolumeEncryptorTestCase, self).setUp()
        self.cmds = []
        self.connection_info = {
            "data": {
                "device_path": "/dev/disk/by-path/"
                "ip-192.0.2.0:3260-iscsi-iqn.2010-10.org.openstack"
                ":volume-fake_uuid-lun-1",
            },
        }
        self.mock_execute = (
            mock.patch("os_brick.privileged.rootwrap.execute").start())
        self.addCleanup(self.mock_execute.stop)
        _hex = codecs.getdecoder("hex_codec")('0' * 32)[0]
        self.encryption_key = array.array('B', _hex).tolist()
        self.root_helper = None
        self.encryptor = self._create(root_helper=self.root_helper,
                                      connection_info=self.connection_info,
                                      keymgr=fake.fake_api(),
                                      execute=self.mock_execute)

    def test_get_encryptors(self):
        root_helper = None

        encryption = {'control_location': 'front-end',
                      'provider': 'LuksEncryptor'}
        encryptor = encryptors.get_volume_encryptor(
            root_helper=root_helper,
            connection_info=self.connection_info,
            keymgr=fake.fake_api(),
            execute=self.mock_execute,
            **encryption)

        self.assertIsInstance(encryptor,
                              encryptors.luks.LuksEncryptor,
                              "encryptor is not an instance of LuksEncryptor")

        encryption = {'control_location': 'front-end',
                      'provider': 'CryptsetupEncryptor'}
        encryptor = encryptors.get_volume_encryptor(
            root_helper=root_helper,
            connection_info=self.connection_info,
            keymgr=fake.fake_api(),
            execute=self.mock_execute,
            **encryption)

        self.assertIsInstance(encryptor,
                              encryptors.cryptsetup.CryptsetupEncryptor,
                              "encryptor is not an instance of"
                              "CryptsetupEncryptor")

        encryption = {'control_location': 'front-end',
                      'provider': 'NoOpEncryptor'}
        encryptor = encryptors.get_volume_encryptor(
            root_helper=root_helper,
            connection_info=self.connection_info,
            keymgr=fake.fake_api(),
            execute=self.mock_execute,
            **encryption)

        self.assertIsInstance(encryptor,
                              encryptors.nop.NoOpEncryptor,
                              "encryptor is not an instance of NoOpEncryptor")

    def test_get_error_encryptos(self):
        encryption = {'control_location': 'front-end',
                      'provider': 'ErrorEncryptor'}
        self.assertRaises(ValueError,
                          encryptors.get_volume_encryptor,
                          root_helper=None,
                          connection_info=self.connection_info,
                          keymgr=fake.fake_api(),
                          execute=self.mock_execute,
                          **encryption)

    @mock.patch('os_brick.encryptors.LOG')
    def test_error_log(self, log):
        encryption = {'control_location': 'front-end',
                      'provider': 'TestEncryptor'}
        provider = 'TestEncryptor'
        try:
            encryptors.get_volume_encryptor(
                root_helper=None,
                connection_info=self.connection_info,
                keymgr=fake.fake_api(),
                execute=self.mock_execute,
                **encryption)
        except Exception as e:
            log.error.assert_called_once_with("Error instantiating "
                                              "%(provider)s: "
                                              "%(exception)s",
                                              {'provider': provider,
                                               'exception': e})
