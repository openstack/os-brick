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

from os_brick.encryptors import nop
from os_brick.tests.encryptors import test_base


class NoOpEncryptorTestCase(test_base.VolumeEncryptorTestCase):
    def _create(self):
        return nop.NoOpEncryptor(root_helper=self.root_helper,
                                 connection_info=self.connection_info,
                                 keymgr=self.keymgr)

    def test_attach_volume(self):
        test_args = {
            'control_location': 'front-end',
            'provider': 'NoOpEncryptor',
        }
        self.encryptor.attach_volume(None, **test_args)

    def test_detach_volume(self):
        test_args = {
            'control_location': 'front-end',
            'provider': 'NoOpEncryptor',
        }
        self.encryptor.detach_volume(**test_args)
