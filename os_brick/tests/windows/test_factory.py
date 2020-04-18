# Copyright 2016 Cloudbase Solutions Srl
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

from unittest import mock

import ddt

from os_brick import initiator
from os_brick.initiator import connector
from os_brick.initiator.windows import fibre_channel
from os_brick.initiator.windows import iscsi
from os_brick.initiator.windows import smbfs
from os_brick.tests.windows import test_base


@ddt.ddt
class WindowsConnectorFactoryTestCase(test_base.WindowsConnectorTestBase):
    @ddt.data({'proto': initiator.ISCSI,
               'expected_cls': iscsi.WindowsISCSIConnector},
              {'proto': initiator.FIBRE_CHANNEL,
               'expected_cls': fibre_channel.WindowsFCConnector},
              {'proto': initiator.SMBFS,
               'expected_cls': smbfs.WindowsSMBFSConnector})
    @ddt.unpack
    @mock.patch('sys.platform', 'win32')
    def test_factory(self, proto, expected_cls):
        obj = connector.InitiatorConnector.factory(proto, None)
        self.assertIsInstance(obj, expected_cls)
