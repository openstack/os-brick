# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

from os_brick.initiator.connectors import gpfs
from os_brick.tests.initiator.connectors import test_local


class GPFSConnectorTestCase(test_local.LocalConnectorTestCase):

    def setUp(self):
        super(GPFSConnectorTestCase, self).setUp()
        self.connection_properties = {'name': 'foo',
                                      'device_path': '/tmp/bar'}
        self.connector = gpfs.GPFSConnector(None)

    def test_connect_volume(self):
        cprops = self.connection_properties
        dev_info = self.connector.connect_volume(cprops)
        self.assertEqual(dev_info['type'], 'gpfs')
        self.assertEqual(dev_info['path'], cprops['device_path'])

    def test_connect_volume_with_invalid_connection_data(self):
        cprops = {}
        self.assertRaises(ValueError,
                          self.connector.connect_volume, cprops)
