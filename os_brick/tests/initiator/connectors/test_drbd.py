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

from os_brick.initiator.connectors import drbd
from os_brick.tests.initiator import test_connector


class DRBDConnectorTestCase(test_connector.ConnectorTestCase):

    RESOURCE_TEMPLATE = '''
        resource r0 {
            on host1 {
            }
            net {
                shared-secret "%(shared-secret)s";
            }
        }
'''

    def setUp(self):
        super(DRBDConnectorTestCase, self).setUp()

        self.connector = drbd.DRBDConnector(
            None, execute=self._fake_exec)

        self.execs = []

    def _fake_exec(self, *cmd, **kwargs):
        self.execs.append(cmd)

        # out, err
        return ('', '')

    def test_get_connector_properties(self):
        props = drbd.DRBDConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_connect_volume(self):
        """Test connect_volume."""

        cprop = {
            'provider_auth': 'my-secret',
            'config': self.RESOURCE_TEMPLATE,
            'name': 'my-precious',
            'device': '/dev/drbd951722',
            'data': {},
        }

        res = self.connector.connect_volume(cprop)

        self.assertEqual(cprop['device'], res['path'])
        self.assertEqual('adjust', self.execs[0][1])
        self.assertEqual(cprop['name'], self.execs[0][4])

    def test_disconnect_volume(self):
        """Test the disconnect volume case."""

        cprop = {
            'provider_auth': 'my-secret',
            'config': self.RESOURCE_TEMPLATE,
            'name': 'my-precious',
            'device': '/dev/drbd951722',
            'data': {},
        }
        dev_info = {}

        self.connector.disconnect_volume(cprop, dev_info)

        self.assertEqual('down', self.execs[0][1])

    def test_extend_volume(self):
        cprop = {'name': 'something'}
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          cprop)
