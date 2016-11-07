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

import mock

from os_brick import exception
from os_brick.initiator.connectors import sheepdog
from os_brick.initiator import linuxsheepdog
from os_brick.tests.initiator import test_connector


class SheepdogConnectorTestCase(test_connector.ConnectorTestCase):

    def setUp(self):
        super(SheepdogConnectorTestCase, self).setUp()

        self.hosts = ['fake_hosts']
        self.ports = ['fake_ports']
        self.volume = 'fake_volume'

        self.connection_properties = {
            'hosts': self.hosts,
            'name': self.volume,
            'ports': self.ports,
        }

    def test_get_connector_properties(self):
        props = sheepdog.SheepdogConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        sd_connector = sheepdog.SheepdogConnector(None)
        path = sd_connector.get_search_path()
        self.assertIsNone(path)

    def test_get_volume_paths(self):
        sd_connector = sheepdog.SheepdogConnector(None)
        expected = []
        actual = sd_connector.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, actual)

    def test_connect_volume(self):
        """Test the connect volume case."""
        sd_connector = sheepdog.SheepdogConnector(None)
        device_info = sd_connector.connect_volume(self.connection_properties)

        # Ensure expected object is returned correctly
        self.assertIsInstance(device_info['path'],
                              linuxsheepdog.SheepdogVolumeIOWrapper)

    @mock.patch.object(linuxsheepdog.SheepdogVolumeIOWrapper, 'close')
    def test_disconnect_volume(self, volume_close):
        """Test the disconnect volume case."""
        sd_connector = sheepdog.SheepdogConnector(None)
        device_info = sd_connector.connect_volume(self.connection_properties)
        sd_connector.disconnect_volume(self.connection_properties, device_info)

        self.assertEqual(1, volume_close.call_count)

    def test_disconnect_volume_with_invalid_handle(self):
        """Test the disconnect volume case with invalid handle."""
        sd_connector = sheepdog.SheepdogConnector(None)
        device_info = {'path': 'fake_handle'}
        self.assertRaises(exception.InvalidIOHandleObject,
                          sd_connector.disconnect_volume,
                          self.connection_properties,
                          device_info)

    def test_extend_volume(self):
        sd_connector = sheepdog.SheepdogConnector(None)
        self.assertRaises(NotImplementedError,
                          sd_connector.extend_volume,
                          self.connection_properties)
