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
import os
from unittest import mock

from os_brick import exception
from os_brick.initiator.connectors import aoe
from os_brick.tests.initiator import test_connector


class AoEConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for AoE initiator class."""

    def setUp(self):
        super(AoEConnectorTestCase, self).setUp()
        self.connector = aoe.AoEConnector('sudo')
        self.connection_properties = {'target_shelf': 'fake_shelf',
                                      'target_lun': 'fake_lun'}

    def test_get_search_path(self):
        expected = "/dev/etherd"
        actual_path = self.connector.get_search_path()
        self.assertEqual(expected, actual_path)

    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_get_volume_paths(self, mock_exists):
        expected = ["/dev/etherd/efake_shelf.fake_lun"]
        paths = self.connector.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, paths)

    def test_get_connector_properties(self):
        props = aoe.AoEConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    @mock.patch.object(os.path, 'exists', side_effect=[True, True])
    def test_connect_volume(self, exists_mock):
        """Ensure that if path exist aoe-revalidate was called."""
        aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)
        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            self.connector.connect_volume(self.connection_properties)

    @mock.patch.object(os.path, 'exists', side_effect=[False, True])
    def test_connect_volume_without_path(self, exists_mock):
        """Ensure that if path doesn't exist aoe-discovery was called."""

        aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)
        expected_info = {
            'type': 'block',
            'device': aoe_device,
            'path': aoe_path,
        }

        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            volume_info = self.connector.connect_volume(
                self.connection_properties)

        self.assertDictEqual(volume_info, expected_info)

    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_connect_volume_could_not_discover_path(self, exists_mock):
        _aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)

        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            self.assertRaises(exception.VolumeDeviceNotFound,
                              self.connector.connect_volume,
                              self.connection_properties)

    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume(self, mock_exists):
        """Ensure that if path exist aoe-revaliadte was called."""
        aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)

        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            self.connector.disconnect_volume(self.connection_properties, {})

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.connection_properties)
