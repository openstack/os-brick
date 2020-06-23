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
import glob
import os

from os_brick import exception
from os_brick.initiator.connectors import disco
from os_brick.tests.initiator import test_connector


class DISCOConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for DISCO connector."""

    # Fake volume information
    volume = {
        'name': 'a-disco-volume',
        'disco_id': '1234567'
    }

    # Conf for test
    conf = {
        'ip': test_connector.MY_IP,
        'port': 9898
    }

    def setUp(self):
        super(DISCOConnectorTestCase, self).setUp()

        self.fake_connection_properties = {
            'name': self.volume['name'],
            'disco_id': self.volume['disco_id'],
            'conf': {
                'server_ip': self.conf['ip'],
                'server_port': self.conf['port']}
        }

        self.fake_volume_status = {'attached': True,
                                   'detached': False}
        self.fake_request_status = {'success': None,
                                    'fail': 'ERROR'}
        self.volume_status = 'detached'
        self.request_status = 'success'

        # Patch the request and os calls to fake versions
        self.mock_object(disco.DISCOConnector,
                         '_send_disco_vol_cmd',
                         self.perform_disco_request)
        self.mock_object(os.path, 'exists', self.is_volume_attached)
        self.mock_object(glob, 'glob', self.list_disco_volume)

        # The actual DISCO connector
        self.connector = disco.DISCOConnector(
            'sudo', execute=self.fake_execute)

    def perform_disco_request(self, *cmd, **kwargs):
        """Fake the socket call."""
        return self.fake_request_status[self.request_status]

    def is_volume_attached(self, *cmd, **kwargs):
        """Fake volume detection check."""
        return self.fake_volume_status[self.volume_status]

    def list_disco_volume(self, *cmd, **kwargs):
        """Fake the glob call."""
        path_dir = self.connector.get_search_path()
        volume_id = self.volume['disco_id']
        volume_items = [path_dir, '/', self.connector.DISCO_PREFIX, volume_id]
        volume_path = ''.join(volume_items)
        return [volume_path]

    def test_get_connector_properties(self):
        props = disco.DISCOConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        """DISCO volumes should be under /dev."""
        expected = "/dev"
        actual = self.connector.get_search_path()
        self.assertEqual(expected, actual)

    def test_get_volume_paths(self):
        """Test to get all the path for a specific volume."""
        expected = ['/dev/dms1234567']
        self.volume_status = 'attached'
        actual = self.connector.get_volume_paths(
            self.fake_connection_properties)
        self.assertEqual(expected, actual)

    def test_connect_volume(self):
        """Attach a volume."""
        self.connector.connect_volume(self.fake_connection_properties)

    def test_connect_volume_already_attached(self):
        """Make sure that we don't issue the request."""
        self.request_status = 'fail'
        self.volume_status = 'attached'
        self.test_connect_volume()

    def test_connect_volume_request_fail(self):
        """Fail the attach request."""
        self.volume_status = 'detached'
        self.request_status = 'fail'
        self.assertRaises(exception.BrickException,
                          self.test_connect_volume)

    def test_disconnect_volume(self):
        """Detach a volume."""
        self.connector.disconnect_volume(self.fake_connection_properties, None)

    def test_disconnect_volume_attached(self):
        """Detach a volume attached."""
        self.request_status = 'success'
        self.volume_status = 'attached'
        self.test_disconnect_volume()

    def test_disconnect_volume_already_detached(self):
        """Ensure that we don't issue the request."""
        self.request_status = 'fail'
        self.volume_status = 'detached'
        self.test_disconnect_volume()

    def test_disconnect_volume_request_fail(self):
        """Fail the detach request."""
        self.volume_status = 'attached'
        self.request_status = 'fail'
        self.assertRaises(exception.BrickException,
                          self.test_disconnect_volume)

    def test_get_all_available_volumes(self):
        """Test to get all the available DISCO volumes."""
        expected = ['/dev/dms1234567']
        actual = self.connector.get_all_available_volumes(None)
        self.assertCountEqual(expected, actual)

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.fake_connection_properties)
