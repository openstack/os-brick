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
from unittest import mock

from os_brick.initiator.connectors import remotefs
from os_brick.remotefs import remotefs as remotefs_client
from os_brick.tests.initiator import test_connector


class RemoteFsConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for Remote FS initiator class."""
    TEST_DEV = '172.18.194.100:/var/nfs'
    TEST_PATH = '/mnt/test/df0808229363aad55c27da50c38d6328'
    TEST_BASE = '/mnt/test'
    TEST_NAME = '9c592d52-ce47-4263-8c21-4ecf3c029cdb'

    def setUp(self):
        super(RemoteFsConnectorTestCase, self).setUp()
        self.connection_properties = {
            'export': self.TEST_DEV,
            'name': self.TEST_NAME}
        self.connector = remotefs.RemoteFsConnector(
            'nfs', root_helper='sudo',
            nfs_mount_point_base=self.TEST_BASE,
            nfs_mount_options='vers=3')

    @mock.patch('os_brick.remotefs.remotefs.ScalityRemoteFsClient')
    def test_init_with_scality(self, mock_scality_remotefs_client):
        remotefs.RemoteFsConnector('scality', root_helper='sudo')
        self.assertEqual(1, mock_scality_remotefs_client.call_count)

    def test_get_connector_properties(self):
        props = remotefs.RemoteFsConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        expected = self.TEST_BASE
        actual = self.connector.get_search_path()
        self.assertEqual(expected, actual)

    @mock.patch.object(remotefs_client.RemoteFsClient, 'mount')
    def test_get_volume_paths(self, mock_mount):
        path = ("%(path)s/%(name)s" % {'path': self.TEST_PATH,
                                       'name': self.TEST_NAME})
        expected = [path]
        actual = self.connector.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, actual)

    @mock.patch.object(remotefs_client.RemoteFsClient, 'mount')
    @mock.patch.object(remotefs_client.RemoteFsClient, 'get_mount_point',
                       return_value="something")
    def test_connect_volume(self, mount_point_mock, mount_mock):
        """Test the basic connect volume case."""
        self.connector.connect_volume(self.connection_properties)

    def test_disconnect_volume(self):
        """Nothing should happen here -- make sure it doesn't blow up."""
        self.connector.disconnect_volume(self.connection_properties, {})

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.connection_properties)
