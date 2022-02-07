# Copyright (C) 2016-2020 Lightbits Labs Ltd.
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
import glob
import http.client
import queue
from unittest import mock
from unittest.mock import mock_open

from os_brick import exception
from os_brick.initiator.connectors import lightos
from os_brick.initiator import linuxscsi
from os_brick.privileged import lightos as priv_lightos
from os_brick.tests.initiator import test_connector
from os_brick import utils

FAKE_NQN = "nqn.fake.qnq"

FAKE_LIGHTOS_CLUSTER_NODES = {
    "nodes": [
        {"UUID": "926e6df8-73e1-11ec-a624-000000000001",
         "nvmeEndpoint": "192.168.75.10:4420"},
        {"UUID": "926e6df8-73e1-11ec-a624-000000000002",
         "nvmeEndpoint": "192.168.75.11:4420"},
        {"UUID": "926e6df8-73e1-11ec-a624-000000000003",
         "nvmeEndpoint": "192.168.75.12:4420"}
    ]
}

FAKE_SUBSYSNQN = "nqn.2014-08.org.nvmexpress:NVMf:uuid:"
FAKE_LIGHTOS_CLUSTER_INFO = {
    'UUID': "926e6df8-73e1-11ec-a624-07ba3880f6cc",
    'subsystemNQN': "nqn.2014-08.org.nvmexpress:NVMf:uuid:"
    "f4a89ce0-9fc2-4900-bfa3-00ad27995e7b",
    'nodes_ips': ["10.17.167.4", "10.17.167.5", "10.17.167.6"]
}
FAKE_VOLUME_UUID = "926e6df8-73e1-11ec-a624-07ba3880f6cd"
NUM_BLOCKS_IN_GIB = 2097152
BLOCK_SIZE = 512


def get_http_response_mock(status):
    resp = mock.Mock()
    resp.status = status
    return resp


class LightosConnectorTestCase(test_connector.ConnectorTestCase):

    """Test cases for NVMe initiator class."""

    def setUp(self):
        super(LightosConnectorTestCase, self).setUp()
        self.connector = lightos.LightOSConnector(None,
                                                  execute=self.fake_execute)

    @staticmethod
    def _get_connection_info():
        lightos_nodes = {}
        for ip in FAKE_LIGHTOS_CLUSTER_INFO['nodes_ips']:
            lightos_nodes[ip] = dict(
                transport_type='tcp',
                target_portal=ip,
                target_port=8009
            )
        return dict(
            subsysnqn=FAKE_LIGHTOS_CLUSTER_INFO['subsystemNQN'],
            uuid=FAKE_LIGHTOS_CLUSTER_INFO['UUID'],
            lightos_nodes=lightos_nodes
        )

    @mock.patch.object(utils, 'get_host_nqn',
                       return_value=FAKE_NQN)
    @mock.patch.object(lightos.LightOSConnector, 'find_dsc',
                       return_value=True)
    def test_get_connector_properties(self, mock_nqn, mock_dsc):
        props = self.connector.get_connector_properties(None)
        expected_props = {"nqn": FAKE_NQN, "found_dsc": True}
        self.assertEqual(expected_props, props)

    @mock.patch.object(lightos.http.client.HTTPConnection, "request",
                       return_value=None)
    @mock.patch.object(lightos.http.client.HTTPConnection, "getresponse",
                       return_value=get_http_response_mock(http.client.OK))
    def test_find_dsc_success(self, mocked_connection, mocked_response):
        mocked_connection.request.return_value = None
        mocked_response.getresponse.return_value = get_http_response_mock(
            http.client.OK)
        self.assertEqual(self.connector.find_dsc(), 'found')

    @mock.patch.object(lightos.http.client.HTTPConnection, "request",
                       return_value=None)
    @mock.patch.object(lightos.http.client.HTTPConnection, "getresponse",
                       return_value=get_http_response_mock(
                           http.client.NOT_FOUND))
    def test_find_dsc_failure(self, mocked_connection, mocked_response):
        mocked_connection.request.return_value = None
        mocked_response.getresponse.return_value = get_http_response_mock(
            http.client.OK)
        self.assertEqual(self.connector.find_dsc(), '')

    @mock.patch.object(utils, 'get_host_nqn',
                       return_value=FAKE_NQN)
    @mock.patch.object(lightos.priv_lightos, 'move_dsc_file',
                       return_value="/etc/discovery_client/discovery.d/v0")
    @mock.patch.object(lightos.LightOSConnector,
                       '_check_device_exists_using_dev_lnk',
                       return_value="/dev/nvme0n1")
    def test_connect_volume_succeed(self, mock_nqn, mock_move_file,
                                    mock_check_device):
        self.connector.connect_volume(self._get_connection_info())

    @mock.patch.object(utils, 'get_host_nqn',
                       return_value=FAKE_NQN)
    @mock.patch.object(lightos.priv_lightos, 'move_dsc_file',
                       return_value="/etc/discovery_client/discovery.d/v0")
    @mock.patch.object(lightos.priv_lightos, 'delete_dsc_file',
                       return_value=None)
    @mock.patch.object(lightos.LightOSConnector, '_get_device_by_uuid',
                       return_value=None)
    def test_connect_volume_failure(self, mock_nqn, mock_move_file,
                                    mock_delete_file, mock_get_device):
        self.assertRaises(exception.BrickException,
                          self.connector.connect_volume,
                          self._get_connection_info())

    @mock.patch.object(priv_lightos, 'delete_dsc_file', return_value=True)
    def test_dsc_disconnect_volume_succeed(self, mock_priv_lightos):
        self.connector.dsc_disconnect_volume(self._get_connection_info())

    @mock.patch.object(priv_lightos, 'delete_dsc_file',
                       side_effect=OSError("failed to delete file"))
    def test_dsc_disconnect_volume_failure(self, execute_mock):
        self.assertRaises(OSError,
                          self.connector.dsc_disconnect_volume,
                          self._get_connection_info())

    @mock.patch.object(lightos.LightOSConnector,
                       '_check_device_exists_using_dev_lnk',
                       return_value=("/dev/nvme0n1"))
    def test_get_device_by_uuid_succeed_with_link(self, execute_mock):
        self.assertEqual(self.connector._get_device_by_uuid(FAKE_VOLUME_UUID),
                         "/dev/nvme0n1")

    @mock.patch.object(lightos.LightOSConnector,
                       '_check_device_exists_reading_block_class',
                       return_value=("/dev/nvme0n1"))
    def test_get_device_by_uuid_succeed_with_block_class(self, execute_mock):
        self.assertEqual(self.connector._get_device_by_uuid(FAKE_VOLUME_UUID),
                         "/dev/nvme0n1")

    @mock.patch.object(lightos.LightOSConnector,
                       '_check_device_exists_using_dev_lnk',
                       side_effect=[None, False, "/dev/nvme0n1"])
    @mock.patch.object(lightos.LightOSConnector,
                       '_check_device_exists_reading_block_class',
                       side_effect=[None, False, "/dev/nvme0n1"])
    def test_get_device_by_uuid_many_attempts(self, execute_mock, glob_mock):
        self.assertEqual(self.connector._get_device_by_uuid(FAKE_VOLUME_UUID),
                         '/dev/nvme0n1')

    @mock.patch.object(lightos.LightOSConnector, 'dsc_connect_volume',
                       return_value=None)
    @mock.patch.object(lightos.LightOSConnector, '_get_device_by_uuid',
                       return_value="/dev/nvme0n1")
    def test_connect_volume(self, dsc_connect, path):
        connection_properties = {"nqn": FAKE_NQN, "found_dsc": True,
                                 "uuid": "123"}
        expected_device_info = {'type': 'block', "path": "/dev/nvme0n1"}
        device_info = self.connector.connect_volume(connection_properties)

        self.assertEqual(expected_device_info, device_info)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io', autospec=True)
    @mock.patch.object(lightos.LightOSConnector, '_get_device_by_uuid',
                       return_value="/dev/nvme0n1")
    @mock.patch.object(lightos.LightOSConnector, 'dsc_disconnect_volume')
    def test_disconnect_volume(self, mock_disconnect, mock_uuid, mock_flush):
        connection_properties = {"nqn": FAKE_NQN, "found_dsc": True,
                                 "uuid": "123"}
        self.connector.disconnect_volume(connection_properties, None)
        mock_disconnect.assert_called_once_with(connection_properties)
        mock_flush.assert_called_once_with(mock.ANY, "/dev/nvme0n1")

    @mock.patch.object(lightos.LightOSConnector, '_get_device_by_uuid',
                       return_value="/dev/nvme0n1")
    @mock.patch("builtins.open", new_callable=mock_open,
                read_data=f"{str(NUM_BLOCKS_IN_GIB)}\n")
    def test_extend_volume(self, mock_execute, m_open):
        connection_properties = {'uuid': FAKE_VOLUME_UUID}
        self.assertEqual(self.connector.extend_volume(connection_properties),
                         NUM_BLOCKS_IN_GIB * BLOCK_SIZE)

    def test_monitor_message_queue_delete(self):
        message_queue = queue.Queue()
        connection = {"uuid": "123"}
        message_queue.put(("delete", connection))
        lightos_db = {"123": "fake_connection"}
        self.connector.monitor_message_queue(message_queue, lightos_db)
        self.assertEqual(len(lightos_db), 0)

    def test_monitor_message_queue_add(self):
        message_queue = queue.Queue()
        connection = {"uuid": "123"}
        lightos_db = {}
        message_queue.put(("add", connection))
        self.connector.monitor_message_queue(message_queue, lightos_db)
        self.assertEqual(len(lightos_db), 1)

    @mock.patch.object(lightos.os.path, 'exists', return_value=True)
    @mock.patch.object(lightos.os.path, 'realpath',
                       return_value="/dev/nvme0n1")
    def test_check_device_exists_using_dev_lnk_succeed(self, mock_path_exists,
                                                       mock_realpath):
        found_dev = self.connector._check_device_exists_using_dev_lnk(
            FAKE_VOLUME_UUID)
        self.assertEqual("/dev/nvme0n1", found_dev)

    def test_check_device_exists_using_dev_lnk_false(self):
        self.assertIsNone(self.connector._check_device_exists_using_dev_lnk(
            FAKE_VOLUME_UUID))

    @mock.patch.object(glob, "glob", return_value=['/path/nvme0n1/wwid'])
    @mock.patch("builtins.open", new_callable=mock_open,
                read_data=f"uuid.{FAKE_VOLUME_UUID}\n")
    def test_check_device_exists_reading_block_class(self, mock_glob, m_open):
        found_dev = self.connector._check_device_exists_reading_block_class(
            FAKE_VOLUME_UUID)
        self.assertEqual("/dev/nvme0n1", found_dev)
