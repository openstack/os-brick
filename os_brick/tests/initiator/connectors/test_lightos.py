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

from unittest import mock
import queue

from os_brick.initiator.connectors import lightos
from os_brick.tests.initiator import test_connector


FAKE_NQN = "nqn.fake.qnq"

class LightosConnectorTestCase(test_connector.ConnectorTestCase):

    """Test cases for NVMe initiator class."""
    
    def setUp(self):
        super(LightosConnectorTestCase, self).setUp()
        self.connector = lightos.LightOSConnector(None,
                                                execute=self.fake_execute)

    @mock.patch.object(lightos.LightOSConnector, 'get_hostnqn',
                       return_value=FAKE_NQN)
    @mock.patch.object(lightos.LightOSConnector, 'find_dsc',
                       return_value=True)
    def test_get_connector_properties(self, mock_nqn, mock_dsc):
        props = self.connector.get_connector_properties(None)
        expected_props = {"hostnqn": FAKE_NQN, "found_dsc": True}
        self.assertEqual(expected_props, props)

    def test_find_dsc(self):
        pass
    
    def test_dsc_do_connect_volume(self):
        pass

    def test_discovery_client_disconnect_volume(self):
        pass

    def test_get_device_by_uuid(self):
        pass
    
    @mock.patch.object(lightos.LightOSConnector, '_get_device_by_uuid',
                       return_value="/dev/nvme/nvme0n1")
    @mock.patch.object(lightos.LightOSConnector,
                       '_execute',
                       return_value=(10, None))
    def test_get_size_by_uuid(self, mock_uuid, mock_execute):
        size = self.connector._get_size_by_uuid("123")
        self.assertEqual(size, 10 * 512)
    @mock.patch.object(lightos.LightOSConnector, 'dsc_connect_volume',
                       return_value=None)
    @mock.patch.object(lightos.LightOSConnector, '_get_device_by_uuid',
                       return_value="/dev/nvme0n1")              
    def test_connect_volume(self, dsc_connect, path):
        connection_properties = {"hostnqn": FAKE_NQN, "found_dsc": True,
                                 "uuid": "123"}
        expected_device_info = {'type': 'block', "path": "/dev/nvme0n1"}
        device_info = self.connector.connect_volume(connection_properties)
        
        self.assertEqual(expected_device_info, device_info)
    @mock.patch.object(lightos.LightOSConnector, 'dsc_disconnect_volume') 
    def test_disconnect_volume(self, mock_disconnect):
        connection_properties = {"hostnqn": FAKE_NQN, "found_dsc": True,
                                 "uuid": "123"}
        self.connector.disconnect_volume(connection_properties, None)
        mock_disconnect.assert_called_once_with(connection_properties)

    def test_extend_volume(self):
        pass

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
