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

from os_brick.initiator.connectors import iscsi
from os_brick.tests.initiator import test_connector


class ISERConnectorTestCase(test_connector.ConnectorTestCase):

    def setUp(self):
        super(ISERConnectorTestCase, self).setUp()
        self.connector = iscsi.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=False)
        self.connection_data = {
            'volume_id': 'volume_id',
            'target_portal': 'ip:port',
            'target_iqn': 'target_1',
            'target_lun': 1,
            'target_portals': ['ip:port'],
            'target_iqns': ['target_1'],
            'target_luns': [1]
        }

    @mock.patch.object(iscsi.ISCSIConnector, '_get_ips_iqns_luns')
    @mock.patch('glob.glob')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_nodes')
    def test_get_connection_devices(
            self, nodes_mock, sessions_mock, glob_mock, iql_mock):

        self.connector.use_multipath = True
        iql_mock.return_value = \
            self.connector._get_all_targets(self.connection_data)

        # mocked iSCSI sessions
        sessions_mock.return_value = \
            [('iser:', '0', 'ip:port', '1', 'target_1')]

        # mocked iSCSI nodes
        nodes_mock.return_value = [('ip:port', 'target_1')]
        sys_cls = '/sys/class/scsi_host/host'
        glob_mock.side_effect = [
            [sys_cls + '1/device/session/target/1:1:1:1/block/sda']
        ]
        res = self.connector._get_connection_devices(self.connection_data)
        expected = {('ip:port', 'target_1'): ({'sda'}, set())}
        self.assertDictEqual(expected, res)
        iql_mock.assert_called_once_with(self.connection_data, discover=False)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    @mock.patch.object(iscsi.ISCSIConnector, '_execute')
    def test_connect_to_iscsi_portal(self, exec_mock, sessions_mock):
        """Connect to portal while session already established"""

        # connected sessions
        sessions_mock.side_effect = [
            [('iser:', 'session_iser', 'ip:port', '1', 'target_1')]
        ]
        exec_mock.side_effect = [('', None), ('', None), ('', None)]
        res = self.connector._connect_to_iscsi_portal(self.connection_data)

        # session name is expected to be in the result.
        self.assertEqual(("session_iser", True), res)
        prefix = 'iscsiadm -m node -T target_1 -p ip:port'
        expected_cmds = [
            prefix,
            prefix + ' --op update -n node.session.scan -v manual'
        ]
        actual_cmds = [' '.join(args[0]) for args in exec_mock.call_args_list]
        self.assertListEqual(expected_cmds, actual_cmds)
