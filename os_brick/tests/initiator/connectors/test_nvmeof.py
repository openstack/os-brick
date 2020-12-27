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

from os_brick.initiator.connectors import nvmeof
from os_brick.initiator import linuxscsi
from os_brick.tests.initiator import test_connector


@ddt.ddt
class NVMeOFConnectorTestCase(test_connector.ConnectorTestCase):

    """Test cases for NVMe initiator class."""

    def setUp(self):
        super(NVMeOFConnectorTestCase, self).setUp()
        self.connector = nvmeof.NVMeOFConnector(None,
                                                execute=self.fake_execute,
                                                use_multipath=False)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test_get_sysuuid_without_newline(self, mock_execute):
        mock_execute.return_value = (
            "9126E942-396D-11E7-B0B7-A81E84C186D1\n", "")
        uuid = self.connector._get_host_uuid()
        expected_uuid = "9126E942-396D-11E7-B0B7-A81E84C186D1"
        self.assertEqual(expected_uuid, uuid)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_nqn',
                       return_value='fakenqn')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid',
                       return_value=None)
    def test_get_connector_properties_without_sysuuid(
            self, mock_uuid, mock_nqn):
        props = self.connector.get_connector_properties('sudo')
        expected_props = {'nqn': 'fakenqn'}
        self.assertEqual(expected_props, props)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_nqn',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid',
                       autospec=True)
    def test_get_connector_properties_with_sysuuid(
            self, mock_sysuuid, mock_nqn):
        mock_sysuuid.return_value = "9126E942-396D-11E7-B0B7-A81E84C186D1"
        mock_nqn.return_value = "nqn.2014-08.org.nvmexpress:uuid:c417f2d3"
        props = self.connector.get_connector_properties('sudo')
        expected_props = {
            "uuid": "9126E942-396D-11E7-B0B7-A81E84C186D1",
            "nqn": "nqn.2014-08.org.nvmexpress:uuid:c417f2d3"}
        self.assertEqual(expected_props, props)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    def test_get_volume_paths_unreplicated(self, mock_get_device_path):
        mock_get_device_path.return_value = '/dev/nvme1n1'
        self.assertEqual(self.connector.get_volume_paths(
            {'target_nqn': 'fakenqn',
                'vol_uuid': 'fakeuuid',
                'portals': [('fake', 'portal', 'tcp')]}),
            ['/dev/nvme1n1'])
        mock_get_device_path.assert_called_with(
            self.connector, 'fakenqn', 'fakeuuid')

    def test_get_volume_paths_replicated(self):
        connection_properties = {
            'alias': 'fakealias',
            'volume_replicas': [
                {
                    'target_nqn': 'fakenqn1',
                    'vol_uuid': 'fakeuuid1',
                    'portals': [('10.0.0.1', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn2',
                    'vol_uuid': 'fakeuuid2',
                    'portals': [('10.0.0.2', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn3',
                    'vol_uuid': 'fakeuuid3',
                    'portals': [('10.0.0.3', 4420, 'tcp')]
                }
            ]
        }
        self.assertEqual(self.connector.get_volume_paths(
            connection_properties),
            ['/dev/md/fakealias'])

    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target_volume')
    def test_connect_volume_unreplicated(
            self, mock_connect_target_volume):
        mock_connect_target_volume.return_value = '/dev/nvme0n1'
        self.assertEqual(
            self.connector.connect_volume(
                {
                    'target_nqn': 'fakenqn',
                    'vol_uuid': 'fakeuuid',
                    'portals': [('fake', 'portal', 'tcp')]
                }
            ),
            {'type': 'block', 'path': '/dev/nvme0n1'})
        mock_connect_target_volume.assert_called_with(
            'fakenqn', 'fakeuuid', [('fake', 'portal', 'tcp')])

    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_replicated_volume')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target_volume')
    def test_connect_volume_replicated(
            self, mock_connect_target_volume, mock_replicated_volume):
        mock_connect_target_volume.side_effect = (
            '/dev/nvme0n1', '/dev/nvme1n2', '/dev/nvme2n1')
        mock_replicated_volume.return_value = '/dev/md/md1'
        connection_properties = {
            'alias': 'fakealias',
            'volume_replicas': [
                {
                    'target_nqn': 'fakenqn1',
                    'vol_uuid': 'fakeuuid1',
                    'portals': [('10.0.0.1', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn2',
                    'vol_uuid': 'fakeuuid2',
                    'portals': [('10.0.0.2', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn3',
                    'vol_uuid': 'fakeuuid3',
                    'portals': [('10.0.0.3', 4420, 'tcp')]
                }
            ]
        }
        actual = self.connector.connect_volume(connection_properties)
        mock_connect_target_volume.assert_any_call(
            'fakenqn1', 'fakeuuid1', [('10.0.0.1', 4420, 'tcp')])
        mock_connect_target_volume.assert_any_call(
            'fakenqn2', 'fakeuuid2', [('10.0.0.2', 4420, 'tcp')])
        mock_connect_target_volume.assert_any_call(
            'fakenqn3', 'fakeuuid3', [('10.0.0.3', 4420, 'tcp')])
        mock_replicated_volume.assert_called_with(
            ['/dev/nvme0n1', '/dev/nvme1n2', '/dev/nvme2n1'],
            connection_properties['alias'],
            len(connection_properties['volume_replicas']))
        self.assertEqual(actual, {'type': 'block', 'path': '/dev/md/md1'})

    def test_disconnect_unreplicated_volume_nova(self):
        connection_properties = {
            'vol_uuid': 'fakeuuid',
            'portals': [('10.0.0.1', 4420, 'tcp')],
            'target_nqn': 'fakenqn',
            'device_path': '/dev/nvme0n1'
        }
        self.connector.disconnect_volume(connection_properties, None)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'end_raid')
    def test_disconnect_replicated_volume_nova(self, mock_end_raid):
        connection_properties = {
            'vol_uuid': 'fakeuuid',
            'volume_replicas': [
                {
                    'target_nqn': 'fakenqn1',
                    'vol_uuid': 'fakeuuid1',
                    'portals': [('10.0.0.1', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn2',
                    'vol_uuid': 'fakeuuid2',
                    'portals': [('10.0.0.2', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn3',
                    'vol_uuid': 'fakeuuid3',
                    'portals': [('10.0.0.3', 4420, 'tcp')]
                }
            ],
            'device_path': '/dev/md/md1'
        }
        self.connector.disconnect_volume(connection_properties, None)
        mock_end_raid.assert_called_with(self.connector, '/dev/md/md1')

    def test_disconnect_unreplicated_volume_cinder(self):
        connection_properties = {
            'vol_uuid': 'fakeuuid',
            'portals': [('10.0.0.1', 4420, 'tcp')],
            'target_nqn': 'fakenqn',
        }
        device_info = {'path': '/dev/nvme0n1'}
        self.connector.disconnect_volume(connection_properties,
                                         device_info,
                                         ignore_errors=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'end_raid')
    def test_disconnect_replicated_volume_cinder(self, mock_end_raid):
        connection_properties = {
            'volume_replicas': [
                {
                    'target_nqn': 'fakenqn1',
                    'vol_uuid': 'fakeuuid1',
                    'portals': [('10.0.0.1', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn2',
                    'vol_uuid': 'fakeuuid2',
                    'portals': [('10.0.0.2', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn3',
                    'vol_uuid': 'fakeuuid3',
                    'portals': [('10.0.0.3', 4420, 'tcp')]
                }
            ]
        }
        device_info = {'path': '/dev/md/md1'}
        self.connector.disconnect_volume(connection_properties,
                                         device_info,
                                         ignore_errors=True)
        mock_end_raid.assert_called_with(self.connector, '/dev/md/md1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    def test_extend_volume_unreplicated(
            self, mock_device_size, mock_device_path):
        connection_properties = {
            'target_nqn': 'fakenqn',
            'vol_uuid': 'fakeuuid'
        }
        mock_device_path.return_value = '/dev/nvme0n1'
        mock_device_size.return_value = 100
        self.assertEqual(
            self.connector.extend_volume(connection_properties),
            100)
        mock_device_path.assert_called_with(
            self.connector, 'fakenqn', 'fakeuuid')
        mock_device_size.assert_called_with('/dev/nvme0n1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    def test_extend_volume_replicated(
            self, mock_device_size, mock_mdadm):
        connection_properties = {
            'alias': 'fakealias',
            'volume_replicas': [
                {
                    'target_nqn': 'fakenqn1',
                    'vol_uuid': 'fakeuuid1',
                    'portals': [('10.0.0.1', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn2',
                    'vol_uuid': 'fakeuuid2',
                    'portals': [('10.0.0.2', 4420, 'tcp')]
                }, {
                    'target_nqn': 'fakenqn3',
                    'vol_uuid': 'fakeuuid3',
                    'portals': [('10.0.0.3', 4420, 'tcp')]
                }
            ]
        }
        mock_device_size.return_value = 100
        self.assertEqual(
            self.connector.extend_volume(connection_properties),
            100)
        device_path = '/dev/md/' + connection_properties['alias']
        mock_mdadm.assert_called_with(
            self.connector, ['mdadm', '--grow', '--size', 'max', device_path])
        mock_device_size.assert_called_with(device_path)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    def test__connect_target_volume_with_connected_device(
            self, mock_device_path, mock_rescan):
        mock_device_path.return_value = '/dev/nvme0n1'
        self.assertEqual(
            self.connector._connect_target_volume(
                'fakenqn', 'fakeuuid', [('fake', 'portal', 'tcp')]),
            '/dev/nvme0n1')
        mock_device_path.assert_called_with(
            self.connector, 'fakenqn', 'fakeuuid')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'connect_to_portals')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    def test__connect_target_volume_new_device_path(
            self, mock_device_path, mock_connect_portal):
        mock_device_path.side_effect = (None, '/dev/nvme0n1')
        self.assertEqual(
            self.connector._connect_target_volume(
                'fakenqn', 'fakeuuid', [('fake', 'portal', 'tcp')]),
            '/dev/nvme0n1')
        mock_connect_portal.assert_called_with(
            self.connector, 'fakenqn', [('fake', 'portal', 'tcp')])
        mock_device_path.assert_called_with(
            self.connector, 'fakenqn', 'fakeuuid')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    def test_connect_to_portals(self, mock_nvme_cli):
        nvme_command = (
            'connect', '-a', '10.0.0.1', '-s', 4420, '-t',
            'tcp', '-n', 'fakenqn', '-Q', '128', '-l', '-1')
        self.assertEqual(
            self.connector.connect_to_portals(
                self.connector, 'fakenqn', [('10.0.0.1', 4420, 'tcp')]),
            True)
        mock_nvme_cli.assert_called_with(self.connector, nvme_command)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_and_assemble_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_device_in_raid')
    def test_handle_replicated_volume_existing(
            self, mock_device_raid, mock_stop_assemble_raid):
        mock_device_raid.return_value = True
        self.assertEqual(
            self.connector._handle_replicated_volume(
                ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
                'fakealias', 3),
            '/dev/md/fakealias')
        mock_device_raid.assert_called_with(self.connector, '/dev/nvme1n1')
        mock_stop_assemble_raid.assert_called_with(
            self.connector, ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
            '/dev/md/fakealias', False)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'create_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_device_in_raid')
    def test_handle_replicated_volume_new(
            self, mock_device_raid, mock_create_raid):
        mock_device_raid.return_value = False
        self.assertEqual(
            self.connector._handle_replicated_volume(
                ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
                'fakealias', 3),
            '/dev/md/fakealias')
        mock_device_raid.assert_any_call(self.connector, '/dev/nvme1n1')
        mock_device_raid.assert_any_call(self.connector, '/dev/nvme1n2')
        mock_device_raid.assert_any_call(self.connector, '/dev/nvme1n3')
        mock_create_raid.assert_called_with(
            self.connector, ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
            '1', 'fakealias', 'fakealias', False)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'ks_readlink')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_md_name')
    def test_stop_and_assemble_raid_existing_simple(
            self, mock_md_name, mock_readlink):
        mock_readlink.return_value = '/dev/md/mdalias'
        mock_md_name.return_value = 'mdalias'
        self.assertIsNone(self.connector.stop_and_assemble_raid(
            self.connector, ['/dev/sda'], '/dev/md/mdalias', False))
        mock_md_name.assert_called_with(self.connector, 'sda')
        mock_readlink.assert_called_with('/dev/md/mdalias')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_assemble_raid_simple(self, mock_run_mdadm):
        self.assertEqual(self.connector.assemble_raid(
            self.connector, ['/dev/sda'], '/dev/md/md1', True), True)
        mock_run_mdadm.assert_called_with(
            self.connector,
            ['mdadm', '--assemble', '--run', '/dev/md/md1', '-o', '/dev/sda'],
            True)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_create_raid_cmd_simple(self, mock_run_mdadm):
        self.assertIsNone(self.connector.create_raid(
            self.connector, ['/dev/sda'], '1', 'md1', 'name', True))
        mock_run_mdadm.assert_called_with(
            self.connector,
            ['mdadm', '-C', '-o', 'md1', '-R', '-N', 'name', '--level', '1',
             '--raid-devices=1', '--bitmap=internal', '--homehost=any',
             '--failfast', '--assume-clean', '/dev/sda'])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'is_raid_exists')
    def test_end_raid_simple(self, mock_raid_exists, mock_stop_raid):
        mock_raid_exists.return_value = True
        mock_stop_raid.return_value = False
        self.assertIsNone(self.connector.end_raid(
            self.connector, '/dev/md/md1'))
        mock_raid_exists.assert_called_with(self.connector, '/dev/md/md1')
        mock_stop_raid.assert_called_with(self.connector, '/dev/md/md1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_stop_raid_simple(self, mock_run_mdadm):
        mock_run_mdadm.return_value = 'mdadm output'
        self.assertEqual(self.connector.stop_raid(
            self.connector, '/dev/md/md1'), 'mdadm output')
        mock_run_mdadm.assert_called_with(
            self.connector, ['mdadm', '--stop', '/dev/md/md1'])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_remove_raid_simple(self, mock_run_mdadm):
        self.assertIsNone(self.connector.remove_raid(
            self.connector, '/dev/md/md1'))
        mock_run_mdadm.assert_called_with(
            self.connector, ['mdadm', '--remove', '/dev/md/md1'])
