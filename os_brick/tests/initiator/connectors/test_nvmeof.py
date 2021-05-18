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

import builtins
import glob
import os.path
from unittest import mock

import ddt
from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick import executor
from os_brick.initiator.connectors import nvmeof
from os_brick.initiator import linuxscsi
from os_brick.tests.initiator import test_connector


TARGET_NQN = 'target.nqn'
EXECUTOR = executor.Executor(None)
VOL_UUID = 'c20aba21-6ef6-446b-b374-45733b4883ba'
NVME_DEVICE_PATH = '/dev/nvme1'
NVME_NS_PATH = '/dev/nvme1n1'
SYS_UUID = '9126E942-396D-11E7-B0B7-A81E84C186D1'
HOST_UUID = 'c20aba21-6ef6-446b-b374-45733b4883ba'
HOST_NQN = 'nqn.2014-08.org.nvmexpress:uuid:' \
           'beaae2de-3a97-4be1-a739-6ac4bc5bf138'
volume_replicas = [{'target_nqn': 'fakenqn1', 'vol_uuid': 'fakeuuid1',
                    'portals': [('10.0.0.1', 4420, 'tcp')]},
                   {'target_nqn': 'fakenqn2', 'vol_uuid': 'fakeuuid2',
                    'portals': [('10.0.0.2', 4420, 'tcp')]},
                   {'target_nqn': 'fakenqn3', 'vol_uuid': 'fakeuuid3',
                    'portals': [('10.0.0.3', 4420, 'tcp')]}]
connection_properties = {
    'alias': 'fakealias',
    'vol_uuid': 'fakevoluuid',
    'volume_replicas': volume_replicas
}
fake_portal = ('fake', 'portal', 'tcp')


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

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test_get_sysuuid_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        uuid = self.connector._get_host_uuid()
        self.assertIsNone(uuid)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_nqn',
                       return_value='fakenqn')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_system_uuid',
                       return_value=None)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid',
                       return_value=None)
    def test_get_connector_properties_without_sysuuid(self, mock_host_uuid,
                                                      mock_sysuuid, mock_nqn):
        props = self.connector.get_connector_properties('sudo')
        expected_props = {'nqn': 'fakenqn'}
        self.assertEqual(expected_props, props)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_nqn', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_system_uuid',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid', autospec=True)
    def test_get_connector_properties_with_sysuuid(self, mock_host_uuid,
                                                   mock_sysuuid, mock_nqn):
        mock_host_uuid.return_value = HOST_UUID
        mock_sysuuid.return_value = SYS_UUID
        mock_nqn.return_value = HOST_NQN
        props = self.connector.get_connector_properties('sudo')
        expected_props = {"system uuid": SYS_UUID, "nqn": HOST_NQN,
                          "uuid": HOST_UUID}
        self.assertEqual(expected_props, props)

    def test_get_volume_paths_unreplicated(self):
        self.assertEqual(self.connector.get_volume_paths(
            {'target_nqn': 'fakenqn', 'vol_uuid': 'fakeuuid',
             'portals': [('fake', 'portal', 'tcp')]}), [])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    def test_get_volume_paths_single(self, mock_get_device_path):
        mock_get_device_path.return_value = '/dev/nvme1n1'
        connection_properties = {
            'alias': 'fakealias',
            'volume_replicas': [volume_replicas[0]]
        }
        self.assertEqual(self.connector.get_volume_paths(
            connection_properties),
            ['/dev/nvme1n1'])
        mock_get_device_path.assert_called_with(
            self.connector, volume_replicas[0]['target_nqn'],
            volume_replicas[0]['vol_uuid'])

    def test_get_volume_paths_replicated(self):
        self.assertEqual(self.connector.get_volume_paths(
            connection_properties),
            ['/dev/md/fakealias'])

    def test_get_volume_paths(self):
        connection_properties = {
            'device_path': '/dev/md/fakealias'
        }
        self.assertEqual(self.connector.get_volume_paths(
            connection_properties),
            [connection_properties['device_path']])

    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target_volume')
    def test_connect_volume_single_rep(
            self, mock_connect_target_volume):
        connection_properties1 = {
            'target_nqn': 'fakenqn',
            'vol_uuid': 'fakeuuid',
            'volume_replicas': [volume_replicas[0]]
        }
        mock_connect_target_volume.return_value = '/dev/nvme0n1'
        self.assertEqual(
            self.connector.connect_volume(connection_properties1),
            {'type': 'block', 'path': '/dev/nvme0n1'})
        mock_connect_target_volume.assert_called_with(
            connection_properties1['volume_replicas'][0]['target_nqn'],
            connection_properties1['volume_replicas'][0]['vol_uuid'],
            connection_properties1['volume_replicas'][0]['portals'])

    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target_volume')
    def test_connect_volume_unreplicated(
            self, mock_connect_target_volume):
        mock_connect_target_volume.return_value = '/dev/nvme0n1'
        self.assertEqual(
            self.connector._connect_volume_replicated(
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

    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_replicated_volume')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target_volume')
    def test_connect_volume_replicated_exception(
            self, mock_connect_target_volume, mock_replicated_volume):
        mock_connect_target_volume.side_effect = Exception()
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector.connect_volume, connection_properties)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_nova(self, mock_sleep, mock_execute,
                                    mock_devices, mock_flush):
        device = '/dev/nvme0n1'
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': device,
                                 'transport_type': 'rdma'}
        mock_devices.return_value = [device]

        self.connector.disconnect_volume(connection_properties, None)

        mock_flush.assert_called_once_with(mock.ANY, device)
        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'disconnect', '-n', 'nqn.volume_123',
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_cinder(self, mock_sleep, mock_execute,
                                      mock_devices, mock_flush):
        device = '/dev/nvme0n1'
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'transport_type': 'rdma'}
        device_info = {'path': device}
        mock_devices.return_value = [device]

        self.connector.disconnect_volume(connection_properties,
                                         device_info,
                                         ignore_errors=True)

        mock_flush.assert_called_once_with(mock.ANY, device)
        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'disconnect', '-n', 'nqn.volume_123',
            root_helper=None,
            run_as_root=True)

    @ddt.data({'force': False, 'expected': putils.ProcessExecutionError},
              {'force': True, 'expected': exception.ExceptionChainer})
    @ddt.unpack
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_raise(self, mock_sleep, mock_execute,
                                     mock_devices, mock_flush,
                                     force, expected):
        device = '/dev/nvme0n1'
        mock_execute.side_effect = putils.ProcessExecutionError
        mock_devices.return_value = device
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': device,
                                 'transport_type': 'rdma'}

        self.assertRaises(expected,
                          self.connector.disconnect_volume,
                          connection_properties,
                          None, force)
        mock_flush.assert_called_once_with(mock.ANY, device)
        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'disconnect', '-n', 'nqn.volume_123',
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_force_ignore_errors(self, mock_sleep,
                                                   mock_execute, mock_devices,
                                                   mock_flush):
        device = '/dev/nvme0n1'
        mock_flush.side_effect = putils.ProcessExecutionError
        mock_execute.side_effect = putils.ProcessExecutionError
        mock_devices.return_value = device
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': device,
                                 'transport_type': 'rdma'}

        res = self.connector.disconnect_volume(connection_properties,
                                               None,
                                               force=True,
                                               ignore_errors=True)
        self.assertIsNone(res)
        mock_flush.assert_called_once_with(mock.ANY, device)
        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'disconnect', '-n', 'nqn.volume_123',
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_fs_type')
    def test_disconnect_unreplicated_volume_nova(self, mock_get_fs_type):
        connection_properties = {
            'vol_uuid': 'fakeuuid',
            'portals': [('10.0.0.1', 4420, 'tcp')],
            'target_nqn': 'fakenqn',
            'device_path': '/dev/nvme0n1'
        }
        mock_get_fs_type.return_value = 'linux_raid_member'
        self.connector._disconnect_volume_replicated(
            connection_properties, None)
        mock_get_fs_type.assert_called_with(
            connection_properties['device_path'])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'end_raid')
    def test_disconnect_replicated_volume_no_device_path(self, mock_end_raid):

        mock_end_raid.return_value = None
        self.connector.disconnect_volume(connection_properties, None)
        device_path = '/dev/md/' + connection_properties['alias']
        mock_end_raid.assert_called_with(self.connector, device_path)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'end_raid')
    def test_disconnect_replicated_volume_nova(self, mock_end_raid):
        connection_properties = {
            'vol_uuid': 'fakeuuid',
            'volume_replicas': volume_replicas,
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
        self.connector._disconnect_volume_replicated(
            connection_properties, device_info, ignore_errors=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'end_raid')
    def test_disconnect_replicated_volume_cinder(self, mock_end_raid):
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
            'vol_uuid': 'fakeuuid',
            'volume_replicas': [volume_replicas[0]]
        }
        mock_device_path.return_value = '/dev/nvme0n1'
        mock_device_size.return_value = 100
        self.assertEqual(
            self.connector.extend_volume(connection_properties),
            100)
        mock_device_path.assert_called_with(
            self.connector, volume_replicas[0]['target_nqn'],
            volume_replicas[0]['vol_uuid'])
        mock_device_size.assert_called_with('/dev/nvme0n1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    def test_extend_volume_unreplicated_no_replica(
            self, mock_device_size, mock_device_path):
        connection_properties = {
            'target_nqn': 'fakenqn',
            'vol_uuid': 'fakeuuid'
        }
        mock_device_path.return_value = '/dev/nvme0n1'
        mock_device_size.return_value = 100
        self.assertEqual(
            self.connector._extend_volume_replicated(
                connection_properties), 100)
        mock_device_path.assert_called_with(
            self.connector, 'fakenqn', 'fakeuuid')
        mock_device_size.assert_called_with('/dev/nvme0n1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    def test_extend_volume_replicated(
            self, mock_device_size, mock_mdadm):
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
    def test__connect_target_volume_not_connected(
            self, mock_device_path, mock_portals):
        mock_device_path.side_effect = exception.VolumeDeviceNotFound()
        mock_portals.return_value = True
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_target_volume, TARGET_NQN,
                          VOL_UUID, [('fake', 'portal', 'tcp')])
        mock_device_path.assert_called_with(
            self.connector, TARGET_NQN, VOL_UUID)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'connect_to_portals')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    def test__connect_target_volume_no_portals_con(
            self, mock_device_path, mock_portals):
        mock_device_path.return_value = None
        mock_portals.return_value = None
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_target_volume, 'fakenqn',
                          'fakeuuid', [fake_portal])
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

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    def test_connect_to_portals_rdma_no_conn(self, mock_nvme_cli):
        mock_nvme_cli.side_effect = Exception()
        nvme_command = (
            'connect', '-a', '10.0.0.1', '-s', 4420, '-t',
            'rdma', '-n', 'fakenqn', '-Q', '128', '-l', '-1')
        self.assertEqual(
            self.connector.connect_to_portals(
                self.connector, 'fakenqn', [('10.0.0.1', 4420, 'RoCEv2')]),
            False)
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

    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_device_in_raid')
    def test_handle_replicated_volume_not_found(
            self, mock_device_raid):
        mock_device_raid.return_value = False
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._handle_replicated_volume,
                          ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
                          'fakealias', 4)
        mock_device_raid.assert_any_call(self.connector, '/dev/nvme1n1')
        mock_device_raid.assert_any_call(self.connector, '/dev/nvme1n2')
        mock_device_raid.assert_any_call(self.connector, '/dev/nvme1n3')

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
        mock_readlink.return_value = ''
        mock_md_name.return_value = 'mdalias'
        self.assertIsNone(self.connector.stop_and_assemble_raid(
            self.connector, ['/dev/sda'], '/dev/md/mdalias', False))
        mock_md_name.assert_called_with(self.connector, 'sda')
        mock_readlink.assert_called_with('/dev/md/mdalias')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'ks_readlink')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_md_name')
    def test_stop_and_assemble_raid(
            self, mock_md_name, mock_readlink):
        mock_readlink.return_value = '/dev/md/mdalias'
        mock_md_name.return_value = 'mdalias'
        self.assertIsNone(self.connector.stop_and_assemble_raid(
            self.connector, ['/dev/sda'], '/dev/md/mdalias', False))
        mock_md_name.assert_called_with(self.connector, 'sda')
        mock_readlink.assert_called_with('/dev/md/mdalias')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'assemble_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'ks_readlink')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_md_name')
    def test_stop_and_assemble_raid_err(self, mock_md_name, mock_readlink,
                                        mock_assemble):
        mock_readlink.return_value = '/dev/md/mdalias'
        mock_md_name.return_value = 'dummy'
        mock_assemble.side_effect = Exception()
        self.assertIsNone(self.connector.stop_and_assemble_raid(
            self.connector, ['/dev/sda'], '/dev/md/mdalias', False))
        mock_md_name.assert_called_with(self.connector, 'sda')
        mock_readlink.assert_called_with('/dev/md/mdalias')
        mock_assemble.assert_called_with(self.connector, ['/dev/sda'],
                                         '/dev/md/mdalias', False)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_assemble_raid_simple(self, mock_run_mdadm):
        self.assertEqual(self.connector.assemble_raid(
            self.connector, ['/dev/sda'], '/dev/md/md1', True), True)
        mock_run_mdadm.assert_called_with(
            self.connector,
            ['mdadm', '--assemble', '--run', '/dev/md/md1', '-o', '/dev/sda'],
            True)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_assemble_raid_simple_err(self, mock_run_mdadm):
        mock_run_mdadm.side_effect = putils.ProcessExecutionError()
        self.assertRaises(putils.ProcessExecutionError,
                          self.connector.assemble_raid, self.connector,
                          ['/dev/sda'], '/dev/md/md1', True)
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

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'is_raid_exists')
    def test_end_raid(self, mock_raid_exists, mock_stop_raid, mock_os):
        mock_raid_exists.return_value = True
        mock_stop_raid.return_value = False
        mock_os.return_value = True
        self.assertIsNone(self.connector.end_raid(
            self.connector, '/dev/md/md1'))
        mock_raid_exists.assert_called_with(self.connector, '/dev/md/md1')
        mock_stop_raid.assert_called_with(self.connector, '/dev/md/md1')
        mock_os.assert_called_with('/dev/md/md1')

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'is_raid_exists')
    def test_end_raid_err(self, mock_raid_exists, mock_stop_raid, mock_os):
        mock_raid_exists.return_value = True
        mock_stop_raid.side_effect = Exception()
        mock_os.return_value = True
        self.assertIsNone(self.connector.end_raid(
            self.connector, '/dev/md/md1'))
        mock_raid_exists.assert_called_with(self.connector, '/dev/md/md1')
        mock_stop_raid.assert_called_with(self.connector, '/dev/md/md1')
        mock_os.assert_called_with('/dev/md/md1')

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

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_controller')
    def test_rescan(self, mock_get_nvme_controller, mock_run_nvme_cli):
        mock_get_nvme_controller.return_value = 'nvme1'
        mock_run_nvme_cli.return_value = None
        result = self.connector.rescan(EXECUTOR, TARGET_NQN, VOL_UUID)
        self.assertIsNone(result)
        mock_get_nvme_controller.assert_called_with(EXECUTOR, TARGET_NQN)
        nvme_command = ('ns-rescan', NVME_DEVICE_PATH)
        mock_run_nvme_cli.assert_called_with(EXECUTOR, nvme_command)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_controller')
    def test_rescan_err(self, mock_get_nvme_controller, mock_run_nvme_cli):
        mock_get_nvme_controller.return_value = 'nvme1'
        mock_run_nvme_cli.side_effect = Exception()
        self.assertRaises(exception.CommandExecutionFailed,
                          self.connector.rescan, EXECUTOR, TARGET_NQN,
                          VOL_UUID)
        mock_get_nvme_controller.assert_called_with(EXECUTOR, TARGET_NQN)
        nvme_command = ('ns-rescan', NVME_DEVICE_PATH)
        mock_run_nvme_cli.assert_called_with(EXECUTOR, nvme_command)

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_raid_exists_not(self, mock_execute):
        mock_execute.return_value = (VOL_UUID + "\n", "")
        result = self.connector.is_raid_exists(EXECUTOR, NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--detail', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_raid_exists(self, mock_execute):
        mock_execute.return_value = (NVME_DEVICE_PATH + ':' + "\n", "")
        result = self.connector.is_raid_exists(EXECUTOR, NVME_DEVICE_PATH)
        self.assertEqual(True, result)
        cmd = ['mdadm', '--detail', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_raid_exists_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError
        result = self.connector.is_raid_exists(EXECUTOR, NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--detail', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_get_md_name(self, mock_execute):
        mock_execute.return_value = ('nvme1' + "\n", "")
        result = self.connector.get_md_name(EXECUTOR, NVME_DEVICE_PATH)
        self.assertEqual('nvme1', result)
        get_md_cmd = 'cat /proc/mdstat | grep /dev/nvme1 | awk \'{print $1;}\''
        cmd = ['bash', '-c', get_md_cmd]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_get_md_name_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        result = self.connector.get_md_name(EXECUTOR, NVME_DEVICE_PATH)
        self.assertIsNone(result)
        get_md_cmd = 'cat /proc/mdstat | grep /dev/nvme1 | awk \'{print $1;}\''
        cmd = ['bash', '-c', get_md_cmd]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_device_in_raid(self, mock_execute):
        mock_execute.return_value = (NVME_DEVICE_PATH + ':' + "\n", "")
        result = self.connector._is_device_in_raid(self.connector,
                                                   NVME_DEVICE_PATH)
        self.assertEqual(True, result)
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_device_in_raid_not_found(self, mock_execute):
        mock_execute.return_value = (VOL_UUID + "\n", "")
        result = self.connector._is_device_in_raid(self.connector,
                                                   NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_device_in_raid_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        result = self.connector._is_device_in_raid(self.connector,
                                                   NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_run_mdadm(self, mock_execute):
        mock_execute.return_value = (VOL_UUID + "\n", "")
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        result = self.connector.run_mdadm(EXECUTOR, cmd)
        self.assertEqual(VOL_UUID, result)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_run_mdadm_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        result = self.connector.run_mdadm(EXECUTOR, cmd)
        self.assertIsNone(result)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    @mock.patch.object(glob, 'glob')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_controller')
    def test_get_nvme_device_path(self, mock_get_nvme_controller, mock_glob,
                                  mock_execute):
        mock_get_nvme_controller.return_value = 'nvme1'
        block_dev_path = '/sys/class/nvme-fabrics/ctl/nvme1/nvme1n*'
        mock_glob.side_effect = [['/sys/class/nvme-fabrics/ctl/nvme1/nvme1n1']]
        mock_execute.return_value = (VOL_UUID + "\n", "")
        cmd = ['cat', '/sys/class/nvme-fabrics/ctl/nvme1/nvme1n1/uuid']
        result = self.connector.get_nvme_device_path(EXECUTOR, TARGET_NQN,
                                                     VOL_UUID)
        mock_get_nvme_controller.assert_called_with(EXECUTOR, TARGET_NQN)
        self.assertEqual(NVME_NS_PATH, result)
        mock_glob.assert_any_call(block_dev_path)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])

    def execute_side_effect(self, value, run_as_root, root_helper):
        if 'nqn' in value:
            return TARGET_NQN + "\n", ""
        if 'state' in value:
            return 'live' + "\n", ""

    def execute_side_effect_not_live(self, value, run_as_root, root_helper):
        if 'nqn' in value:
            return TARGET_NQN + "\n", ""
        if 'state' in value:
            return 'dead' + "\n", ""

    def execute_side_effect_not_found(self, value, run_as_root, root_helper):
        if 'nqn' in value:
            return "dummy" + "\n", ""
        if 'state' in value:
            return 'live' + "\n", ""

    @mock.patch.object(executor.Executor, '_execute',
                       side_effect=execute_side_effect)
    @mock.patch.object(glob, 'glob')
    def test_get_nvme_controller(self, mock_glob, mock_execute):
        ctrl_path = '/sys/class/nvme-fabrics/ctl/nvme*'
        mock_glob.side_effect = [['/sys/class/nvme-fabrics/ctl/nvme1']]
        cmd = ['cat', '/sys/class/nvme-fabrics/ctl/nvme1/state']
        result = self.connector._get_nvme_controller(EXECUTOR, TARGET_NQN)
        self.assertEqual('nvme1', result)
        mock_glob.assert_any_call(ctrl_path)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])

    @mock.patch.object(executor.Executor, '_execute',
                       side_effect=execute_side_effect_not_live)
    @mock.patch.object(glob, 'glob')
    def test_get_nvme_controller_not_live(self, mock_glob, mock_execute):
        ctrl_path = '/sys/class/nvme-fabrics/ctl/nvme*'
        mock_glob.side_effect = [['/sys/class/nvme-fabrics/ctl/nvme1']]
        cmd = ['cat', '/sys/class/nvme-fabrics/ctl/nvme1/state']
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._get_nvme_controller, EXECUTOR,
                          TARGET_NQN)
        mock_glob.assert_any_call(ctrl_path)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])

    @mock.patch.object(executor.Executor, '_execute',
                       side_effect=execute_side_effect_not_found)
    @mock.patch.object(glob, 'glob')
    def test_get_nvme_controller_not_found(self, mock_glob, mock_execute):
        ctrl_path = '/sys/class/nvme-fabrics/ctl/nvme*'
        mock_glob.side_effect = [['/sys/class/nvme-fabrics/ctl/nvme1']]
        cmd = ['cat', '/sys/class/nvme-fabrics/ctl/nvme1/state']
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._get_nvme_controller, EXECUTOR,
                          TARGET_NQN)
        mock_glob.assert_any_call(ctrl_path)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])

    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_file_available(self, mock_open):
        mock_open.return_value.__enter__.return_value.read = (
            lambda: HOST_NQN + "\n")
        host_nqn = self._get_host_nqn()
        self.assertEqual(host_nqn, HOST_NQN)

    @mock.patch.object(executor.Executor, '_execute')
    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_err(self, mock_open, mock_execute):
        mock_execute.side_effect = Exception()
        mock_open.side_effect = IOError()
        result = self.connector._get_host_nqn()
        self.assertIsNone(result)

    @mock.patch.object(executor.Executor, '_execute')
    def test_run_nvme_cli(self, mock_execute):
        mock_execute.return_value = ("\n", "")
        cmd = 'dummy command'
        result = self.connector.run_nvme_cli(EXECUTOR, cmd)
        self.assertEqual(("\n", ""), result)

    def test_ks_readlink(self):
        dest = 'dummy path'
        result = self.connector.ks_readlink(dest)
        self.assertEqual('', result)

    @mock.patch.object(executor.Executor, '_execute')
    def test_get_fs_type_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        result = self.connector._get_fs_type(NVME_DEVICE_PATH)
        self.assertIsNone(result)
        cmd = ['blkid', NVME_DEVICE_PATH, '-s', 'TYPE', '-o', 'value']
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])
        self.assertEqual(args[3], cmd[3])
        self.assertEqual(args[4], cmd[4])
        self.assertEqual(args[5], cmd[5])

    def _get_host_nqn(self):
        try:
            with open('/etc/nvme/hostnqn', 'r') as f:
                host_nqn = f.read().strip()
                f.close()
        except IOError:
            host_nqn = HOST_NQN
        return host_nqn
