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
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests.initiator import test_connector
from os_brick import utils


TARGET_NQN = 'target.nqn'
EXECUTOR = executor.Executor(None)
VOL_UUID = 'c20aba21-6ef6-446b-b374-45733b4883ba'
NVME_DEVICE_PATH = '/dev/nvme1'
NVME_NS_PATH = '/dev/nvme1n1'
NVME_DEVICE_NGUID = '4941ef7595b8ee978ccf096800f205c6'
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
    'volume_replicas': volume_replicas,
    'replica_count': 3
}
fake_portal = ('fake', 'portal', 'tcp')
fake_controller = '/sys/class/nvme-fabrics/ctl/nvme1'
fake_controllers_map = {'traddr=fakeaddress,trsvcid=4430': 'nvme1'}
nvme_list_subsystems_stdout = """
 {
   "Subsystems" : [
     {
       "Name" : "nvme-subsys0",
       "NQN" : "nqn.2016-06.io.spdk:cnode1"
     },
     {
       "Paths" : [
         {
           "Name" : "nvme0",
           "Transport" : "tcp",
           "Address" : "traddr=10.0.2.15 trsvcid=4420"
         }
       ]
     },
    {
       "Name" : "nvme-subsys1",
       "NQN" : "nqn.2016-06.io.spdk:cnode2"
     },
     {
       "Paths" : [
         {
           "Name" : "nvme1",
           "Transport" : "rdma",
           "Address" : "traddr=10.0.2.16 trsvcid=4420"
         },
        {
           "Name" : "nvme2",
           "Transport" : "rdma",
           "Address" : "traddr=10.0.2.17 trsvcid=4420"
         }
       ]
     }
   ]
 }
"""

nvme_list_stdout = """
Node          SN      Model Namespace Usage            Format      FW Rev
------------- ------- ----- --------- ---------------- ----------- -------
/dev/nvme0n1  AB12345 s123  12682     0.00 B / 2.15 GB 512 B + 0 B 2.1.0.0
/dev/nvme0n2  AB12345 s123  12683     0.00 B / 1.07 GB 512 B + 0 B 2.1.0.0
"""


@ddt.ddt
class NVMeOFConnectorTestCase(test_connector.ConnectorTestCase):

    """Test cases for NVMe initiator class."""

    def setUp(self):
        super(NVMeOFConnectorTestCase, self).setUp()
        self.connector = nvmeof.NVMeOFConnector(None,
                                                execute=self.fake_execute,
                                                use_multipath=False)

    @mock.patch.object(priv_rootwrap, 'custom_execute', autospec=True)
    def test_nvme_present(self, mock_execute):
        nvme_present = self.connector.nvme_present()
        self.assertTrue(nvme_present)

    @ddt.data(OSError(2, 'FileNotFoundError'), Exception())
    @mock.patch('os_brick.initiator.connectors.nvmeof.LOG')
    @mock.patch.object(priv_rootwrap, 'custom_execute', autospec=True)
    def test_nvme_present_exception(self, exc, mock_execute, mock_log):
        mock_execute.side_effect = exc
        nvme_present = self.connector.nvme_present()
        log = mock_log.debug if isinstance(exc, OSError) else mock_log.warning
        log.assert_called_once()
        self.assertFalse(nvme_present)

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

    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported',
                       return_value=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, 'nvme_present',
                       return_value=True)
    @mock.patch.object(utils, 'get_host_nqn',
                       return_value='fakenqn')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_system_uuid',
                       return_value=None)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid',
                       return_value=None)
    def test_get_connector_properties_without_sysuuid(self, mock_host_uuid,
                                                      mock_sysuuid, mock_nqn,
                                                      mock_nvme_present,
                                                      mock_nat_mpath_support):
        props = self.connector.get_connector_properties('sudo')
        expected_props = {'nqn': 'fakenqn', 'nvme_native_multipath': False}
        self.assertEqual(expected_props, props)

    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported',
                       return_value=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, 'nvme_present')
    @mock.patch.object(utils, 'get_host_nqn', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_system_uuid',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid', autospec=True)
    def test_get_connector_properties_with_sysuuid(self, mock_host_uuid,
                                                   mock_sysuuid, mock_nqn,
                                                   mock_nvme_present,
                                                   mock_native_mpath_support):
        mock_host_uuid.return_value = HOST_UUID
        mock_sysuuid.return_value = SYS_UUID
        mock_nqn.return_value = HOST_NQN
        mock_nvme_present.return_value = True
        props = self.connector.get_connector_properties('sudo')
        expected_props = {"system uuid": SYS_UUID, "nqn": HOST_NQN,
                          "uuid": HOST_UUID, 'nvme_native_multipath': False}
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
            'volume_replicas': [volume_replicas[0]],
            'replica_count': 1
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

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test__try_connect_nvme_idempotent(self, mock_execute):
        cmd = [
            'nvme', 'connect',
            '-t', 'tcp',
            '-n', TARGET_NQN,
            '-a', 'portal',
            '-s', 4420]
        mock_execute.side_effect = putils.ProcessExecutionError(exit_code=70)
        self.connector._try_connect_nvme(cmd)
        mock_execute.assert_called_once_with(self.connector,
                                             *cmd,
                                             root_helper=None,
                                             run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices')
    def test__get_device_path(self, mock_nvme_devices):
        mock_nvme_devices.return_value = ['/dev/nvme0n1',
                                          '/dev/nvme1n1',
                                          '/dev/nvme0n2']
        current_devices = ['/dev/nvme0n1', '/dev/nvme0n2']
        self.assertEqual(self.connector._get_device_path(current_devices),
                         '/dev/nvme1n1')

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices')
    def test__get_device_path_no_new_device(self, mock_nvme_devices):
        current_devices = ['/dev/nvme0n1', '/dev/nvme0n2']
        mock_nvme_devices.return_value = current_devices
        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector._get_device_path,
                          current_devices)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test__get_device_path_by_nguid(self, mock_execute):
        mock_execute.return_value = '/dev/nvme0n1\n', None
        res = self.connector._get_device_path_by_nguid(NVME_DEVICE_NGUID)
        self.assertEqual(res, '/dev/nvme0n1')

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test__get_device_path_by_nguid_empty_response(self, mock_execute):
        mock_execute.return_value = None, None
        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector._get_device_path_by_nguid,
                          NVME_DEVICE_NGUID)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test__get_device_path_by_nguid_exception(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._get_device_path_by_nguid,
                          NVME_DEVICE_NGUID)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target_volume')
    def test_connect_volume_single_rep(
            self, mock_connect_target_volume):
        connection_properties1 = {
            'target_nqn': 'fakenqn',
            'vol_uuid': 'fakeuuid',
            'volume_replicas': [volume_replicas[0]],
            'replica_count': 1
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
            self.connector._connect_volume_by_uuid(
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
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_nova(self, mock_sleep,
                                    mock_devices,
                                    mock_flush):
        device = '/dev/nvme0n1'
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': device,
                                 'transport_type': 'rdma'}
        mock_devices.return_value = [device]
        self.connector.disconnect_volume(connection_properties, None)

        mock_flush.assert_called_once_with(mock.ANY, device)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_cinder(self, mock_sleep,
                                      mock_devices,
                                      mock_flush):
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

    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_force_ignore_errors(self, mock_sleep,
                                                   mock_devices,
                                                   mock_flush):
        device = '/dev/nvme0n1'
        mock_flush.side_effect = putils.ProcessExecutionError
        mock_devices.return_value = [device]
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
            'replica_count': 3,
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
            'volume_replicas': [volume_replicas[0]],
            'replica_count': 1
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

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    def test_extend_volume_with_nguid(self, mock_device_size):
        device_path = '/dev/nvme0n1'
        connection_properties = {
            'volume_nguid': NVME_DEVICE_NGUID,
            'device_path': device_path,
        }
        mock_device_size.return_value = 100
        self.assertEqual(
            self.connector.extend_volume(connection_properties),
            100
        )
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
        mock_rescan.assert_called_with(self.connector, 'fakenqn')
        mock_device_path.assert_called_with(
            self.connector, 'fakenqn', 'fakeuuid', list({}.values()))

    @mock.patch.object(nvmeof.NVMeOFConnector, 'connect_to_portals')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    def test__connect_target_volume_not_connected(
            self, mock_device_path, mock_portals):
        mock_device_path.side_effect = exception.VolumeDeviceNotFound()
        mock_portals.return_value = False
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_target_volume, TARGET_NQN,
                          VOL_UUID, [('fake', 'portal', 'tcp')])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'connect_to_portals')
    def test__connect_target_volume_no_portals_con(
            self, mock_portals, mock_controller):
        mock_controller.side_effect = exception.VolumeDeviceNotFound()
        mock_portals.return_value = None
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_target_volume, 'fakenqn',
                          'fakeuuid', [fake_portal])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_device_path')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_live_nvme_controllers_map')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'connect_to_portals')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    def test__connect_target_volume_new_device_path(
            self, mock_rescan, mock_connect_portal,
            mock_get_live_nvme_controllers_map, mock_device_path):
        mock_device_path.return_value = '/dev/nvme0n1'
        mock_rescan.return_value = {}
        mock_connect_portal.return_value = True
        mock_get_live_nvme_controllers_map.return_value = fake_controllers_map
        self.assertEqual(
            self.connector._connect_target_volume(
                'fakenqn', 'fakeuuid', [('fake', 'portal', 'tcp')]),
            '/dev/nvme0n1')
        mock_rescan.assert_called_with(self.connector, 'fakenqn')
        mock_connect_portal.assert_called_with(
            self.connector, 'fakenqn', [('fake', 'portal', 'tcp')], {})
        mock_get_live_nvme_controllers_map.assert_called_with(self.connector,
                                                              'fakenqn')
        fake_controllers_map_values = fake_controllers_map.values()
        mock_device_path.assert_called_with(
            self.connector, 'fakenqn', 'fakeuuid',
            list(fake_controllers_map_values))

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    def test_connect_to_portals(self, mock_nvme_cli):
        nvme_command = (
            'connect', '-a', '10.0.0.1', '-s', 4420, '-t',
            'tcp', '-n', 'fakenqn', '-Q', '128', '-l', '-1')
        self.assertEqual(
            self.connector.connect_to_portals(
                self.connector, 'fakenqn', [('10.0.0.1', 4420, 'tcp')], {}),
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
                self.connector, 'fakenqn', [('10.0.0.1', 4420, 'RoCEv2')], {}),
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

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_create_raid_cmd_simple(self, mock_run_mdadm, mock_os):
        mock_os.return_value = True
        self.assertIsNone(self.connector.create_raid(
            self.connector, ['/dev/sda'], '1', 'md1', 'name', True))
        mock_run_mdadm.assert_called_with(
            self.connector,
            ['mdadm', '-C', '-o', 'md1', '-R', '-N', 'name', '--level', '1',
             '--raid-devices=1', '--bitmap=internal', '--homehost=any',
             '--failfast', '--assume-clean', '/dev/sda'])
        mock_os.assert_called_with('/dev/md/name')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'is_raid_exists')
    def test_end_raid_simple(self, mock_raid_exists, mock_stop_raid):
        mock_raid_exists.return_value = True
        mock_stop_raid.return_value = False
        self.assertIsNone(self.connector.end_raid(
            self.connector, '/dev/md/md1'))
        mock_raid_exists.assert_called_with(self.connector, '/dev/md/md1')
        mock_stop_raid.assert_called_with(self.connector, '/dev/md/md1', True)

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
        mock_stop_raid.assert_called_with(self.connector, '/dev/md/md1', True)
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
        mock_stop_raid.assert_called_with(self.connector, '/dev/md/md1', True)
        mock_os.assert_called_with('/dev/md/md1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_stop_raid_simple(self, mock_run_mdadm):
        mock_run_mdadm.return_value = 'mdadm output'
        self.assertEqual(self.connector.stop_raid(
            self.connector, '/dev/md/md1', True), 'mdadm output')
        mock_run_mdadm.assert_called_with(
            self.connector, ['mdadm', '--stop', '/dev/md/md1'], True)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_remove_raid_simple(self, mock_run_mdadm):
        self.assertIsNone(self.connector.remove_raid(
            self.connector, '/dev/md/md1'))
        mock_run_mdadm.assert_called_with(
            self.connector, ['mdadm', '--remove', '/dev/md/md1'])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_live_nvme_controllers_map')
    def test_rescan(self, mock_get_live_nvme_controllers_map,
                    mock_run_nvme_cli):
        mock_get_live_nvme_controllers_map.return_value = fake_controllers_map
        mock_run_nvme_cli.return_value = None
        result = self.connector.rescan(EXECUTOR, TARGET_NQN)
        self.assertEqual(fake_controllers_map, result)
        mock_get_live_nvme_controllers_map.assert_called_with(EXECUTOR,
                                                              TARGET_NQN)
        nvme_command = ('ns-rescan', NVME_DEVICE_PATH)
        mock_run_nvme_cli.assert_called_with(EXECUTOR, nvme_command)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_live_nvme_controllers_map')
    def test_rescan_err(self, mock_get_live_nvme_controllers_map,
                        mock_run_nvme_cli):
        mock_get_live_nvme_controllers_map.return_value = fake_controllers_map
        mock_run_nvme_cli.side_effect = Exception()
        result = self.connector.rescan(EXECUTOR, TARGET_NQN)
        self.assertEqual(fake_controllers_map, result)
        mock_get_live_nvme_controllers_map.assert_called_with(EXECUTOR,
                                                              TARGET_NQN)
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
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_nvme_controllers')
    def test_get_nvme_device_path(self, mock_get_nvme_controllers, mock_glob,
                                  mock_execute):
        mock_get_nvme_controllers.return_value = ['nvme1']
        block_dev_path = '/sys/class/block/nvme1n*/uuid'
        mock_glob.side_effect = [['/sys/class/block/nvme1n1/uuid']]
        mock_execute.return_value = (VOL_UUID + "\n", "")
        cmd = ['cat', '/sys/class/block/nvme1n1/uuid']
        result = self.connector.get_nvme_device_path(EXECUTOR, TARGET_NQN,
                                                     VOL_UUID)
        mock_get_nvme_controllers.assert_called_with(EXECUTOR, TARGET_NQN)
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

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_live_nvme_controllers_map')
    def test_get_nvme_controllers(self, mock_get_live_nvme_controllers_map):
        mock_get_live_nvme_controllers_map.return_value = fake_controllers_map
        result = self.connector.get_nvme_controllers(EXECUTOR, TARGET_NQN)
        fake_controllers_map_values = fake_controllers_map.values()
        self.assertEqual(list(fake_controllers_map_values)[0][1],
                         list(result)[0][1])
        mock_get_live_nvme_controllers_map.assert_called_with(EXECUTOR,
                                                              TARGET_NQN)

    @mock.patch.object(executor.Executor, '_execute',
                       side_effect=execute_side_effect_not_live)
    @mock.patch.object(glob, 'glob')
    def test_get_nvme_controllers_not_live(self, mock_glob, mock_execute):
        ctrl_path = '/sys/class/nvme-fabrics/ctl/nvme*'
        mock_glob.side_effect = [['/sys/class/nvme-fabrics/ctl/nvme1']]
        cmd = ['cat', '/sys/class/nvme-fabrics/ctl/nvme1/state']
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector.get_nvme_controllers, EXECUTOR,
                          TARGET_NQN)
        mock_glob.assert_any_call(ctrl_path)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])

    @mock.patch.object(executor.Executor, '_execute',
                       side_effect=execute_side_effect_not_found)
    @mock.patch.object(glob, 'glob')
    def test_get_nvme_controllers_not_found(self, mock_glob, mock_execute):
        ctrl_path = '/sys/class/nvme-fabrics/ctl/nvme*'
        mock_glob.side_effect = [['/sys/class/nvme-fabrics/ctl/nvme1']]
        cmd = ['cat', '/sys/class/nvme-fabrics/ctl/nvme1/state']
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector.get_nvme_controllers, EXECUTOR,
                          TARGET_NQN)
        mock_glob.assert_any_call(ctrl_path)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])

    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_file_available(self, mock_open):
        mock_open.return_value.__enter__.return_value.read = (
            lambda: HOST_NQN + "\n")
        host_nqn = self._get_host_nqn()
        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'r')
        self.assertEqual(HOST_NQN, host_nqn)

    @mock.patch.object(utils.priv_nvme, 'create_hostnqn')
    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_io_err(self, mock_open, mock_create):
        mock_create.return_value = mock.sentinel.nqn
        mock_open.side_effect = IOError()
        result = utils.get_host_nqn()
        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'r')
        mock_create.assert_called_once_with()
        self.assertEqual(mock.sentinel.nqn, result)

    @mock.patch.object(utils.priv_nvme, 'create_hostnqn')
    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_err(self, mock_open, mock_create):
        mock_open.side_effect = Exception()
        result = utils.get_host_nqn()
        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'r')
        mock_create.assert_not_called()
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

    @mock.patch.object(executor.Executor, '_execute',
                       return_value=('', 'There was a big error'))
    def test_get_fs_type_err(self, mock_execute):
        result = self.connector._get_fs_type(NVME_DEVICE_PATH)
        self.assertIsNone(result)
        mock_execute.assert_called_once_with(
            'blkid', NVME_DEVICE_PATH, '-s', 'TYPE', '-o', 'value',
            run_as_root=True, root_helper=self.connector._root_helper,
            check_exit_code=False)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices')
    def test__is_nvme_available(self, mock_nvme_devices):
        mock_nvme_devices.return_value = {'/dev/nvme0n1',
                                          '/dev/nvme2n1',
                                          '/dev/nvme2n2',
                                          '/dev/nvme3n1'}
        result = self.connector._is_nvme_available('nvme2')
        self.assertTrue(result)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices')
    def test__is_nvme_available_wrong_name(self, mock_nvme_devices):
        mock_nvme_devices.return_value = {'/dev/nvme0n1',
                                          '/dev/nvme2n1',
                                          '/dev/nvme2n2',
                                          '/dev/nvme3n1'}
        self.assertRaises(exception.NotFound,
                          self.connector._is_nvme_available,
                          'nvme1')

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices')
    def test__is_nvme_available_no_devices(self, mock_nvme_devices):
        mock_nvme_devices.return_value = []
        self.assertRaises(exception.NotFound,
                          self.connector._is_nvme_available,
                          'nvme1')

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices')
    def test__is_nvme_available_fail_to_get_devices(self, mock_nvme_devices):
        mock_nvme_devices.side_effect = exception.CommandExecutionFailed()
        self.assertRaises(exception.CommandExecutionFailed,
                          self.connector._is_nvme_available,
                          'nvme1')

    @mock.patch.object(executor.Executor, '_execute')
    def test__get_nvme_devices(self, mock_execute):
        mock_execute.return_value = nvme_list_stdout, None
        res = self.connector._get_nvme_devices()
        self.assertEqual(set(res), {'/dev/nvme0n1', '/dev/nvme0n2'})

    @mock.patch.object(executor.Executor, '_execute')
    def test__get_nvme_devices_failed(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        self.assertRaises(exception.CommandExecutionFailed,
                          self.connector._get_nvme_devices)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_nvme_available')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys')
    def test__wait_for_blk(self, mock_nvme_subsys, mock_nvme_avail):
        mock_nvme_subsys.return_value = nvme_list_subsystems_stdout, None
        mock_nvme_avail.return_value = True
        result = self.connector._wait_for_blk('rdma',
                                              'nqn.2016-06.io.spdk:cnode2',
                                              '10.0.2.16', '4420')
        self.assertTrue(result)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys')
    def test__wait_for_blk_cli_exception(self, mock_nvme_subsys):
        mock_nvme_subsys.side_effect = putils.ProcessExecutionError()
        self.assertRaises(putils.ProcessExecutionError,
                          self.connector._wait_for_blk,
                          'rdma',
                          'nqn.2016-06.io.spdk:cnode2',
                          '10.0.2.16', '4420')

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys')
    def test__wait_for_blk_bad_json(self, mock_nvme_subsys):
        mock_nvme_subsys.return_value = ".", None
        result = self.connector._wait_for_blk('rdma',
                                              'nqn.2016-06.io.spdk:cnode2',
                                              '10.0.2.16', '4420')
        self.assertFalse(result)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys')
    def test__wait_for_blk_ip_not_found(self, mock_nvme_subsys):
        mock_nvme_subsys.return_value = nvme_list_subsystems_stdout, None
        result = self.connector._wait_for_blk('rdma',
                                              'nqn.2016-06.io.spdk:cnode2',
                                              '10.0.2.18', '4420')
        self.assertFalse(result)

    def _get_host_nqn(self):
        host_nqn = None
        try:
            with open('/etc/nvme/hostnqn', 'r') as f:
                host_nqn = f.read().strip()
                f.close()
        except IOError:
            host_nqn = HOST_NQN
        return host_nqn

    @ddt.data(True, False)
    @mock.patch.object(nvmeof.NVMeOFConnector, 'native_multipath_supported',
                       None)
    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported')
    def test__set_native_multipath_supported(self, value, mock_ana):
        mock_ana.return_value = value
        res = self.connector._set_native_multipath_supported()
        mock_ana.assert_called_once_with()
        self.assertIs(value, res)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'native_multipath_supported',
                       True)
    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported')
    def test__set_native_multipath_supported_second_call(self, mock_ana):
        mock_ana.return_value = False
        res = self.connector._set_native_multipath_supported()
        mock_ana.assert_not_called()
        self.assertTrue(res)
