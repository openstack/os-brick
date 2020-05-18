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
from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator.connectors import nvmeof
from os_brick.initiator import linuxscsi
from os_brick.tests.initiator import test_connector

FAKE_NVME_LIST_OUTPUT = """
Node             SN                   Model                                  \
  Namespace Usage                      Format           FW Rev\n
---------------- -------------------- ---------------------------------------\
- --------- -------------------------- ---------------- --------\n
/dev/nvme0n1     67ff9467da6e5567     Linux                                  \
  10          1.07  GB /   1.07  GB    512   B +  0 B   4.8.0-58\n
/dev/nvme11n12   fecc8e73584753d7     Linux                                  \
  1           3.22  GB /   3.22  GB    512   B +  0 B   4.8.0-56\n
"""

FAKE_NVME_LIST_SUBSYS = """
{
  "Subsystems" : [
    {
      "Name" : "nvme-subsys0",
      "NQN" : "nqn.fake:cnode1"
    },
    {
      "Paths" : [
        {
          "Name" : "nvme0",
          "Transport" : "rdma",
          "Address" : "traddr=10.0.2.15 trsvcid=4420"
        }
      ]
    },
    {
      "Name" : "nvme-subsys1",
      "NQN" : "nqn.2016-06.io.spdk:cnode1"
    },
    {
      "Paths" : [
        {
          "Name" : "nvme1",
          "Transport" : "rdma",
          "Address" : "traddr=10.0.2.15 trsvcid=4420"
        }
      ]
    }
  ]
}
"""

NVME_DATA1 = {'nvme_transport_type': 'rdma',
              'conn_nqn': 'nqn.2016-06.io.spdk:cnode1',
              'target_portal': '10.0.2.15',
              'port': '4420'}

NVME_DATA2 = {'nvme_transport_type': 'rdma',
              'conn_nqn': 'nqn.2016-06.io.spdk:cnode2',
              'target_portal': '10.0.2.15',
              'port': '4420'}


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
        uuid = self.connector._get_system_uuid()
        expected_uuid = "9126E942-396D-11E7-B0B7-A81E84C186D1"
        self.assertEqual(expected_uuid, uuid)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test_get_connector_properties_without_sysuuid(
            self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError
        props = self.connector.get_connector_properties('sudo')
        expected_props = {}
        self.assertEqual(expected_props, props)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_system_uuid',
                       autospec=True)
    def test_get_connector_properties_with_sysuuid(
            self, mock_sysuuid):
        mock_sysuuid.return_value = "9126E942-396D-11E7-B0B7-A81E84C186D1"
        props = self.connector.get_connector_properties('sudo')
        expected_props = {
            "system uuid": "9126E942-396D-11E7-B0B7-A81E84C186D1"}
        self.assertEqual(expected_props, props)

    def _nvmeof_list_cmd(self, *args, **kwargs):
        return FAKE_NVME_LIST_OUTPUT, None

    def test__get_nvme_devices(self):
        expected = ['/dev/nvme0n1', '/dev/nvme11n12']
        self.connector._execute = self._nvmeof_list_cmd
        actual = self.connector._get_nvme_devices()
        self.assertEqual(expected, actual)

    @ddt.unpack
    @ddt.data({'expected': True, 'nvme': NVME_DATA1,
               'list_subsys': FAKE_NVME_LIST_SUBSYS,
               'nvme_list': ['/dev/nvme0n1', '/dev/nvme1n1']},
              {'expected': False, 'nvme': NVME_DATA2,
               'list_subsys': FAKE_NVME_LIST_SUBSYS,
               'nvme_list': ['/dev/nvme1n1']},
              {'expected': False, 'nvme': NVME_DATA1,
               'list_subsys': '{}',
               'nvme_list': ['dev/nvme1n1']})
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys',
                       autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test__wait_for_blk(self, mock_sleep, mock_nvme_subsys,
                           mock_nvme_dev, expected, nvme,
                           list_subsys, nvme_list):
        mock_nvme_subsys.return_value = (list_subsys, "")
        mock_nvme_dev.return_value = nvme_list
        actual = self.connector._wait_for_blk(**nvme)
        self.assertEqual(expected, actual)

    @ddt.unpack
    @ddt.data({'expected': False, 'nvme': NVME_DATA1,
               'list_subsys': FAKE_NVME_LIST_SUBSYS,
               'nvme_list': ['/dev/nvme0n1']})
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys',
                       autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test__wait_for_blk_raise(self, mock_sleep, mock_nvme_subsys,
                                 mock_nvme_dev, expected, nvme,
                                 list_subsys, nvme_list):
        mock_nvme_subsys.return_value = (list_subsys, "")
        mock_nvme_dev.return_value = nvme_list
        self.assertRaises(exception.NotFound,
                          self.connector._wait_for_blk,
                          **nvme)

    @ddt.unpack
    @ddt.data({'expected': True, 'nvme': NVME_DATA1,
               'list_subsys': FAKE_NVME_LIST_SUBSYS,
               'nvme_list': ['dev/nvme0n1', '/dev/nvme1n1']})
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys',
                       autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test__wait_for_blk_retry_success(self, mock_sleep, mock_nvme_subsys,
                                         mock_nvme_dev, expected, nvme,
                                         list_subsys, nvme_list):
        mock_nvme_subsys.return_value = (list_subsys, "")
        mock_nvme_dev.side_effect = [[], nvme_list]
        actual = self.connector._wait_for_blk(**nvme)
        self.assertEqual(expected, actual)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_get_nvme_devices_raise(self, mock_sleep, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError
        self.assertRaises(exception.CommandExecutionFailed,
                          self.connector._get_nvme_devices)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_wait_for_blk',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_volume(self, mock_sleep, mock_execute, mock_devices,
                            mock_blk):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}

        mock_devices.side_effect = [
            ['/dev/nvme0n1'], ['/dev/nvme0n2']]
        mock_blk.return_value = True

        device_info = self.connector.connect_volume(
            connection_properties)
        self.assertEqual('/dev/nvme0n2', device_info['path'])
        self.assertEqual('block', device_info['type'])

        self.assertEqual(2, mock_devices.call_count)

        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'connect', '-t',
            connection_properties['transport_type'], '-n',
            'nqn.volume_123',
            '-a', connection_properties['target_portal'],
            '-s', connection_properties['target_port'],
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_wait_for_blk',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_volume_hostnqn(
            self, mock_sleep, mock_execute, mock_devices,
            mock_blk):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma',
                                 'host_nqn': 'nqn.host_456'}

        mock_devices.side_effect = [
            ['/dev/nvme0n1'], ['/dev/nvme0n2']]
        mock_blk.return_value = True

        device_info = self.connector.connect_volume(
            connection_properties)
        self.assertEqual('/dev/nvme0n2', device_info['path'])
        self.assertEqual('block', device_info['type'])

        self.assertEqual(2, mock_devices.call_count)

        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'connect',
            '-t', connection_properties['transport_type'],
            '-n', connection_properties['nqn'],
            '-a', connection_properties['target_portal'],
            '-s', connection_properties['target_port'],
            '-q', connection_properties['host_nqn'],
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_volume_raise(self, mock_sleep, mock_execute):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}
        mock_execute.side_effect = putils.ProcessExecutionError
        self.assertRaises(exception.CommandExecutionFailed,
                          self.connector.connect_volume,
                          connection_properties)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_subsys',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_wait_for_blk',
                       autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_volume_wait_for_blk_raise(self, mock_sleep, mock_blk,
                                               mock_subsys, mock_devices,
                                               mock_execute):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}
        mock_blk.side_effect = exception.NotFound
        self.assertRaises(exception.NotFound,
                          self.connector.connect_volume,
                          connection_properties)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_wait_for_blk',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_volume_max_retry(
            self, mock_sleep, mock_execute, mock_devices,
            mock_blk):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}

        mock_devices.return_value = '/dev/nvme0n1'
        mock_blk.return_value = True

        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector.connect_volume,
                          connection_properties)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_wait_for_blk',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_volume_nvmelist_retry_success(
            self, mock_sleep, mock_execute, mock_devices,
            mock_blk):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}
        mock_devices.side_effect = [
            ['/dev/nvme0n1'],
            ['/dev/nvme0n1'],
            ['/dev/nvme0n1', '/dev/nvme0n2']]
        mock_blk.return_value = True
        device_info = self.connector.connect_volume(
            connection_properties)
        self.assertEqual('/dev/nvme0n2', device_info['path'])
        self.assertEqual('block', device_info['type'])

    @mock.patch.object(nvmeof.NVMeOFConnector, '_wait_for_blk',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_nvme_retry_success(
            self, mock_sleep, mock_execute, mock_devices,
            mock_blk):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}
        mock_devices.side_effect = [
            ['/dev/nvme0n1'],
            ['/dev/nvme0n1', '/dev/nvme0n2']]
        mock_blk.return_value = True
        device_info = self.connector.connect_volume(
            connection_properties)
        mock_execute.side_effect = [
            putils.ProcessExecutionError,
            putils.ProcessExecutionError,
            None]
        self.assertEqual('/dev/nvme0n2', device_info['path'])
        self.assertEqual('block', device_info['type'])

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_nova(
            self, mock_sleep, mock_execute, mock_devices):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '/dev/nvme0n1',
                                 'transport_type': 'rdma'}
        mock_devices.return_value = '/dev/nvme0n1'
        self.connector.disconnect_volume(connection_properties, None)
        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'disconnect', '-n', 'nqn.volume_123',
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_cinder(
            self, mock_sleep, mock_execute, mock_devices):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'transport_type': 'rdma'}
        device_info = {'path': '/dev/nvme0n1'}
        mock_devices.return_value = '/dev/nvme0n1'
        self.connector.disconnect_volume(connection_properties,
                                         device_info,
                                         ignore_errors=True)

        mock_execute.assert_called_once_with(
            self.connector,
            'nvme', 'disconnect', '-n', 'nqn.volume_123',
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_nvme_devices',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    @mock.patch('os_brick.utils._time_sleep')
    def test_disconnect_volume_raise(
            self, mock_sleep, mock_execute, mock_devices):
        mock_execute.side_effect = putils.ProcessExecutionError
        mock_devices.return_value = '/dev/nvme0n1'
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '/dev/nvme0n1',
                                 'transport_type': 'rdma'}

        self.assertRaises(putils.ProcessExecutionError,
                          self.connector.disconnect_volume,
                          connection_properties,
                          None)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths',
                       autospec=True)
    def test_extend_volume_no_path(self, mock_volume_paths):
        mock_volume_paths.return_value = []
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}

        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector.extend_volume,
                          connection_properties)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path',
                       autospec=True)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'extend_volume', autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths',
                       autospec=True)
    def test_extend_volume(self, mock_volume_paths, mock_scsi_extend,
                           mock_scsi_find_mpath):
        fake_new_size = 1024
        mock_volume_paths.return_value = ['/dev/vdx']
        mock_scsi_extend.return_value = fake_new_size
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}
        new_size = self.connector.extend_volume(connection_properties)
        self.assertEqual(fake_new_size, new_size)
        self.assertFalse(mock_scsi_find_mpath.called)
