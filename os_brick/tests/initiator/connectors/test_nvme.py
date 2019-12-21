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

import mock

from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator.connectors import nvme
from os_brick.initiator import linuxscsi
from os_brick.tests.initiator import test_connector

FAKE_NVME_LIST_OUTPUT = """
Node             SN                   Model                                  \
  Namespace Usage                      Format           FW Rev\n
---------------- -------------------- ---------------------------------------\
- --------- -------------------------- ---------------- --------\n
/dev/nvme0n1     67ff9467da6e5567     Linux                                  \
  10          1.07  GB /   1.07  GB    512   B +  0 B   4.8.0-58\n
"""


class NVMeConnectorTestCase(test_connector.ConnectorTestCase):

    """Test cases for NVMe initiator class."""

    def setUp(self):
        super(NVMeConnectorTestCase, self).setUp()
        self.connector = nvme.NVMeConnector(None,
                                            execute=self.fake_execute,
                                            use_multipath=False)

    def _nvme_list_cmd(self, *args, **kwargs):
        return FAKE_NVME_LIST_OUTPUT, None

    def test__get_nvme_devices(self):
        expected = ['/dev/nvme0n1']
        self.connector._execute = self._nvme_list_cmd
        actual = self.connector._get_nvme_devices()
        self.assertEqual(expected, actual)

    @mock.patch.object(nvme.NVMeConnector, '_execute')
    @mock.patch('time.sleep')
    def test_get_nvme_devices_raise(self, mock_sleep, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError
        self.assertRaises(exception.CommandExecutionFailed,
                          self.connector._get_nvme_devices)

    @mock.patch.object(nvme.NVMeConnector, '_get_nvme_devices')
    @mock.patch.object(nvme.NVMeConnector, '_execute')
    @mock.patch('time.sleep')
    def test_connect_volume(self, mock_sleep, mock_execute, mock_devices):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}

        mock_devices.side_effect = [
            ['/dev/nvme0n1'], ['/dev/nvme0n2']]

        device_info = self.connector.connect_volume(
            connection_properties)
        self.assertEqual('/dev/nvme0n2', device_info['path'])
        self.assertEqual('block', device_info['type'])

        self.assertEqual(2, mock_devices.call_count)

        mock_execute.assert_called_once_with(
            'nvme', 'connect', '-t',
            connection_properties['transport_type'], '-n',
            'nqn.volume_123',
            '-a', connection_properties['target_portal'],
            '-s', connection_properties['target_port'],
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(nvme.NVMeConnector, '_execute')
    @mock.patch('time.sleep')
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

    @mock.patch.object(nvme.NVMeConnector, '_get_nvme_devices')
    @mock.patch.object(nvme.NVMeConnector, '_execute')
    @mock.patch('time.sleep')
    def test_connect_volume_max_retry(
            self, mock_sleep, mock_execute, mock_devices):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '',
                                 'transport_type': 'rdma'}

        mock_devices.return_value = '/dev/nvme0n1'

        self.assertRaises(exception.TargetPortalNotFound,
                          self.connector.connect_volume,
                          connection_properties)

    @mock.patch.object(nvme.NVMeConnector, '_get_nvme_devices')
    @mock.patch.object(nvme.NVMeConnector, '_execute')
    @mock.patch('time.sleep')
    def test_disconnect_volume(self, mock_sleep, mock_execute, mock_devices):
        connection_properties = {'target_portal': 'portal',
                                 'target_port': 1,
                                 'nqn': 'nqn.volume_123',
                                 'device_path': '/dev/nvme0n1',
                                 'transport_type': 'rdma'}
        mock_devices.return_value = '/dev/nvme0n1'
        self.connector.disconnect_volume(connection_properties, None)

        mock_execute.asert_called_once_with(
            'nvme', 'disconnect', '-n',
            'volume_123',
            root_helper=None,
            run_as_root=True)

    @mock.patch.object(nvme.NVMeConnector, '_get_nvme_devices')
    @mock.patch.object(nvme.NVMeConnector, '_execute')
    @mock.patch('time.sleep')
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

    @mock.patch.object(nvme.NVMeConnector, 'get_volume_paths')
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

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'extend_volume')
    @mock.patch.object(nvme.NVMeConnector, 'get_volume_paths')
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
        mock_scsi_find_mpath.assert_not_called()
