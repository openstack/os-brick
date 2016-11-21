# Copyright 2016 Cloudbase Solutions Srl
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

import ddt
import mock

from os_brick import exception
from os_brick.initiator.windows import fibre_channel as fc
from os_brick.tests.windows import test_base


@ddt.ddt
class WindowsFCConnectorTestCase(test_base.WindowsConnectorTestBase):
    def setUp(self):
        super(WindowsFCConnectorTestCase, self).setUp()
        self._connector = fc.WindowsFCConnector(
            device_scan_interval=mock.sentinel.rescan_interval)

        self._diskutils = self._connector._diskutils
        self._fc_utils = self._connector._fc_utils

    @ddt.data(True, False)
    @mock.patch.object(fc.utilsfactory, 'get_fc_utils')
    def test_get_volume_connector_props(self, valid_fc_hba_ports,
                                        mock_get_fc_utils):
        fake_fc_hba_ports = [{'node_name': mock.sentinel.node_name,
                              'port_name': mock.sentinel.port_name},
                             {'node_name': mock.sentinel.second_node_name,
                              'port_name': mock.sentinel.second_port_name}]
        self._fc_utils = mock_get_fc_utils.return_value
        self._fc_utils.get_fc_hba_ports.return_value = (
            fake_fc_hba_ports if valid_fc_hba_ports else [])

        props = self._connector.get_connector_properties()

        self._fc_utils.refresh_hba_configuration.assert_called_once_with()
        self._fc_utils.get_fc_hba_ports.assert_called_once_with()

        if valid_fc_hba_ports:
            expected_props = {
                'wwpns': [mock.sentinel.port_name,
                          mock.sentinel.second_port_name],
                'wwnns': [mock.sentinel.node_name,
                          mock.sentinel.second_node_name]
            }
        else:
            expected_props = {}

        self.assertItemsEqual(expected_props, props)

    @mock.patch.object(fc.WindowsFCConnector, '_get_scsi_wwn')
    @mock.patch.object(fc.WindowsFCConnector, 'get_volume_paths')
    def test_connect_volume(self, mock_get_vol_paths,
                            mock_get_scsi_wwn):
        mock_get_vol_paths.return_value = [mock.sentinel.dev_name]
        mock_get_dev_num = self._diskutils.get_device_number_from_device_name
        mock_get_dev_num.return_value = mock.sentinel.dev_num

        expected_device_info = dict(type='block',
                                    path=mock.sentinel.dev_name,
                                    number=mock.sentinel.dev_num,
                                    scsi_wwn=mock_get_scsi_wwn.return_value)
        device_info = self._connector.connect_volume(mock.sentinel.conn_props)

        self.assertEqual(expected_device_info, device_info)
        mock_get_vol_paths.assert_called_once_with(mock.sentinel.conn_props)
        mock_get_dev_num.assert_called_once_with(mock.sentinel.dev_name)
        mock_get_scsi_wwn.assert_called_once_with(mock.sentinel.dev_num)

    @mock.patch.object(fc.WindowsFCConnector, 'get_volume_paths')
    def test_connect_volume_not_found(self, mock_get_vol_paths):
        mock_get_vol_paths.return_value = []
        self.assertRaises(exception.NoFibreChannelVolumeDeviceFound,
                          self._connector.connect_volume,
                          mock.sentinel.conn_props)

    @ddt.data({'volume_mappings': [], 'expected_paths': []},
              {'volume_mappings': [dict(device_name='')] * 3,
               'expected_paths': []},
              {'volume_mappings': [dict(device_name=''),
                                   dict(device_name=mock.sentinel.disk_path)],
               'expected_paths': [mock.sentinel.disk_path]})
    @ddt.unpack
    @mock.patch('time.sleep')
    @mock.patch.object(fc.WindowsFCConnector, '_get_fc_volume_mappings')
    @mock.patch.object(fc.WindowsFCConnector, '_check_device_paths')
    def test_get_volume_paths(self, mock_check_device_paths,
                              mock_get_fc_mappings,
                              mock_sleep,
                              volume_mappings, expected_paths):
        mock_get_fc_mappings.return_value = volume_mappings

        vol_paths = self._connector.get_volume_paths(mock.sentinel.conn_props)
        self.assertEqual(expected_paths, vol_paths)

        # In this test case, either the volume is found after the first
        # attempt, either it's not found at all, in which case we'd expect
        # the number of retries to be the requested maximum number of rescans.
        expected_try_count = (1 if expected_paths
                              else self._connector.device_scan_attempts)
        self._diskutils.rescan_disks.assert_has_calls(
            [mock.call()] * expected_try_count)
        mock_get_fc_mappings.assert_has_calls(
            [mock.call(mock.sentinel.conn_props)] * expected_try_count)
        mock_check_device_paths.assert_called_once_with(
            set(vol_paths))
        mock_sleep.assert_has_calls(
            [mock.call(mock.sentinel.rescan_interval)] *
            (expected_try_count - 1))

    @mock.patch.object(fc.WindowsFCConnector, '_get_fc_hba_mappings')
    def test_get_fc_volume_mappings(self, mock_get_fc_hba_mappings):
        fake_target_wwpn = 'FAKE_TARGET_WWPN'
        fake_conn_props = dict(target_lun=mock.sentinel.target_lun,
                               target_wwn=[fake_target_wwpn])

        mock_hba_mappings = {mock.sentinel.node_name: mock.sentinel.hba_ports}
        mock_get_fc_hba_mappings.return_value = mock_hba_mappings

        all_target_mappings = [{'device_name': mock.sentinel.dev_name,
                                'port_name': fake_target_wwpn,
                                'lun': mock.sentinel.target_lun},
                               {'device_name': mock.sentinel.dev_name_1,
                                'port_name': mock.sentinel.target_port_name_1,
                                'lun': mock.sentinel.target_lun},
                               {'device_name': mock.sentinel.dev_name,
                                'port_name': mock.sentinel.target_port_name,
                                'lun': mock.sentinel.target_lun_1}]
        expected_mappings = [all_target_mappings[0]]

        self._fc_utils.get_fc_target_mappings.return_value = (
            all_target_mappings)

        volume_mappings = self._connector._get_fc_volume_mappings(
            fake_conn_props)
        self.assertEqual(expected_mappings, volume_mappings)

    def test_get_fc_hba_mappings(self):
        fake_fc_hba_ports = [{'node_name': mock.sentinel.node_name,
                              'port_name': mock.sentinel.port_name}]

        self._fc_utils.get_fc_hba_ports.return_value = fake_fc_hba_ports

        resulted_mappings = self._connector._get_fc_hba_mappings()

        expected_mappings = {
            mock.sentinel.node_name: [mock.sentinel.port_name]}
        self.assertEqual(expected_mappings, resulted_mappings)
