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

from unittest import mock

import ddt
from os_win import exceptions as os_win_exc

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

        self.assertCountEqual(expected_props, props)

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
              {'volume_mappings': [dict(device_name='',
                                        fcp_lun=mock.sentinel.fcp_lun)] * 3,
               'scsi_id_side_eff': os_win_exc.OSWinException,
               'expected_paths': []},
              {'volume_mappings': [dict(device_name='',
                                        fcp_lun=mock.sentinel.fcp_lun),
                                   dict(device_name=mock.sentinel.disk_path)],
               'expected_paths': [mock.sentinel.disk_path]},
              {'volume_mappings': [dict(device_name='',
                                        fcp_lun=mock.sentinel.fcp_lun)],
               'scsi_id_side_eff': [[mock.sentinel.disk_path]],
               'expected_paths': [mock.sentinel.disk_path]},
              {'volume_mappings': [dict(device_name=mock.sentinel.disk_path)],
               'use_multipath': True,
               'is_mpio_disk': True,
               'expected_paths': [mock.sentinel.disk_path]},
              {'volume_mappings': [dict(device_name=mock.sentinel.disk_path)],
               'use_multipath': True,
               'is_mpio_disk': False,
               'expected_paths': []})
    @ddt.unpack
    @mock.patch('time.sleep')
    @mock.patch.object(fc.WindowsFCConnector, '_get_fc_volume_mappings')
    @mock.patch.object(fc.WindowsFCConnector, '_get_disk_paths_by_scsi_id')
    def test_get_volume_paths(self, mock_get_disk_paths_by_scsi_id,
                              mock_get_fc_mappings,
                              mock_sleep,
                              volume_mappings, expected_paths,
                              scsi_id_side_eff=None,
                              use_multipath=False,
                              is_mpio_disk=False):
        mock_get_dev_num = self._diskutils.get_device_number_from_device_name
        mock_get_fc_mappings.return_value = volume_mappings
        mock_get_disk_paths_by_scsi_id.side_effect = scsi_id_side_eff
        self._diskutils.is_mpio_disk.return_value = is_mpio_disk

        self._connector.use_multipath = use_multipath

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
        mock_sleep.assert_has_calls(
            [mock.call(mock.sentinel.rescan_interval)] *
            (expected_try_count - 1))

        dev_names = [mapping['device_name']
                     for mapping in volume_mappings if mapping['device_name']]
        if volume_mappings and not dev_names:
            mock_get_disk_paths_by_scsi_id.assert_any_call(
                mock.sentinel.conn_props,
                volume_mappings[0]['fcp_lun'])

        if expected_paths and use_multipath:
            mock_get_dev_num.assert_called_once_with(expected_paths[0])

            self._diskutils.is_mpio_disk.assert_any_call(
                mock_get_dev_num.return_value)

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

    @mock.patch.object(fc.WindowsFCConnector, '_get_dev_nums_by_scsi_id')
    def test_get_disk_paths_by_scsi_id(self, mock_get_dev_nums):
        remote_wwpns = [mock.sentinel.remote_wwpn_0,
                        mock.sentinel.remote_wwpn_1]
        fake_init_target_map = {mock.sentinel.local_wwpn: remote_wwpns}
        conn_props = dict(initiator_target_map=fake_init_target_map)

        mock_get_dev_nums.side_effect = [os_win_exc.FCException,
                                         [mock.sentinel.dev_num]]
        mock_get_dev_name = self._diskutils.get_device_name_by_device_number
        mock_get_dev_name.return_value = mock.sentinel.dev_name

        disk_paths = self._connector._get_disk_paths_by_scsi_id(
            conn_props, mock.sentinel.fcp_lun)
        self.assertEqual([mock.sentinel.dev_name], disk_paths)

        mock_get_dev_nums.assert_has_calls([
            mock.call(mock.sentinel.local_wwpn,
                      remote_wwpn,
                      mock.sentinel.fcp_lun)
            for remote_wwpn in remote_wwpns])
        mock_get_dev_name.assert_called_once_with(mock.sentinel.dev_num)

    @mock.patch.object(fc.WindowsFCConnector, '_get_fc_hba_wwn_for_port')
    def test_get_dev_nums_by_scsi_id(self, mock_get_fc_hba_wwn):
        fake_identifier = dict(id=mock.sentinel.id,
                               type=mock.sentinel.type)

        mock_get_fc_hba_wwn.return_value = mock.sentinel.local_wwnn
        self._fc_utils.get_scsi_device_identifiers.return_value = [
            fake_identifier]
        self._diskutils.get_disk_numbers_by_unique_id.return_value = (
            mock.sentinel.dev_nums)

        dev_nums = self._connector._get_dev_nums_by_scsi_id(
            mock.sentinel.local_wwpn,
            mock.sentinel.remote_wwpn,
            mock.sentinel.fcp_lun)
        self.assertEqual(mock.sentinel.dev_nums, dev_nums)

        mock_get_fc_hba_wwn.assert_called_once_with(mock.sentinel.local_wwpn)
        self._fc_utils.get_scsi_device_identifiers.assert_called_once_with(
            mock.sentinel.local_wwnn, mock.sentinel.local_wwpn,
            mock.sentinel.remote_wwpn, mock.sentinel.fcp_lun)
        self._diskutils.get_disk_numbers_by_unique_id.assert_called_once_with(
            unique_id=mock.sentinel.id,
            unique_id_format=mock.sentinel.type)
