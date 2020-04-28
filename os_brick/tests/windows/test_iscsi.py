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
from os_brick.initiator.windows import iscsi
from os_brick.tests.windows import test_base


@ddt.ddt
class WindowsISCSIConnectorTestCase(test_base.WindowsConnectorTestBase):
    @mock.patch.object(iscsi.WindowsISCSIConnector, 'validate_initiators')
    def setUp(self, mock_validate_connectors):
        super(WindowsISCSIConnectorTestCase, self).setUp()

        self._diskutils = mock.Mock()
        self._iscsi_utils = mock.Mock()

        self._connector = iscsi.WindowsISCSIConnector(
            device_scan_interval=mock.sentinel.rescan_interval)
        self._connector._diskutils = self._diskutils
        self._connector._iscsi_utils = self._iscsi_utils

    @ddt.data({'requested_initiators': [mock.sentinel.initiator_0],
               'available_initiators': [mock.sentinel.initiator_0,
                                        mock.sentinel.initiator_1]},
              {'requested_initiators': [mock.sentinel.initiator_0],
               'available_initiators': [mock.sentinel.initiator_1]},
              {'requested_initiators': [],
               'available_initiators': [mock.sentinel.software_initiator]})
    @ddt.unpack
    def test_validate_initiators(self, requested_initiators,
                                 available_initiators):
        self._iscsi_utils.get_iscsi_initiators.return_value = (
            available_initiators)
        self._connector.initiator_list = requested_initiators

        expected_valid_initiator = not (
            set(requested_initiators).difference(set(available_initiators)))
        valid_initiator = self._connector.validate_initiators()

        self.assertEqual(expected_valid_initiator, valid_initiator)

    def test_get_initiator(self):
        initiator = self._connector.get_initiator()
        self.assertEqual(self._iscsi_utils.get_iscsi_initiator.return_value,
                         initiator)

    @mock.patch.object(iscsi, 'utilsfactory')
    def test_get_connector_properties(self, mock_utilsfactory):
        mock_iscsi_utils = (
            mock_utilsfactory.get_iscsi_initiator_utils.return_value)

        props = self._connector.get_connector_properties()
        expected_props = dict(
            initiator=mock_iscsi_utils.get_iscsi_initiator.return_value)

        self.assertEqual(expected_props, props)

    @mock.patch.object(iscsi.WindowsISCSIConnector, '_get_all_targets')
    def test_get_all_paths(self, mock_get_all_targets):
        initiators = [mock.sentinel.initiator_0, mock.sentinel.initiator_1]
        all_targets = [(mock.sentinel.portal_0, mock.sentinel.target_0,
                        mock.sentinel.lun_0),
                       (mock.sentinel.portal_1, mock.sentinel.target_1,
                        mock.sentinel.lun_1)]

        self._connector.initiator_list = initiators
        mock_get_all_targets.return_value = all_targets

        expected_paths = [
            (initiator_name, target_portal, target_iqn, target_lun)
            for target_portal, target_iqn, target_lun in all_targets
            for initiator_name in initiators]
        all_paths = self._connector._get_all_paths(mock.sentinel.conn_props)

        self.assertEqual(expected_paths, all_paths)
        mock_get_all_targets.assert_called_once_with(mock.sentinel.conn_props)

    @ddt.data(True, False)
    @mock.patch.object(iscsi.WindowsISCSIConnector, '_get_scsi_wwn')
    @mock.patch.object(iscsi.WindowsISCSIConnector, '_get_all_paths')
    def test_connect_volume(self, use_multipath,
                            mock_get_all_paths, mock_get_scsi_wwn):
        fake_paths = [(mock.sentinel.initiator_name,
                       mock.sentinel.target_portal,
                       mock.sentinel.target_iqn,
                       mock.sentinel.target_lun)] * 3
        fake_conn_props = dict(auth_username=mock.sentinel.auth_username,
                               auth_password=mock.sentinel.auth_password)

        mock_get_all_paths.return_value = fake_paths
        self._iscsi_utils.login_storage_target.side_effect = [
            os_win_exc.OSWinException, None, None]
        self._iscsi_utils.get_device_number_and_path.return_value = (
            mock.sentinel.device_number, mock.sentinel.device_path)
        self._connector.use_multipath = use_multipath

        device_info = self._connector.connect_volume(fake_conn_props)
        expected_device_info = dict(type='block',
                                    path=mock.sentinel.device_path,
                                    number=mock.sentinel.device_number,
                                    scsi_wwn=mock_get_scsi_wwn.return_value)

        self.assertEqual(expected_device_info, device_info)

        mock_get_all_paths.assert_called_once_with(fake_conn_props)
        expected_login_attempts = 3 if use_multipath else 2
        self._iscsi_utils.login_storage_target.assert_has_calls(
            [mock.call(target_lun=mock.sentinel.target_lun,
                       target_iqn=mock.sentinel.target_iqn,
                       target_portal=mock.sentinel.target_portal,
                       auth_username=mock.sentinel.auth_username,
                       auth_password=mock.sentinel.auth_password,
                       mpio_enabled=use_multipath,
                       initiator_name=mock.sentinel.initiator_name,
                       ensure_lun_available=False)] *
            expected_login_attempts)
        self._iscsi_utils.get_device_number_and_path.assert_called_once_with(
            mock.sentinel.target_iqn, mock.sentinel.target_lun,
            retry_attempts=self._connector.device_scan_attempts,
            retry_interval=self._connector.device_scan_interval,
            rescan_disks=True,
            ensure_mpio_claimed=use_multipath)
        mock_get_scsi_wwn.assert_called_once_with(mock.sentinel.device_number)

    @mock.patch.object(iscsi.WindowsISCSIConnector, '_get_all_paths')
    def test_connect_volume_exc(self, mock_get_all_paths):
        fake_paths = [(mock.sentinel.initiator_name,
                       mock.sentinel.target_portal,
                       mock.sentinel.target_iqn,
                       mock.sentinel.target_lun)] * 3

        mock_get_all_paths.return_value = fake_paths
        self._iscsi_utils.login_storage_target.side_effect = (
            os_win_exc.OSWinException)
        self._connector.use_multipath = True

        self.assertRaises(exception.BrickException,
                          self._connector.connect_volume,
                          connection_properties={})

    @mock.patch.object(iscsi.WindowsISCSIConnector, '_get_all_targets')
    def test_disconnect_volume(self, mock_get_all_targets):
        targets = [
            (mock.sentinel.portal_0, mock.sentinel.tg_0, mock.sentinel.lun_0),
            (mock.sentinel.portal_1, mock.sentinel.tg_1, mock.sentinel.lun_1)]

        mock_get_all_targets.return_value = targets
        self._iscsi_utils.get_target_luns.return_value = [mock.sentinel.lun_0]

        self._connector.disconnect_volume(mock.sentinel.conn_props,
                                          mock.sentinel.dev_info)

        self._diskutils.rescan_disks.assert_called_once_with()
        mock_get_all_targets.assert_called_once_with(mock.sentinel.conn_props)
        self._iscsi_utils.logout_storage_target.assert_called_once_with(
            mock.sentinel.tg_0)
        self._iscsi_utils.get_target_luns.assert_has_calls(
            [mock.call(mock.sentinel.tg_0), mock.call(mock.sentinel.tg_1)])

    @mock.patch.object(iscsi.WindowsISCSIConnector, '_get_all_targets')
    @mock.patch.object(iscsi.WindowsISCSIConnector, '_check_device_paths')
    def test_get_volume_paths(self, mock_check_dev_paths,
                              mock_get_all_targets):
        targets = [
            (mock.sentinel.portal_0, mock.sentinel.tg_0, mock.sentinel.lun_0),
            (mock.sentinel.portal_1, mock.sentinel.tg_1, mock.sentinel.lun_1)]

        mock_get_all_targets.return_value = targets
        self._iscsi_utils.get_device_number_and_path.return_value = [
            mock.sentinel.dev_num, mock.sentinel.dev_path]

        volume_paths = self._connector.get_volume_paths(
            mock.sentinel.conn_props)
        expected_paths = [mock.sentinel.dev_path]

        self.assertEqual(expected_paths, volume_paths)
        mock_check_dev_paths.assert_called_once_with(set(expected_paths))
