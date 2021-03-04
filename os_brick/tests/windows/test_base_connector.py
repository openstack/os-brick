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

from os_brick import exception
from os_brick.initiator.windows import base as base_win_conn
from os_brick.tests.windows import fake_win_conn
from os_brick.tests.windows import test_base


@ddt.ddt
class BaseWindowsConnectorTestCase(test_base.WindowsConnectorTestBase):
    def setUp(self):
        super(BaseWindowsConnectorTestCase, self).setUp()

        self._diskutils = mock.Mock()

        self._connector = fake_win_conn.FakeWindowsConnector()
        self._connector._diskutils = self._diskutils

    @ddt.data({},
              {'feature_available': True},
              {'feature_available': False, 'enforce_multipath': True})
    @ddt.unpack
    @mock.patch.object(base_win_conn.utilsfactory, 'get_hostutils')
    def test_check_multipath_support(self, mock_get_hostutils,
                                     feature_available=True,
                                     enforce_multipath=False):
        mock_hostutils = mock_get_hostutils.return_value
        mock_hostutils.check_server_feature.return_value = feature_available
        check_mpio = base_win_conn.BaseWindowsConnector.check_multipath_support

        if feature_available or not enforce_multipath:
            multipath_support = check_mpio(
                enforce_multipath=enforce_multipath)
            self.assertEqual(feature_available, multipath_support)
        else:
            self.assertRaises(exception.BrickException,
                              check_mpio,
                              enforce_multipath=enforce_multipath)
        mock_hostutils.check_server_feature.assert_called_once_with(
            mock_hostutils.FEATURE_MPIO)

    @ddt.data({}, {'mpio_requested': False}, {'mpio_available': True})
    @mock.patch.object(base_win_conn.BaseWindowsConnector,
                       'check_multipath_support')
    @ddt.unpack
    def test_get_connector_properties(self, mock_check_mpio,
                                      mpio_requested=True,
                                      mpio_available=True):
        mock_check_mpio.return_value = mpio_available
        enforce_multipath = False

        props = base_win_conn.BaseWindowsConnector.get_connector_properties(
            multipath=mpio_requested,
            enforce_multipath=enforce_multipath)
        self.assertEqual(mpio_requested and mpio_available,
                         props['multipath'])
        if mpio_requested:
            mock_check_mpio.assert_called_once_with(enforce_multipath)

    def test_get_scsi_wwn(self):
        mock_get_uid_and_type = self._diskutils.get_disk_uid_and_uid_type
        mock_get_uid_and_type.return_value = (mock.sentinel.disk_uid,
                                              mock.sentinel.uid_type)

        scsi_wwn = self._connector._get_scsi_wwn(mock.sentinel.dev_num)
        expected_wwn = '%s%s' % (mock.sentinel.uid_type,
                                 mock.sentinel.disk_uid)
        self.assertEqual(expected_wwn, scsi_wwn)
        mock_get_uid_and_type.assert_called_once_with(mock.sentinel.dev_num)

    @ddt.data(None, IOError)
    @mock.patch('os_brick.initiator.windows.base.open',
                new_callable=mock.mock_open)
    def test_check_valid_device(self, exc, mock_open):
        mock_open.side_effect = exc

        valid_device = self._connector.check_valid_device(
            mock.sentinel.dev_path)
        self.assertEqual(not exc, valid_device)

        mock_open.assert_any_call(mock.sentinel.dev_path, 'r')
        mock_read = mock_open.return_value.__enter__.return_value.read
        if not exc:
            mock_read.assert_called_once_with(1)

    def test_check_device_paths(self):
        # We expect an exception to be raised if the same volume
        # can be accessed through multiple paths.
        device_paths = [mock.sentinel.dev_path_0,
                        mock.sentinel.dev_path_1]
        self.assertRaises(exception.BrickException,
                          self._connector._check_device_paths,
                          device_paths)

    @mock.patch.object(fake_win_conn.FakeWindowsConnector,
                       'get_volume_paths')
    def test_extend_volume(self, mock_get_vol_paths):
        mock_vol_paths = [mock.sentinel.dev_path]
        mock_get_vol_paths.return_value = mock_vol_paths

        self._connector.extend_volume(mock.sentinel.conn_props)

        mock_get_vol_paths.assert_called_once_with(mock.sentinel.conn_props)
        mock_get_dev_num = self._diskutils.get_device_number_from_device_name
        mock_get_dev_num.assert_called_once_with(mock.sentinel.dev_path)
        self._diskutils.refresh_disk.assert_called_once_with(
            mock_get_dev_num.return_value)

    @mock.patch.object(fake_win_conn.FakeWindowsConnector,
                       'get_volume_paths')
    def test_extend_volume_missing_path(self, mock_get_vol_paths):
        mock_get_vol_paths.return_value = []

        self.assertRaises(exception.NotFound,
                          self._connector.extend_volume,
                          mock.sentinel.conn_props)

        mock_get_vol_paths.assert_called_once_with(mock.sentinel.conn_props)
