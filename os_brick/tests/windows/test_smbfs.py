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

import os
from unittest import mock

import ddt

from os_brick.initiator.windows import smbfs
from os_brick.remotefs import windows_remotefs
from os_brick.tests.windows import test_base


@ddt.ddt
class WindowsSMBFSConnectorTestCase(test_base.WindowsConnectorTestBase):
    def setUp(self):
        super(WindowsSMBFSConnectorTestCase, self).setUp()

        self._load_connector()

    @mock.patch.object(windows_remotefs, 'WindowsRemoteFsClient')
    def _load_connector(self, mock_remotefs_cls, *args, **kwargs):
        self._connector = smbfs.WindowsSMBFSConnector(*args, **kwargs)
        self._remotefs = mock_remotefs_cls.return_value

        self._vhdutils = self._connector._vhdutils
        self._diskutils = self._connector._diskutils

    @mock.patch.object(smbfs.WindowsSMBFSConnector, '_get_disk_path')
    @mock.patch.object(smbfs.WindowsSMBFSConnector, 'ensure_share_mounted')
    def test_connect_volume(self, mock_ensure_mounted,
                            mock_get_disk_path):
        device_info = self._connector.connect_volume(mock.sentinel.conn_props)
        expected_info = dict(type='file',
                             path=mock_get_disk_path.return_value)

        self.assertEqual(expected_info, device_info)
        mock_ensure_mounted.assert_called_once_with(mock.sentinel.conn_props)
        mock_get_disk_path.assert_called_once_with(mock.sentinel.conn_props)

    @ddt.data(True, False)
    @mock.patch.object(smbfs.WindowsSMBFSConnector, '_get_disk_path')
    @mock.patch.object(smbfs.WindowsSMBFSConnector, 'ensure_share_mounted')
    def test_connect_and_mount_volume(self, read_only,
                                      mock_ensure_mounted,
                                      mock_get_disk_path):
        self._load_connector(expect_raw_disk=True)

        fake_conn_props = dict(access_mode='ro' if read_only else 'rw')
        self._vhdutils.get_virtual_disk_physical_path.return_value = (
            mock.sentinel.raw_disk_path)
        mock_get_disk_path.return_value = mock.sentinel.image_path

        device_info = self._connector.connect_volume(fake_conn_props)

        expected_info = dict(type='file',
                             path=mock.sentinel.raw_disk_path)

        self.assertEqual(expected_info, device_info)
        self._vhdutils.attach_virtual_disk.assert_called_once_with(
            mock.sentinel.image_path,
            read_only=read_only)
        self._vhdutils.get_virtual_disk_physical_path.assert_called_once_with(
            mock.sentinel.image_path)
        get_dev_num = self._diskutils.get_device_number_from_device_name
        get_dev_num.assert_called_once_with(mock.sentinel.raw_disk_path)
        self._diskutils.set_disk_offline.assert_called_once_with(
            get_dev_num.return_value)

    @mock.patch.object(smbfs.WindowsSMBFSConnector, '_get_disk_path')
    @mock.patch.object(smbfs.WindowsSMBFSConnector, '_get_export_path')
    def test_disconnect_volume(self, mock_get_export_path,
                               mock_get_disk_path):
        self._connector.disconnect_volume(mock.sentinel.conn_props,
                                          mock.sentinel.dev_info)

        mock_get_disk_path.assert_called_once_with(
            mock.sentinel.conn_props)
        self._vhdutils.detach_virtual_disk.assert_called_once_with(
            mock_get_disk_path.return_value)
        self._remotefs.unmount.assert_called_once_with(
            mock_get_export_path.return_value)
        mock_get_export_path.assert_called_once_with(mock.sentinel.conn_props)

    def test_get_export_path(self):
        fake_export = '//ip/share'
        fake_conn_props = dict(export=fake_export)

        expected_export = fake_export.replace('/', '\\')
        export_path = self._connector._get_export_path(fake_conn_props)
        self.assertEqual(expected_export, export_path)

    @ddt.data({},
              {'mount_base': mock.sentinel.mount_base},
              {'is_local_share': True},
              {'is_local_share': True,
               'local_path_for_loopbk': True})
    @ddt.unpack
    def test_get_disk_path(self, mount_base=None,
                           local_path_for_loopbk=False,
                           is_local_share=False):
        fake_mount_point = r'C:\\fake_mount_point'
        fake_share_name = 'fake_share'
        fake_local_share_path = 'C:\\%s' % fake_share_name
        fake_export_path = '\\\\host\\%s' % fake_share_name
        fake_disk_name = 'fake_disk.vhdx'
        fake_conn_props = dict(name=fake_disk_name,
                               export=fake_export_path)

        self._remotefs.get_mount_base.return_value = mount_base
        self._remotefs.get_mount_point.return_value = fake_mount_point
        self._remotefs.get_local_share_path.return_value = (
            fake_local_share_path)
        self._remotefs.get_share_name.return_value = fake_share_name
        self._connector._local_path_for_loopback = local_path_for_loopbk
        self._connector._smbutils.is_local_share.return_value = is_local_share

        expecting_local = local_path_for_loopbk and is_local_share

        if mount_base:
            expected_export_path = fake_mount_point
        elif expecting_local:
            # In this case, we expect the local share export path to be
            # used directly.
            expected_export_path = fake_local_share_path
        else:
            expected_export_path = fake_export_path
        expected_disk_path = os.path.join(expected_export_path,
                                          fake_disk_name)

        disk_path = self._connector._get_disk_path(fake_conn_props)
        self.assertEqual(expected_disk_path, disk_path)

        if mount_base:
            self._remotefs.get_mount_point.assert_called_once_with(
                fake_export_path)
        elif expecting_local:
            self._connector._smbutils.is_local_share.assert_called_once_with(
                fake_export_path)
            self._remotefs.get_local_share_path.assert_called_once_with(
                fake_export_path)

    def test_get_search_path(self):
        search_path = self._connector.get_search_path()
        self.assertEqual(search_path,
                         self._remotefs.get_mount_base.return_value)

    @mock.patch.object(smbfs.WindowsSMBFSConnector, '_get_disk_path')
    def test_volume_paths(self, mock_get_disk_path):
        expected_paths = [mock_get_disk_path.return_value]
        volume_paths = self._connector.get_volume_paths(
            mock.sentinel.conn_props)

        self.assertEqual(expected_paths, volume_paths)
        mock_get_disk_path.assert_called_once_with(
            mock.sentinel.conn_props)

    @mock.patch.object(smbfs.WindowsSMBFSConnector, '_get_export_path')
    def test_ensure_share_mounted(self, mock_get_export_path):
        fake_conn_props = dict(options=mock.sentinel.mount_opts)

        self._connector.ensure_share_mounted(fake_conn_props)
        self._remotefs.mount.assert_called_once_with(
            mock_get_export_path.return_value,
            mock.sentinel.mount_opts)
