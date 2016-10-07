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
from os_brick.remotefs import windows_remotefs
from os_brick.tests import base


@ddt.ddt
class WindowsRemotefsClientTestCase(base.TestCase):
    _FAKE_SHARE_NAME = 'fake_share'
    _FAKE_SHARE_SERVER = 'fake_share_server'
    _FAKE_SHARE = '\\\\%s\\%s' % (_FAKE_SHARE_SERVER,
                                  _FAKE_SHARE_NAME)

    @mock.patch.object(windows_remotefs, 'utilsfactory')
    def setUp(self, mock_utilsfactory):
        super(WindowsRemotefsClientTestCase, self).setUp()

        self._remotefs = windows_remotefs.WindowsRemoteFsClient(
            mount_type='smbfs')
        self._remotefs._mount_base = mock.sentinel.mount_base

        self._smbutils = self._remotefs._smbutils
        self._pathutils = self._remotefs._pathutils

    @ddt.data({},
              {'expect_existing': False},
              {'local_path': mock.sentinel.local_path})
    @ddt.unpack
    def test_get_local_share_path(self, expect_existing=True,
                                  local_path=None):
        self._smbutils.get_smb_share_path.return_value = local_path
        if not local_path and expect_existing:
            self.assertRaises(
                exception.VolumePathsNotFound,
                self._remotefs.get_local_share_path,
                mock.sentinel.share_name,
                expect_existing=expect_existing)
        else:
            share_path = self._remotefs.get_local_share_path(
                mock.sentinel.share_name,
                expect_existing=expect_existing)
            self.assertEqual(local_path, share_path)

    def test_get_share_name(self):
        resulted_name = self._remotefs.get_share_name(self._FAKE_SHARE)
        self.assertEqual(self._FAKE_SHARE_NAME, resulted_name)

    @ddt.data(True, False)
    @mock.patch.object(windows_remotefs.WindowsRemoteFsClient,
                       '_create_mount_point')
    def test_mount(self, is_local_share,
                   mock_create_mount_point):
        flags = '-o pass=password'
        self._remotefs._mount_options = '-o user=username,randomopt'
        self._remotefs._local_path_for_loopback = True

        self._smbutils.check_smb_mapping.return_value = False
        self._smbutils.is_local_share.return_value = is_local_share

        self._remotefs.mount(self._FAKE_SHARE, flags)

        if is_local_share:
            self.assertFalse(self._smbutils.check_smb_mapping.called)
            self.assertFalse(self._smbutils.mount_smb_share.called)
        else:
            self._smbutils.check_smb_mapping.assert_called_once_with(
                self._FAKE_SHARE)
            self._smbutils.mount_smb_share.assert_called_once_with(
                self._FAKE_SHARE,
                username='username',
                password='password')

        mock_create_mount_point.assert_called_once_with(self._FAKE_SHARE,
                                                        is_local_share)

    def test_unmount(self):
        self._remotefs.unmount(self._FAKE_SHARE)
        self._smbutils.unmount_smb_share.assert_called_once_with(
            self._FAKE_SHARE)

    @ddt.data({'use_local_path': True},
              {'path_exists': True, 'is_symlink': True},
              {'path_exists': True})
    @mock.patch.object(windows_remotefs.WindowsRemoteFsClient,
                       'get_local_share_path')
    @mock.patch.object(windows_remotefs.WindowsRemoteFsClient,
                       'get_mount_point')
    @mock.patch.object(windows_remotefs, 'os')
    @ddt.unpack
    def test_create_mount_point(self, mock_os, mock_get_mount_point,
                                mock_get_local_share_path,
                                path_exists=False, is_symlink=False,
                                use_local_path=False):
        mock_os.path.exists.return_value = path_exists
        mock_os.isdir.return_value = False
        self._pathutils.is_symlink.return_value = is_symlink

        if path_exists and not is_symlink:
            self.assertRaises(exception.BrickException,
                              self._remotefs._create_mount_point,
                              self._FAKE_SHARE,
                              use_local_path)
        else:
            self._remotefs._create_mount_point(self._FAKE_SHARE,
                                               use_local_path)

        mock_get_mount_point.assert_called_once_with(self._FAKE_SHARE)
        mock_os.path.isdir.assert_called_once_with(mock.sentinel.mount_base)

        if use_local_path:
            mock_get_local_share_path.assert_called_once_with(
                self._FAKE_SHARE_NAME)
            expected_symlink_target = mock_get_local_share_path.return_value
        else:
            expected_symlink_target = self._FAKE_SHARE.replace('/', '\\')

        if path_exists:
            self._pathutils.is_symlink.assert_called_once_with(
                mock_get_mount_point.return_value)
        else:
            self._pathutils.create_sym_link.assert_called_once_with(
                mock_get_mount_point.return_value,
                expected_symlink_target)
