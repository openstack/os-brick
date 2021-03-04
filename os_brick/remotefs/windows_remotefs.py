# Copyright 2016 Cloudbase Solutions Srl
# All Rights Reserved
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

"""Windows remote filesystem client utilities."""

import os
import re

from os_win import utilsfactory
from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick.remotefs import remotefs

LOG = logging.getLogger(__name__)


class WindowsRemoteFsClient(remotefs.RemoteFsClient):
    _username_regex = re.compile(r'user(?:name)?=([^, ]+)')
    _password_regex = re.compile(r'pass(?:word)?=([^, ]+)')
    _loopback_share_map = {}

    def __init__(self, mount_type, root_helper=None,
                 execute=None, *args, **kwargs):
        mount_type_to_option_prefix = {
            'cifs': 'smbfs',
            'smbfs': 'smbfs',
        }

        self._local_path_for_loopback = kwargs.get('local_path_for_loopback',
                                                   True)

        if mount_type not in mount_type_to_option_prefix:
            raise exception.ProtocolNotSupported(protocol=mount_type)

        self._mount_type = mount_type
        option_prefix = mount_type_to_option_prefix[mount_type]

        self._mount_base = kwargs.get(option_prefix + '_mount_point_base')
        self._mount_options = kwargs.get(option_prefix + '_mount_options')

        self._smbutils = utilsfactory.get_smbutils()
        self._pathutils = utilsfactory.get_pathutils()

    def get_local_share_path(self, share, expect_existing=True):
        share = self._get_share_norm_path(share)
        share_name = self.get_share_name(share)
        share_subdir = self.get_share_subdir(share)
        is_local_share = self._smbutils.is_local_share(share)

        if not is_local_share:
            LOG.debug("Share '%s' is not exposed by the current host.", share)
            local_share_path = None
        else:
            local_share_path = self._smbutils.get_smb_share_path(share_name)

        if not local_share_path and expect_existing:
            err_msg = _("Could not find the local "
                        "share path for %(share)s.")
            raise exception.VolumePathsNotFound(err_msg % dict(share=share))

        if local_share_path and share_subdir:
            local_share_path = os.path.join(local_share_path, share_subdir)

        return local_share_path

    def _get_share_norm_path(self, share):
        return share.replace('/', '\\')

    def get_share_name(self, share):
        return self._get_share_norm_path(share).lstrip('\\').split('\\')[1]

    def get_share_subdir(self, share):
        return "\\".join(
            self._get_share_norm_path(share).lstrip('\\').split('\\')[2:])

    def mount(self, share, flags=None):
        share_norm_path = self._get_share_norm_path(share)
        use_local_path = (self._local_path_for_loopback and
                          self._smbutils.is_local_share(share_norm_path))

        if use_local_path:
            LOG.info("Skipping mounting local share %(share_path)s.",
                     dict(share_path=share_norm_path))
        else:
            mount_options = " ".join(
                [self._mount_options or '', flags or ''])
            username, password = self._parse_credentials(mount_options)

            if not self._smbutils.check_smb_mapping(
                    share_norm_path):
                self._smbutils.mount_smb_share(share_norm_path,
                                               username=username,
                                               password=password)

        if self._mount_base:
            self._create_mount_point(share, use_local_path)

    def unmount(self, share):
        self._smbutils.unmount_smb_share(self._get_share_norm_path(share))

    def _create_mount_point(self, share, use_local_path):
        # The mount point will contain a hash of the share so we're
        # intentionally preserving the original share path as this is
        # what the caller will expect.
        mnt_point = self.get_mount_point(share)
        share_norm_path = self._get_share_norm_path(share)
        symlink_dest = (share_norm_path if not use_local_path
                        else self.get_local_share_path(share))

        if not os.path.isdir(self._mount_base):
            os.makedirs(self._mount_base)

        if os.path.exists(mnt_point):
            if not self._pathutils.is_symlink(mnt_point):
                raise exception.BrickException(_("Link path already exists "
                                                 "and it's not a symlink"))
        else:
            self._pathutils.create_sym_link(mnt_point, symlink_dest)

    def _parse_credentials(self, opts_str):
        if not opts_str:
            return None, None

        match = self._username_regex.findall(opts_str)
        username = match[0] if match and match[0] != 'guest' else None

        match = self._password_regex.findall(opts_str)
        password = match[0] if match else None

        return username, password
