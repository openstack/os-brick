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

from oslo_log import log as logging

from os_win import utilsfactory

from os_brick import exception
from os_brick.i18n import _, _LI
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
                                                   False)

        if mount_type not in mount_type_to_option_prefix:
            raise exception.ProtocolNotSupported(protocol=mount_type)

        self._mount_type = mount_type
        option_prefix = mount_type_to_option_prefix[mount_type]

        self._mount_base = kwargs.get(option_prefix + '_mount_point_base')
        self._mount_options = kwargs.get(option_prefix + '_mount_options')

        self._smbutils = utilsfactory.get_smbutils()
        self._pathutils = utilsfactory.get_pathutils()

    def get_local_share_path(self, share, expect_existing=True):
        local_share_path = self._smbutils.get_smb_share_path(share)
        if not local_share_path and expect_existing:
            err_msg = _("Could not find the local "
                        "share path for %(share)s.")
            raise exception.VolumePathsNotFound(err_msg % dict(share=share))

        return local_share_path

    def get_share_name(self, share):
        return share.replace('/', '\\').lstrip('\\').split('\\', 1)[1]

    def mount(self, share, flags=None):
        share = share.replace('/', '\\')
        use_local_path = (self._local_path_for_loopback and
                          self._smbutils.is_local_share(share))

        if use_local_path:
            LOG.info(_LI("Skipping mounting local share %(share_path)s."),
                     dict(share_path=share))
        else:
            mount_options = " ".join(
                [self._mount_options or '', flags or ''])
            username, password = self._parse_credentials(mount_options)

            if not self._smbutils.check_smb_mapping(
                    share):
                self._smbutils.mount_smb_share(share,
                                               username=username,
                                               password=password)

        if self._mount_base:
            share_name = self.get_share_name(share)
            symlink_dest = (share if not use_local_path
                            else self.get_local_share_path(share_name))
            self._create_mount_point(symlink_dest)

    def unmount(self, share):
        self._smbutils.unmount_smb_share(share.replace('/', '\\'))

    def _create_mount_point(self, share):
        mnt_point = self.get_mount_point(share)

        if not os.path.isdir(self._mount_base):
            os.makedirs(self._mount_base)

        if os.path.exists(mnt_point):
            if not self._pathutils.is_symlink(mnt_point):
                raise exception.BrickException(_("Link path already exists "
                                                 "and it's not a symlink"))
        else:
            self._pathutils.create_sym_link(mnt_point, share)

    def _parse_credentials(self, opts_str):
        if not opts_str:
            return None, None

        match = self._username_regex.findall(opts_str)
        username = match[0] if match and match[0] != 'guest' else None

        match = self._password_regex.findall(opts_str)
        password = match[0] if match else None

        return username, password
