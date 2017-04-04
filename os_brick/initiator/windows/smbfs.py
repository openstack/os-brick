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

from os_win import utilsfactory

from os_brick.initiator.windows import base as win_conn_base
from os_brick.remotefs import windows_remotefs as remotefs
from os_brick import utils


class WindowsSMBFSConnector(win_conn_base.BaseWindowsConnector):
    def __init__(self, *args, **kwargs):
        super(WindowsSMBFSConnector, self).__init__(*args, **kwargs)
        # If this flag is set, we use the local paths in case of local
        # shares. This is in fact mandatory in some cases, for example
        # for the Hyper-C scenario.
        self._local_path_for_loopback = kwargs.get('local_path_for_loopback',
                                                   False)
        self._remotefsclient = remotefs.WindowsRemoteFsClient(
            mount_type='smbfs',
            *args, **kwargs)
        self._smbutils = utilsfactory.get_smbutils()

    @staticmethod
    def get_connector_properties(*args, **kwargs):
        # No connector properties updates in this case.
        return {}

    @utils.trace
    def connect_volume(self, connection_properties):
        self.ensure_share_mounted(connection_properties)
        disk_path = self._get_disk_path(connection_properties)
        device_info = {'type': 'file',
                       'path': disk_path}
        return device_info

    @utils.trace
    def disconnect_volume(self, connection_properties,
                          force=False, ignore_errors=False):
        export_path = self._get_export_path(connection_properties)
        self._remotefsclient.unmount(export_path)

    def _get_export_path(self, connection_properties):
        return connection_properties['export'].replace('/', '\\')

    def _get_disk_path(self, connection_properties):
        # This is expected to be the share address, as an UNC path.
        export_path = self._get_export_path(connection_properties)
        mount_base = self._remotefsclient.get_mount_base()
        use_local_path = (self._local_path_for_loopback and
                          self._smbutils.is_local_share(export_path))

        disk_dir = export_path
        if mount_base:
            # This will be a symlink pointing to either the share
            # path directly or to the local share path, if requested
            # and available.
            disk_dir = self._remotefsclient.get_mount_point(
                export_path)
        elif use_local_path:
            share_name = self._remotefsclient.get_share_name(export_path)
            disk_dir = self._remotefsclient.get_local_share_path(share_name)

        disk_name = connection_properties['name']
        disk_path = os.path.join(disk_dir, disk_name)
        return disk_path

    def get_search_path(self):
        return self._remotefsclient.get_mount_base()

    @utils.trace
    def get_volume_paths(self, connection_properties):
        return [self._get_disk_path(connection_properties)]

    def ensure_share_mounted(self, connection_properties):
        export_path = self._get_export_path(connection_properties)
        mount_options = connection_properties.get('options')
        self._remotefsclient.mount(export_path, mount_options)

    def extend_volume(self, connection_properties):
        raise NotImplementedError
