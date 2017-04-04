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

from oslo_log import log as logging

from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick.remotefs import remotefs
from os_brick import utils

LOG = logging.getLogger(__name__)


class RemoteFsConnector(base.BaseLinuxConnector):
    """Connector class to attach/detach NFS and GlusterFS volumes."""

    def __init__(self, mount_type, root_helper, driver=None,
                 execute=None,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        kwargs = kwargs or {}
        conn = kwargs.get('conn')
        mount_type_lower = mount_type.lower()
        if conn:
            mount_point_base = conn.get('mount_point_base')
            if mount_type_lower in ('nfs', 'glusterfs', 'scality',
                                    'quobyte', 'vzstorage'):
                kwargs[mount_type_lower + '_mount_point_base'] = (
                    kwargs.get(mount_type_lower + '_mount_point_base') or
                    mount_point_base)
        else:
            LOG.warning("Connection details not present."
                        " RemoteFsClient may not initialize properly.")

        if mount_type_lower == 'scality':
            cls = remotefs.ScalityRemoteFsClient
        elif mount_type_lower == 'vzstorage':
            cls = remotefs.VZStorageRemoteFSClient
        else:
            cls = remotefs.RemoteFsClient
        self._remotefsclient = cls(mount_type, root_helper, execute=execute,
                                   *args, **kwargs)

        super(RemoteFsConnector, self).__init__(
            root_helper, driver=driver,
            execute=execute,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The RemoteFS connector properties."""
        return {}

    def set_execute(self, execute):
        super(RemoteFsConnector, self).set_execute(execute)
        self._remotefsclient.set_execute(execute)

    def get_search_path(self):
        return self._remotefsclient.get_mount_base()

    def _get_volume_path(self, connection_properties):
        mnt_flags = []
        if connection_properties.get('options'):
            mnt_flags = connection_properties['options'].split()

        nfs_share = connection_properties['export']
        self._remotefsclient.mount(nfs_share, mnt_flags)
        mount_point = self._remotefsclient.get_mount_point(nfs_share)
        path = mount_point + '/' + connection_properties['name']
        return path

    def get_volume_paths(self, connection_properties):
        path = self._get_volume_path(connection_properties)
        return [path]

    @utils.trace
    def connect_volume(self, connection_properties):
        """Ensure that the filesystem containing the volume is mounted.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
             connection_properties must include:
             export - remote filesystem device (e.g. '172.18.194.100:/var/nfs')
             name - file name within the filesystem
        :type connection_properties: dict
        :returns: dict


        connection_properties may optionally include:
        options - options to pass to mount
        """
        path = self._get_volume_path(connection_properties)
        return {'path': path}

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """No need to do anything to disconnect a volume in a filesystem.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError
