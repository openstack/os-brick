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
import tempfile

from oslo_concurrency import processutils as putils

from os_brick.initiator.connectors import base
from os_brick import utils


class DRBDConnector(base.BaseLinuxConnector):
    """"Connector class to attach/detach DRBD resources."""

    def __init__(self, root_helper, driver=None,
                 execute=putils.execute, *args, **kwargs):

        super(DRBDConnector, self).__init__(root_helper, driver=driver,
                                            execute=execute, *args, **kwargs)

        self._execute = execute
        self._root_helper = root_helper

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The DRBD connector properties."""
        return {}

    def check_valid_device(self, path, run_as_root=True):
        """Verify an existing volume."""
        # TODO(linbit): check via drbdsetup first, to avoid blocking/hanging
        # in case of network problems?

        return super(DRBDConnector, self).check_valid_device(path, run_as_root)

    def get_all_available_volumes(self, connection_properties=None):

        base = "/dev/"
        blkdev_list = []

        for e in os.listdir(base):
            path = base + e
            if os.path.isblk(path):
                blkdev_list.append(path)

        return blkdev_list

    def _drbdadm_command(self, cmd, data_dict, sh_secret):
        # TODO(linbit): Write that resource file to a permanent location?
        tmp = tempfile.NamedTemporaryFile(suffix="res", delete=False, mode="w")
        try:
            kv = {'shared-secret': sh_secret}
            tmp.write(data_dict['config'] % kv)
            tmp.close()

            (out, err) = self._execute('drbdadm', cmd,
                                       "-c", tmp.name,
                                       data_dict['name'],
                                       run_as_root=True,
                                       root_helper=self._root_helper)
        finally:
            os.unlink(tmp.name)

        return (out, err)

    @utils.trace
    def connect_volume(self, connection_properties):
        """Attach the volume."""

        self._drbdadm_command("adjust", connection_properties,
                              connection_properties['provider_auth'])

        device_info = {
            'type': 'block',
            'path': connection_properties['device'],
        }

        return device_info

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Detach the volume."""

        self._drbdadm_command("down", connection_properties,
                              connection_properties['provider_auth'])

    def get_volume_paths(self, connection_properties):
        path = connection_properties['device']
        return [path]

    def get_search_path(self):
        # TODO(linbit): is it allowed to return "/dev", or is that too broad?
        return None

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError
