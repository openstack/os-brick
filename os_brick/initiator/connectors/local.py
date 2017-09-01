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

from os_brick.i18n import _
from os_brick.initiator.connectors import base
from os_brick import utils


class LocalConnector(base.BaseLinuxConnector):
    """"Connector class to attach/detach File System backed volumes."""

    def __init__(self, root_helper, driver=None,
                 *args, **kwargs):
        super(LocalConnector, self).__init__(root_helper, driver=driver,
                                             *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The Local connector properties."""
        return {}

    def get_volume_paths(self, connection_properties):
        path = connection_properties['device_path']
        return [path]

    def get_search_path(self):
        return None

    def get_all_available_volumes(self, connection_properties=None):
        # TODO(walter-boring): not sure what to return here.
        return []

    @utils.trace
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all of the
          target volume attributes. ``connection_properties`` must include:

          - ``device_path`` - path to the volume to be connected
        :type connection_properties: dict
        :returns: dict
        """
        if 'device_path' not in connection_properties:
            msg = (_("Invalid connection_properties specified "
                     "no device_path attribute"))
            raise ValueError(msg)

        device_info = {'type': 'local',
                       'path': connection_properties['device_path']}
        return device_info

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Disconnect a volume from the local host.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        pass

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError
