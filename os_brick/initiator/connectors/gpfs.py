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
from os_brick.initiator.connectors import local
from os_brick import utils


class GPFSConnector(local.LocalConnector):
    """"Connector class to attach/detach File System backed volumes."""

    @utils.trace
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
               connection_properties must include:
               device_path - path to the volume to be connected
        :type connection_properties: dict
        :returns: dict
        """
        if 'device_path' not in connection_properties:
            msg = (_("Invalid connection_properties specified "
                     "no device_path attribute."))
            raise ValueError(msg)

        device_info = {'type': 'gpfs',
                       'path': connection_properties['device_path']}
        return device_info
