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

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick.initiator import linuxsheepdog
from os_brick import utils

DEVICE_SCAN_ATTEMPTS_DEFAULT = 3
LOG = logging.getLogger(__name__)


class SheepdogConnector(base.BaseLinuxConnector):
    """"Connector class to attach/detach sheepdog volumes."""

    def __init__(self, root_helper, driver=None, use_multipath=False,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):

        super(SheepdogConnector, self).__init__(root_helper, driver=driver,
                                                device_scan_attempts=
                                                device_scan_attempts,
                                                *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The Sheepdog connector properties."""
        return {}

    def get_volume_paths(self, connection_properties):
        # TODO(lixiaoy1): don't know where the connector
        # looks for sheepdog volumes.
        return []

    def get_search_path(self):
        # TODO(lixiaoy1): don't know where the connector
        # looks for sheepdog volumes.
        return None

    def get_all_available_volumes(self, connection_properties=None):
        # TODO(lixiaoy1): not sure what to return here for sheepdog
        return []

    def _get_sheepdog_handle(self, connection_properties):
        try:
            host = connection_properties['hosts'][0]
            name = connection_properties['name']
            port = connection_properties['ports'][0]
        except IndexError:
            msg = _("Connect volume failed, malformed connection properties")
            raise exception.BrickException(msg=msg)

        sheepdog_handle = linuxsheepdog.SheepdogVolumeIOWrapper(
            host, port, name)
        return sheepdog_handle

    @utils.trace
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """

        sheepdog_handle = self._get_sheepdog_handle(connection_properties)
        return {'path': sheepdog_handle}

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Disconnect a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        if device_info:
            sheepdog_handle = device_info.get('path', None)
            self.check_IO_handle_valid(sheepdog_handle,
                                       linuxsheepdog.SheepdogVolumeIOWrapper,
                                       'Sheepdog')
            if sheepdog_handle is not None:
                sheepdog_handle.close()

    def check_valid_device(self, path, run_as_root=True):
        """Verify an existing sheepdog handle is connected and valid."""
        sheepdog_handle = path

        if sheepdog_handle is None:
            return False

        original_offset = sheepdog_handle.tell()

        try:
            sheepdog_handle.read(4096)
        except Exception as e:
            LOG.error("Failed to access sheepdog device "
                      "handle: %(error)s",
                      {"error": e})
            return False
        finally:
            sheepdog_handle.seek(original_offset, 0)

        return True

    def extend_volume(self, connection_properties):
        # TODO(lixiaoy1): is this possible?
        raise NotImplementedError
