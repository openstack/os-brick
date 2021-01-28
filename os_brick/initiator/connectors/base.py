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


import glob
import os

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick import initiator
from os_brick.initiator import host_driver
from os_brick.initiator import initiator_connector
from os_brick.initiator import linuxscsi

LOG = logging.getLogger(__name__)


class BaseLinuxConnector(initiator_connector.InitiatorConnector):
    os_type = initiator.OS_TYPE_LINUX

    def __init__(self, root_helper: str, driver=None, execute=None,
                 *args, **kwargs):
        self._linuxscsi = linuxscsi.LinuxSCSI(root_helper, execute=execute)

        if not driver:
            driver = host_driver.HostDriver()
        self.set_driver(driver)

        super(BaseLinuxConnector, self).__init__(root_helper, execute=execute,
                                                 *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper: str, *args, **kwargs) -> dict:
        """The generic connector properties."""
        multipath = kwargs['multipath']
        enforce_multipath = kwargs['enforce_multipath']
        props = {}

        props['multipath'] = (multipath and
                              linuxscsi.LinuxSCSI.is_multipath_running(
                                  enforce_multipath, root_helper,
                                  execute=kwargs.get('execute')))

        return props

    def check_valid_device(self, path: str, run_as_root: bool = True) -> bool:
        cmd = ('dd', 'if=%(path)s' % {"path": path},
               'of=/dev/null', 'count=1')
        out, info = None, None
        try:
            out, info = self._execute(*cmd, run_as_root=run_as_root,
                                      root_helper=self._root_helper)
        except putils.ProcessExecutionError as e:
            LOG.error("Failed to access the device on the path "
                      "%(path)s: %(error)s.",
                      {"path": path, "error": e.stderr})
            return False
        # If the info is none, the path does not exist.
        if info is None:
            return False
        return True

    def get_all_available_volumes(self, connection_properties=None):
        volumes = []
        path = self.get_search_path()
        if path:
            # now find all entries in the search path
            if os.path.isdir(path):
                path_items = [path, '/*']
                file_filter = ''.join(path_items)
                volumes = glob.glob(file_filter)

        return volumes

    def _discover_mpath_device(self,
                               device_wwn: str,
                               connection_properties: dict,
                               device_name: str) -> tuple:
        """This method discovers a multipath device.

        Discover a multipath device based on a defined connection_property
        and a device_wwn and return the multipath_id and path of the multipath
        enabled device if there is one.
        """

        path = self._linuxscsi.find_multipath_device_path(device_wwn)
        device_path = None
        multipath_id = None

        if path is None:
            # find_multipath_device only accept realpath not symbolic path
            device_realpath = os.path.realpath(device_name)
            mpath_info = self._linuxscsi.find_multipath_device(
                device_realpath)
            if mpath_info:
                device_path = mpath_info['device']
                multipath_id = device_wwn
            else:
                # we didn't find a multipath device.
                # so we assume the kernel only sees 1 device
                device_path = device_name
                LOG.debug("Unable to find multipath device name for "
                          "volume. Using path %(device)s for volume.",
                          {'device': device_path})
        else:
            device_path = path
            multipath_id = device_wwn
        if connection_properties.get('access_mode', '') != 'ro':
            try:
                # Sometimes the multipath devices will show up as read only
                # initially and need additional time/rescans to get to RW.
                self._linuxscsi.wait_for_rw(device_wwn, device_path)
            except exception.BlockDeviceReadOnly:
                LOG.warning('Block device %s is still read-only. '
                            'Continuing anyway.', device_path)
        return device_path, multipath_id
