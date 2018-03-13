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
from os_brick.initiator.connectors import fibre_channel

LOG = logging.getLogger(__name__)


class FibreChannelConnectorPPC64(fibre_channel.FibreChannelConnector):
    """Connector class to attach/detach Fibre Channel volumes on PPC64 arch."""

    platform = initiator.PLATFORM_PPC64

    def __init__(self, root_helper, driver=None,
                 execute=None, use_multipath=False,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(FibreChannelConnectorPPC64, self).__init__(
            root_helper,
            driver=driver,
            execute=execute,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)
        self.use_multipath = use_multipath

    def set_execute(self, execute):
        super(FibreChannelConnectorPPC64, self).set_execute(execute)
        self._linuxscsi.set_execute(execute)
        self._linuxfc.set_execute(execute)

    def _get_host_devices(self, possible_devs, lun):
        host_devices = set()
        for pci_num, target_wwn in possible_devs:
            host_device = "/dev/disk/by-path/fc-%s-lun-%s" % (
                target_wwn,
                self._linuxscsi.process_lun_id(lun))
            host_devices.add(host_device)
        return list(host_devices)
