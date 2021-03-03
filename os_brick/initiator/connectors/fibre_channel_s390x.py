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
from os_brick.initiator import linuxfc

LOG = logging.getLogger(__name__)


class FibreChannelConnectorS390X(fibre_channel.FibreChannelConnector):
    """Connector class to attach/detach Fibre Channel volumes on S390X arch."""

    platform = initiator.PLATFORM_S390

    def __init__(self, root_helper, driver=None,
                 execute=None, use_multipath=False,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(FibreChannelConnectorS390X, self).__init__(
            root_helper,
            driver=driver,
            execute=execute,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)
        LOG.debug("Initializing Fibre Channel connector for S390")
        self._linuxfc = linuxfc.LinuxFibreChannelS390X(root_helper, execute)
        self.use_multipath = use_multipath

    def set_execute(self, execute):
        super(FibreChannelConnectorS390X, self).set_execute(execute)
        self._linuxscsi.set_execute(execute)
        self._linuxfc.set_execute(execute)

    def _get_host_devices(self, possible_devs):
        host_devices = []
        for pci_num, target_wwn, lun in possible_devs:
            host_device = self._get_device_file_path(
                pci_num,
                target_wwn,
                lun)
            # NOTE(arne_r)
            # LUN driver path is the same on all distros, so no need to have
            # multiple calls here
            self._linuxfc.configure_scsi_device(pci_num, target_wwn,
                                                self._get_lun_string(lun))
            host_devices.extend(host_device)
        return host_devices

    def _get_lun_string(self, lun):
        target_lun = 0
        if lun <= 0xffff:
            target_lun = "0x%04x000000000000" % lun
        elif lun <= 0xffffffff:
            target_lun = "0x%08x00000000" % lun
        return target_lun

    def _get_device_file_path(self, pci_num, target_wwn, lun):
        # NOTE(arne_r)
        # Need to add multiple possible ways to resolve device paths,
        # depending on OS. Since it gets passed to '_get_possible_volume_paths'
        # having a mismatch is not a problem
        host_device = [
            # RHEL based
            "/dev/disk/by-path/ccw-%s-zfcp-%s:%s" % (
                pci_num, target_wwn, self._get_lun_string(lun)),
            # Debian based (e.g. for storwize)
            "/dev/disk/by-path/ccw-%s-fc-%s-lun-%s" % (
                pci_num, target_wwn, lun),
            # Debian based (e.g. for ds8k)
            "/dev/disk/by-path/ccw-%s-fc-%s-lun-%s" % (
                pci_num, target_wwn, self._get_lun_string(lun)),
        ]
        return host_device

    def _remove_devices(self, connection_properties, devices, device_info):
        hbas = self._linuxfc.get_fc_hbas_info()
        targets = connection_properties['targets']
        possible_devs = self._get_possible_devices(hbas, targets)
        for platform, pci_num, target_wwn, lun in possible_devs:
            target_lun = self._get_lun_string(lun)
            self._linuxfc.deconfigure_scsi_device(pci_num,
                                                  target_wwn,
                                                  target_lun)
