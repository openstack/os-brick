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

import collections
import time

from os_win import utilsfactory
from oslo_log import log as logging

from os_brick import exception
from os_brick.initiator.windows import base as win_conn_base
from os_brick import utils

LOG = logging.getLogger(__name__)


class WindowsFCConnector(win_conn_base.BaseWindowsConnector):
    def __init__(self, *args, **kwargs):
        super(WindowsFCConnector, self).__init__(*args, **kwargs)
        self._fc_utils = utilsfactory.get_fc_utils()

    @staticmethod
    def get_connector_properties(*args, **kwargs):
        props = {}

        fc_utils = utilsfactory.get_fc_utils()
        fc_utils.refresh_hba_configuration()
        fc_hba_ports = fc_utils.get_fc_hba_ports()

        if fc_hba_ports:
            wwnns = []
            wwpns = []
            for port in fc_hba_ports:
                wwnns.append(port['node_name'])
                wwpns.append(port['port_name'])
            props['wwpns'] = wwpns
            props['wwnns'] = list(set(wwnns))
        return props

    @utils.trace
    def connect_volume(self, connection_properties):
        volume_paths = self.get_volume_paths(connection_properties)
        if not volume_paths:
            raise exception.NoFibreChannelVolumeDeviceFound()

        device_path = volume_paths[0]
        device_number = self._diskutils.get_device_number_from_device_name(
            device_path)
        scsi_wwn = self._get_scsi_wwn(device_number)
        device_info = {'type': 'block',
                       'path': device_path,
                       'number': device_number,
                       'scsi_wwn': scsi_wwn}
        return device_info

    @utils.trace
    def get_volume_paths(self, connection_properties):
        # Returns a list containing at most one disk path such as
        # \\.\PhysicalDrive4.
        #
        # If multipath is used and the MPIO service is properly configured
        # to claim the disks, we'll still get a single device path, having
        # the same format, which will be used for all the IO operations.
        disk_paths = set()

        for attempt in range(self.device_scan_attempts):
            self._diskutils.rescan_disks()
            volume_mappings = self._get_fc_volume_mappings(
                connection_properties)
            LOG.debug("Retrieved volume mappings %(vol_mappings)s "
                      "for volume %(conn_props)s",
                      dict(vol_mappings=volume_mappings,
                           conn_props=connection_properties))

            # Because of MPIO, we may not be able to get the device name
            # from a specific mapping if the disk was accessed through
            # an other HBA at that moment. In that case, the device name
            # will show up as an empty string.
            for mapping in volume_mappings:
                device_name = mapping['device_name']
                if device_name:
                    disk_paths.add(device_name)

            if disk_paths:
                break

            time.sleep(self.device_scan_interval)

        self._check_device_paths(disk_paths)
        return list(disk_paths)

    def _get_fc_volume_mappings(self, connection_properties):
        # Note(lpetrut): All the WWNs returned by os-win are upper case.
        target_wwpns = [wwpn.upper()
                        for wwpn in connection_properties['target_wwn']]
        target_lun = connection_properties['target_lun']

        volume_mappings = []
        hba_mappings = self._get_fc_hba_mappings()
        for node_name in hba_mappings:
            target_mappings = self._fc_utils.get_fc_target_mappings(node_name)
            for mapping in target_mappings:
                if (mapping['port_name'] in target_wwpns
                        and mapping['lun'] == target_lun):
                    volume_mappings.append(mapping)

        return volume_mappings

    def _get_fc_hba_mappings(self):
        mappings = collections.defaultdict(list)
        fc_hba_ports = self._fc_utils.get_fc_hba_ports()
        for port in fc_hba_ports:
            mappings[port['node_name']].append(port['port_name'])
        return mappings

    @utils.trace
    def disconnect_volume(self, connection_properties,
                          force=False, ignore_errors=False):
        pass
