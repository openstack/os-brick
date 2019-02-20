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

from os_win import exceptions as os_win_exc
from os_win import utilsfactory
from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator.windows import base as win_conn_base
from os_brick import utils

LOG = logging.getLogger(__name__)


class WindowsFCConnector(win_conn_base.BaseWindowsConnector):
    def __init__(self, *args, **kwargs):
        super(WindowsFCConnector, self).__init__(*args, **kwargs)

        self.use_multipath = kwargs.get('use_multipath', False)

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
        for attempt_num in range(self.device_scan_attempts):
            disk_paths = set()

            if attempt_num:
                time.sleep(self.device_scan_interval)

            self._diskutils.rescan_disks()

            volume_mappings = self._get_fc_volume_mappings(
                connection_properties)
            LOG.debug("Retrieved volume mappings %(vol_mappings)s "
                      "for volume %(conn_props)s",
                      dict(vol_mappings=volume_mappings,
                           conn_props=connection_properties))

            for mapping in volume_mappings:
                device_name = mapping['device_name']
                if device_name:
                    disk_paths.add(device_name)

            if not disk_paths and volume_mappings:
                fcp_lun = volume_mappings[0]['fcp_lun']

                try:
                    disk_paths = self._get_disk_paths_by_scsi_id(
                        connection_properties, fcp_lun)
                    disk_paths = set(disk_paths or [])
                except os_win_exc.OSWinException as ex:
                    LOG.debug("Failed to retrieve disk paths by SCSI ID. "
                              "Exception: %s", ex)

            if not disk_paths:
                LOG.debug("No disk path retrieved yet.")
                continue

            if len(disk_paths) > 1:
                LOG.debug("Multiple disk paths retrieved: %s This may happen "
                          "if MPIO did not claim them yet.", disk_paths)
                continue

            dev_num = self._diskutils.get_device_number_from_device_name(
                list(disk_paths)[0])
            if self.use_multipath and not self._diskutils.is_mpio_disk(
                    dev_num):
                LOG.debug("Multipath was requested but the disk %s was not "
                          "claimed yet by the MPIO service.", dev_num)
                continue

            return list(disk_paths)
        return []

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
                if (mapping['port_name'] in target_wwpns and
                        mapping['lun'] == target_lun):
                    volume_mappings.append(mapping)

        return volume_mappings

    def _get_fc_hba_mappings(self):
        mappings = collections.defaultdict(list)
        fc_hba_ports = self._fc_utils.get_fc_hba_ports()
        for port in fc_hba_ports:
            mappings[port['node_name']].append(port['port_name'])
        return mappings

    def _get_disk_paths_by_scsi_id(self, connection_properties, fcp_lun):
        for local_port_wwn, remote_port_wwns in connection_properties[
                'initiator_target_map'].items():
            for remote_port_wwn in remote_port_wwns:
                try:
                    dev_nums = self._get_dev_nums_by_scsi_id(
                        local_port_wwn, remote_port_wwn, fcp_lun)

                    # This may raise a DiskNotFound exception if the disks
                    # are meanwhile claimed by the MPIO service.
                    disk_paths = [
                        self._diskutils.get_device_name_by_device_number(
                            dev_num)
                        for dev_num in dev_nums]
                    return disk_paths
                except os_win_exc.FCException as ex:
                    LOG.debug("Failed to retrieve volume paths by SCSI id. "
                              "Exception: %s", ex)
                    continue
        return []

    def _get_dev_nums_by_scsi_id(self, local_port_wwn, remote_port_wwn,
                                 fcp_lun):
        LOG.debug("Fetching SCSI Unique ID for FCP lun %(fcp_lun)s. "
                  "Port WWN: %(local_port_wwn)s. "
                  "Remote port WWN: %(remote_port_wwn)s.",
                  dict(fcp_lun=fcp_lun,
                       local_port_wwn=local_port_wwn,
                       remote_port_wwn=remote_port_wwn))

        local_hba_wwn = self._get_fc_hba_wwn_for_port(local_port_wwn)
        # This will return the SCSI identifiers in the order of precedence
        # used by Windows.
        identifiers = self._fc_utils.get_scsi_device_identifiers(
            local_hba_wwn, local_port_wwn,
            remote_port_wwn, fcp_lun)

        if identifiers:
            identifier = identifiers[0]
            dev_nums = self._diskutils.get_disk_numbers_by_unique_id(
                unique_id=identifier['id'],
                unique_id_format=identifier['type'])
            return dev_nums
        return []

    def _get_fc_hba_wwn_for_port(self, port_wwn):
        fc_hba_ports = self._fc_utils.get_fc_hba_ports()
        for port in fc_hba_ports:
            if port_wwn.upper() == port['port_name']:
                return port['node_name']

        err_msg = _("Could not find any FC HBA port "
                    "having WWN '%s'.") % port_wwn
        raise exception.NotFound(err_msg)

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info=None,
                          force=False, ignore_errors=False):
        pass
