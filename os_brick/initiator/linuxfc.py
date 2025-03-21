# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

"""Generic linux Fibre Channel utilities."""

from __future__ import annotations

import glob
import os
from typing import Iterable

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick.initiator import linuxscsi

LOG = logging.getLogger(__name__)


class LinuxFibreChannel(linuxscsi.LinuxSCSI):
    FC_HOST_SYSFS_PATH = '/sys/class/fc_host'
    # Only load the sysfs attributes we care about
    HBA_ATTRIBUTES = ('port_name', 'node_name', 'port_state')

    def _get_target_fc_transport_path(self, path, wwpn, lun):
        """Scan target in the fc_transport path

        Scan for target in the following path:
        * /sys/class/fc_transport/target<host>*

        :returns: List with [c, t, l] if the target path exists else
        empty list
        """
        try:
            cmd = 'grep -Gil "%(wwpns)s" %(path)s*/port_name' % {'wwpns': wwpn,
                                                                 'path': path}
            # We need to run command in shell to expand the * glob
            out, _err = self._execute(cmd, shell=True)  # nosec: B604
            # The grep command will only return 1 path (if found)
            # associated with the target wwpn used for the search
            # in the current HBA host
            out_path = out.split('\n')[0]
            if out_path.startswith(path):
                return out_path.split('/')[4].split(':')[1:] + [lun]
        except Exception as exc:
            LOG.debug('Could not get HBA channel and SCSI target ID, path:'
                      ' %(path)s*, reason: %(reason)s', {'path': path,
                                                         'reason': exc})

        return []

    def _get_target_fc_remote_ports_path(self, path, wwpn, lun):
        """Scan target in the fc_remote_ports path

        Scan for target in the following path:
        * /sys/class/fc_remote_ports/rport-<host>*

        If the path exist, we fetch the target value from the
        scsi_target_id file.
        Example: /sys/class/fc_remote_ports/rport-6:0-1/scsi_target_id

        :returns: List with [c, t, l] if the target path exists else
        empty list
        """
        try:
            cmd = 'grep -Gil "%(wwpns)s" %(path)s*/port_name' % {'wwpns': wwpn,
                                                                 'path': path}
            # We need to run command in shell to expand the * glob
            out, _err = self._execute(cmd, shell=True)  # nosec: B604
            # The scsi_target_id file contains the target ID.
            # Example path:
            # /sys/class/fc_remote_ports/rport-2:0-0/scsi_target_id
            target_path = os.path.dirname(out) + '/scsi_target_id'
            # There could be a case where the out variable has empty string
            # and we end up with a path '/scsi_target_id' so check if it
            # starts with the correct path
            if target_path.startswith(path):
                try:
                    scsi_target = '-1'
                    with open(target_path) as scsi_target_file:
                        lines = scsi_target_file.read()
                        scsi_target = lines.split('\n')[0]
                except OSError:
                    # We were not able to read from the scsi_target_id
                    # file but we can still discover other targets so
                    # continue
                    pass
                # If the target value is -1, it is not a real target so
                # skip it
                if scsi_target != '-1':
                    channel = target_path.split(':')[1].split('-')[0]
                    return [channel, scsi_target, lun]
        except Exception as exc:
            LOG.debug('Could not get HBA channel and SCSI target ID, path:'
                      ' %(path)s*, reason: %(reason)s', {'path': path,
                                                         'reason': exc})

        return []

    def _get_hba_channel_scsi_target_lun(self,
                                         hba,
                                         conn_props):
        """Get HBA channels, SCSI targets, LUNs to FC targets for given HBA.

        Given an HBA and the connection properties we look for the HBA channels
        and SCSI targets for each of the FC targets that this HBA has been
        granted permission to connect.

        For drivers that don't return an initiator to target map we try to find
        the info for all the target ports.

        For drivers that return an initiator_target_map we use the
        initiator_target_lun_map entry that was generated by the FC connector
        based on the contents of the connection information data to know which
        target ports to look for.

        We scan for targets in the following two paths:
        * /sys/class/fc_transport/target<host>*
        * /sys/class/fc_remote_ports/rport-<host>*

        We search for targets in the fc_transport path first and if not
        found, we search in the fc_remote_ports path

        :returns: 2-Tuple with the first entry being a list of [c, t, l]
        entries where the target port was found, and the second entry of the
        tuple being a set of luns for ports that were not found.
        """
        # We want the targets' WWPNs, so we use the initiator_target_map if
        # present for this hba or default to targets if not present.
        targets = conn_props['targets']
        if conn_props.get('initiator_target_map') is not None:
            # This map we try to use was generated by the FC connector
            targets = conn_props['initiator_target_lun_map'].get(
                hba['port_name'], targets)

        # Leave only the number from the host_device field (ie: host6)
        host_device = hba['host_device']
        if host_device and len(host_device) > 4:
            host_device = host_device[4:]

        path = '/sys/class/fc_transport/target%s:' % host_device
        rpath = '/sys/class/fc_remote_ports/rport-%s:' % host_device

        ctls = []
        luns_not_found = set()
        for wwpn, lun in targets:
            # Search for target in the fc_transport path first and if we
            # don't find ctl, search for target in the fc_remote_ports path
            ctl = (self._get_target_fc_transport_path(path, wwpn, lun) or
                   self._get_target_fc_remote_ports_path(rpath, wwpn, lun))

            if ctl:
                ctls.append(ctl)
            else:
                # If we didn't find any paths add it to the not found list
                luns_not_found.add(lun)

        return ctls, luns_not_found

    def rescan_hosts(self,
                     hbas: Iterable,
                     connection_properties: dict) -> None:
        LOG.debug('Rescanning HBAs %(hbas)s with connection properties '
                  '%(conn_props)s', {'hbas': hbas,
                                     'conn_props': connection_properties})
        # Use initiator_target_lun_map (generated from initiator_target_map by
        # the FC connector) as HBA exclusion map
        ports = connection_properties.get('initiator_target_lun_map')
        if ports:
            hbas = [hba for hba in hbas if hba['port_name'] in ports]
            LOG.debug('Using initiator target map to exclude HBAs: %s',
                      hbas)

        # Most storage arrays get their target ports automatically detected
        # by the Linux FC initiator and sysfs gets populated with that
        # information, but there are some that don't.  We'll do a narrow scan
        # using the channel, target, and LUN for the former and a wider scan
        # for the latter.  If all paths to a former type of array were down on
        # the system boot the array could look like it's of the latter type
        # and make us bring us unwanted volumes into the system by doing a
        # broad scan.  To prevent this from happening Cinder drivers can use
        # the "enable_wildcard_scan" key in the connection_info to let us know
        # they don't want us to do broad scans even in those cases.
        broad_scan = connection_properties.get('enable_wildcard_scan', True)
        if not broad_scan:
            LOG.debug('Connection info disallows broad SCSI scanning')

        process = []
        skipped = []
        get_ctls = self._get_hba_channel_scsi_target_lun
        for hba in hbas:
            ctls, luns_wildcards = get_ctls(hba, connection_properties)
            # If we found the target ports, ignore HBAs that din't find them
            if ctls:
                process.append((hba, ctls))

            # If target ports not found and should have, then the HBA is not
            # connected to our storage
            elif not broad_scan:
                LOG.debug('Skipping HBA %s, nothing to scan, target port '
                          'not connected to initiator', hba['node_name'])

            # If we haven't found any target ports we may need to do broad
            # SCSI scans
            elif not process:
                skipped.append((hba,
                                [('-', '-', lun) for lun in luns_wildcards]))

        # If we didn't find any target ports use wildcards if they are enabled
        process = process or skipped

        addressing_mode = connection_properties.get('addressing_mode')

        for hba, ctls in process:
            for hba_channel, target_id, target_lun in ctls:
                target_lun = self.lun_for_addressing(target_lun,
                                                     addressing_mode)
                LOG.debug('Scanning %(host)s (wwnn: %(wwnn)s, c: '
                          '%(channel)s, t: %(target)s, l: %(lun)s)',
                          {'host': hba['host_device'],
                           'wwnn': hba['node_name'], 'channel': hba_channel,
                           'target': target_id, 'lun': target_lun})
                self.echo_scsi_command(
                    "/sys/class/scsi_host/%s/scan" % hba['host_device'],
                    "%(c)s %(t)s %(l)s" % {'c': hba_channel,
                                           't': target_id,
                                           'l': target_lun})

    @classmethod
    def get_fc_hbas(cls) -> list[dict[str, str]]:
        """Get the Fibre Channel HBA information from sysfs."""
        hbas = []
        for hostpath in glob.glob(f'{cls.FC_HOST_SYSFS_PATH}/*'):
            try:
                hba = {'ClassDevice': os.path.basename(hostpath),
                       'ClassDevicepath': os.path.realpath(hostpath)}
                for attribute in cls.HBA_ATTRIBUTES:
                    with open(os.path.join(hostpath, attribute), 'rt') as f:
                        hba[attribute] = f.read().strip()
                hbas.append(hba)
            except Exception as exc:
                LOG.warning('Could not read attributes for %(hp)s: %(exc)s',
                            {'hp': hostpath, 'exc': exc})
        return hbas

    def get_fc_hbas_info(self) -> list[dict[str, str]]:
        """Get Fibre Channel WWNs and device paths from the system, if any."""
        hbas = self.get_fc_hbas()

        hbas_info = []
        for hba in hbas:
            wwpn = hba['port_name'].replace('0x', '')
            wwnn = hba['node_name'].replace('0x', '')
            device_path = hba['ClassDevicepath']
            device = hba['ClassDevice']
            hbas_info.append({'port_name': wwpn,
                              'node_name': wwnn,
                              'host_device': device,
                              'device_path': device_path})
        return hbas_info

    def get_fc_wwpns(self) -> list[str]:
        """Get Fibre Channel WWPNs from the system, if any."""
        hbas = self.get_fc_hbas()

        wwpns = []
        for hba in hbas:
            if hba['port_state'] == 'Online':
                wwpn = hba['port_name'].replace('0x', '')
                wwpns.append(wwpn)

        return wwpns

    def get_fc_wwnns(self) -> list[str]:
        """Get Fibre Channel WWNNs from the system, if any."""
        hbas = self.get_fc_hbas()

        wwnns = []
        for hba in hbas:
            if hba['port_state'] == 'Online':
                wwnn = hba['node_name'].replace('0x', '')
                wwnns.append(wwnn)

        return wwnns


class LinuxFibreChannelS390X(LinuxFibreChannel):
    def get_fc_hbas_info(self):
        """Get Fibre Channel WWNs and device paths from the system, if any."""

        hbas = self.get_fc_hbas()

        hbas_info = []
        for hba in hbas:
            if hba['port_state'] == 'Online':
                wwpn = hba['port_name'].replace('0x', '')
                wwnn = hba['node_name'].replace('0x', '')
                device_path = hba['ClassDevicepath']
                device = hba['ClassDevice']
                hbas_info.append({'port_name': wwpn,
                                  'node_name': wwnn,
                                  'host_device': device,
                                  'device_path': device_path})
        return hbas_info

    def configure_scsi_device(self, device_number, target_wwn, lun):
        """Write the LUN to the port's unit_add attribute.

        If auto-discovery of Fibre-Channel target ports is
        disabled on s390 platforms, ports need to be added to
        the configuration.
        If auto-discovery of LUNs is disabled on s390 platforms
        luns need to be added to the configuration through the
        unit_add interface
        """
        LOG.debug("Configure lun for s390: device_number=%(device_num)s "
                  "target_wwn=%(target_wwn)s target_lun=%(target_lun)s",
                  {'device_num': device_number,
                   'target_wwn': target_wwn,
                   'target_lun': lun})
        filepath = ("/sys/bus/ccw/drivers/zfcp/%s/%s" %
                    (device_number, target_wwn))
        if not (os.path.exists(filepath)):
            zfcp_device_command = ("/sys/bus/ccw/drivers/zfcp/%s/port_rescan" %
                                   (device_number))
            LOG.debug("port_rescan call for s390: %s", zfcp_device_command)
            try:
                self.echo_scsi_command(zfcp_device_command, "1")
            except putils.ProcessExecutionError as exc:
                LOG.warning("port_rescan call for s390 failed exit"
                            " %(code)s, stderr %(stderr)s",
                            {'code': exc.exit_code, 'stderr': exc.stderr})

        zfcp_device_command = ("/sys/bus/ccw/drivers/zfcp/%s/%s/unit_add" %
                               (device_number, target_wwn))
        LOG.debug("unit_add call for s390 execute: %s", zfcp_device_command)
        try:
            self.echo_scsi_command(zfcp_device_command, lun)
        except putils.ProcessExecutionError as exc:
            LOG.warning("unit_add call for s390 failed exit %(code)s, "
                        "stderr %(stderr)s",
                        {'code': exc.exit_code, 'stderr': exc.stderr})

    def deconfigure_scsi_device(self, device_number, target_wwn, lun):
        """Write the LUN to the port's unit_remove attribute.

        If auto-discovery of LUNs is disabled on s390 platforms
        luns need to be removed from the configuration through the
        unit_remove interface
        """
        LOG.debug("Deconfigure lun for s390: "
                  "device_number=%(device_num)s "
                  "target_wwn=%(target_wwn)s target_lun=%(target_lun)s",
                  {'device_num': device_number,
                   'target_wwn': target_wwn,
                   'target_lun': lun})
        zfcp_device_command = ("/sys/bus/ccw/drivers/zfcp/%s/%s/unit_remove" %
                               (device_number, target_wwn))
        LOG.debug("unit_remove call for s390 execute: %s", zfcp_device_command)
        try:
            self.echo_scsi_command(zfcp_device_command, lun)
        except putils.ProcessExecutionError as exc:
            LOG.warning("unit_remove call for s390 failed exit %(code)s, "
                        "stderr %(stderr)s",
                        {'code': exc.exit_code, 'stderr': exc.stderr})
