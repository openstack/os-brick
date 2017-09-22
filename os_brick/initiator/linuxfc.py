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

import errno
import os

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick.initiator import linuxscsi

LOG = logging.getLogger(__name__)


class LinuxFibreChannel(linuxscsi.LinuxSCSI):

    def has_fc_support(self):
        FC_HOST_SYSFS_PATH = '/sys/class/fc_host'
        if os.path.isdir(FC_HOST_SYSFS_PATH):
            return True
        else:
            return False

    def _get_hba_channel_scsi_target(self, hba):
        """Try to get the HBA channel and SCSI target for an HBA.

        This method only works for Fibre Channel targets that implement a
        single WWNN for all ports, so caller should expect us to return either
        None or an empty list.

        :returns: List or None
        """
        # Leave only the number from the host_device field (ie: host6)
        host_device = hba['host_device']
        if host_device and len(host_device) > 4:
            host_device = host_device[4:]

        path = '/sys/class/fc_transport/target%s:' % host_device
        cmd = 'grep %(wwnn)s %(path)s*/node_name' % {'wwnn': hba['node_name'],
                                                     'path': path}
        try:
            out, _err = self._execute(cmd)
            return [line.split('/')[4].split(':')[1:]
                    for line in out.split('\n') if line.startswith(path)]
        except Exception as exc:
            LOG.debug('Could not get HBA channel and SCSI target ID, path: '
                      '%(path)s, reason: %(reason)s', {'path': path,
                                                       'reason': exc})
            return None

    def rescan_hosts(self, hbas, target_lun):
        for hba in hbas:
            # Try to get HBA channel and SCSI target to use as filters
            cts = self._get_hba_channel_scsi_target(hba)
            # If we couldn't get the channel and target use wildcards
            if not cts:
                cts = [('-', '-')]
            for hba_channel, target_id in cts:
                LOG.debug('Scanning host %(host)s (wwnn: %(wwnn)s, c: '
                          '%(channel)s, t: %(target)s, l: %(lun)s)',
                          {'host': hba['host_device'],
                           'wwnn': hba['node_name'], 'channel': hba_channel,
                           'target': target_id, 'lun': target_lun})
                self.echo_scsi_command(
                    "/sys/class/scsi_host/%s/scan" % hba['host_device'],
                    "%(c)s %(t)s %(l)s" % {'c': hba_channel,
                                           't': target_id,
                                           'l': target_lun})

    def get_fc_hbas(self):
        """Get the Fibre Channel HBA information."""

        if not self.has_fc_support():
            # there is no FC support in the kernel loaded
            # so there is no need to even try to run systool
            LOG.debug("No Fibre Channel support detected on system.")
            return []

        out = None
        try:
            out, _err = self._execute('systool', '-c', 'fc_host', '-v',
                                      run_as_root=True,
                                      root_helper=self._root_helper)
        except putils.ProcessExecutionError as exc:
            # This handles the case where rootwrap is used
            # and systool is not installed
            # 96 = nova.cmd.rootwrap.RC_NOEXECFOUND:
            if exc.exit_code == 96:
                LOG.warning("systool is not installed")
            return []
        except OSError as exc:
            # This handles the case where rootwrap is NOT used
            # and systool is not installed
            if exc.errno == errno.ENOENT:
                LOG.warning("systool is not installed")
            return []

        # No FC HBAs were found
        if out is None:
            return []

        lines = out.split('\n')
        # ignore the first 2 lines
        lines = lines[2:]
        hbas = []
        hba = {}
        lastline = None
        for line in lines:
            line = line.strip()
            # 2 newlines denotes a new hba port
            if line == '' and lastline == '':
                if len(hba) > 0:
                    hbas.append(hba)
                    hba = {}
            else:
                val = line.split('=')
                if len(val) == 2:
                    key = val[0].strip().replace(" ", "")
                    value = val[1].strip()
                    hba[key] = value.replace('"', '')
            lastline = line

        return hbas

    def get_fc_hbas_info(self):
        """Get Fibre Channel WWNs and device paths from the system, if any."""

        # Note(walter-boring) modern Linux kernels contain the FC HBA's in /sys
        # and are obtainable via the systool app
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

    def get_fc_wwpns(self):
        """Get Fibre Channel WWPNs from the system, if any."""

        # Note(walter-boring) modern Linux kernels contain the FC HBA's in /sys
        # and are obtainable via the systool app
        hbas = self.get_fc_hbas()

        wwpns = []
        for hba in hbas:
            if hba['port_state'] == 'Online':
                wwpn = hba['port_name'].replace('0x', '')
                wwpns.append(wwpn)

        return wwpns

    def get_fc_wwnns(self):
        """Get Fibre Channel WWNNs from the system, if any."""

        # Note(walter-boring) modern Linux kernels contain the FC HBA's in /sys
        # and are obtainable via the systool app
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


class LinuxFibreChannelPPC64(LinuxFibreChannel):

    def _get_hba_channel_scsi_target(self, hba, wwpn):
        """Try to get the HBA channel and SCSI target for an HBA.

        This method works for Fibre Channel targets iterating over all the
        target wwpn port and finding the c, t, l. so caller should expect us to
        return either None or an empty list.
        """
        # Leave only the number from the host_device field (ie: host6)
        host_device = hba['host_device']
        if host_device and len(host_device) > 4:
            host_device = host_device[4:]
        path = '/sys/class/fc_transport/target%s:' % host_device
        cmd = 'grep -il %(wwpn)s %(path)s*/port_name' % {'wwpn': wwpn,
                                                         'path': path}
        try:
            out, _err = self._execute(cmd, shell=True)
            return [line.split('/')[4].split(':')[1:]
                    for line in out.split('\n') if line.startswith(path)]
        except Exception as exc:
            LOG.error("Could not get HBA channel and SCSI target ID, "
                      "reason: %s", exc)
            return None

    def rescan_hosts(self, hbas, target_lun):
        for hba in hbas:
            # Try to get HBA channel and SCSI target to use as filters
            # Ignore HBA which does not have target wwn
            if 'target_wwn' not in hba.keys():
                continue
            for wwpn in hba['target_wwn']:
                cts = self._get_hba_channel_scsi_target(hba, wwpn)
                # If we couldn't get the channel and target use wildcards
                if not cts:
                    cts = [('-', '-')]
                for hba_channel, target_id in cts:
                    LOG.debug('Scanning host %(host)s (wwpn: %(wwpn)s, c: '
                              '%(channel)s, t: %(target)s, l: %(lun)s)',
                              {'host': hba['host_device'],
                               'wwpn': hba['target_wwn'],
                               'channel': hba_channel,
                               'target': target_id,
                               'lun': target_lun})
                    self.echo_scsi_command(
                        "/sys/class/scsi_host/%s/scan" % hba['host_device'],
                        "%(c)s %(t)s %(l)s" % {'c': hba_channel,
                                               't': target_id,
                                               'l': target_lun})
