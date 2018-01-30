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

    def _get_hba_channel_scsi_target(self, hba, conn_props):
        """Try to get the HBA channel and SCSI target for an HBA.

        This method only works for Fibre Channel targets that implement a
        single WWNN for all ports, so caller should expect us to return either
        explicit channel and targets or wild cards if we cannot determine them.

        The connection properties will need to have "target" values defined in
        it which are expected to be tuples of (wwpn, lun).

        :returns: List of lists with [c, t, l] entries, the channel and target
        may be '-' wildcards if unable to determine them.
        """
        # We want the target's WWPNs, so we use the initiator_target_map if
        # present for this hba or default to target_wwns if not present.
        targets = conn_props['targets']
        if conn_props.get('initiator_target_map') is not None:
            targets = conn_props['initiator_target_lun_map'].get(
                hba['port_name'], targets)

        # Leave only the number from the host_device field (ie: host6)
        host_device = hba['host_device']
        if host_device and len(host_device) > 4:
            host_device = host_device[4:]

        path = '/sys/class/fc_transport/target%s:' % host_device
        ctls = []
        for wwpn, lun in targets:
            cmd = 'grep -Gil "%(wwpns)s" %(path)s*/port_name' % {'wwpns': wwpn,
                                                                 'path': path}
            try:
                # We need to run command in shell to expand the * glob
                out, _err = self._execute(cmd, shell=True)
                ctls += [line.split('/')[4].split(':')[1:] + [lun]
                         for line in out.split('\n') if line.startswith(path)]
            except Exception as exc:
                LOG.debug('Could not get HBA channel and SCSI target ID, path:'
                          ' %(path)s*, reason: %(reason)s', {'path': path,
                                                             'reason': exc})
                # If we didn't find any paths just give back wildcards for
                # the channel and target ids.
                ctls.append(['-', '-', lun])
        return ctls

    def rescan_hosts(self, hbas, connection_properties):
        LOG.debug('Rescaning HBAs %(hbas)s with connection properties '
                  '%(conn_props)s', {'hbas': hbas,
                                     'conn_props': connection_properties})
        get_ctsl = self._get_hba_channel_scsi_target

        # Use initiator_target_map provided by backend as HBA exclusion map
        ports = connection_properties.get('initiator_target_lun_map')
        if ports:
            hbas = [hba for hba in hbas if hba['port_name'] in ports]
            LOG.debug('Using initiator target map to exclude HBAs')
            process = [(hba, get_ctsl(hba, connection_properties))
                       for hba in hbas]

        # With no target map we'll check if target implements single WWNN for
        # all ports, if it does we only use HBAs connected (info was found),
        # otherwise we are forced to blindly scan all HBAs.
        else:
            with_info = []
            no_info = []

            for hba in hbas:
                ctls = get_ctsl(hba, connection_properties)
                found_info = True
                for hba_channel, target_id, target_lun in ctls:
                    if hba_channel == '-' or target_id == '-':
                        found_info = False
                target_list = with_info if found_info else no_info
                target_list.append((hba, ctls))

            process = with_info or no_info
            msg = "implements" if with_info else "doesn't implement"
            LOG.debug('FC target %s single WWNN for all ports.', msg)

        for hba, ctls in process:
            for hba_channel, target_id, target_lun in ctls:
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
