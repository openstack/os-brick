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
import copy
import glob
import os
import time

from oslo_concurrency import lockutils
from oslo_concurrency import processutils as putils
from oslo_log import log as logging
from oslo_utils import strutils

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import base_iscsi
from os_brick import utils

synchronized = lockutils.synchronized_with_prefix('os-brick-')

LOG = logging.getLogger(__name__)


class ISCSIConnector(base.BaseLinuxConnector, base_iscsi.BaseISCSIConnector):
    """Connector class to attach/detach iSCSI volumes."""

    supported_transports = ['be2iscsi', 'bnx2i', 'cxgb3i', 'default',
                            'cxgb4i', 'qla4xxx', 'ocs', 'iser']

    def __init__(self, root_helper, driver=None,
                 execute=None, use_multipath=False,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 transport='default', *args, **kwargs):
        super(ISCSIConnector, self).__init__(
            root_helper, driver=driver,
            execute=execute,
            device_scan_attempts=device_scan_attempts,
            transport=transport, *args, **kwargs)
        self.use_multipath = use_multipath
        self.transport = self._validate_iface_transport(transport)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The iSCSI connector properties."""
        props = {}
        iscsi = ISCSIConnector(root_helper=root_helper,
                               execute=kwargs.get('execute'))
        initiator = iscsi.get_initiator()
        if initiator:
            props['initiator'] = initiator

        return props

    def get_search_path(self):
        """Where do we look for iSCSI based volumes."""
        return '/dev/disk/by-path'

    def get_volume_paths(self, connection_properties):
        """Get the list of existing paths for a volume.

        This method's job is to simply report what might/should
        already exist for a volume.  We aren't trying to attach/discover
        a new volume, but find any existing paths for a volume we
        think is already attached.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        """
        volume_paths = []

        # if there are no sessions, then target_portal won't exist
        if (('target_portal' not in connection_properties) and
           ('target_portals' not in connection_properties)):
            return volume_paths

        # Don't try and connect to the portals in the list as
        # this can create empty iSCSI sessions to hosts if they
        # didn't exist previously.
        # We are simply trying to find any existing volumes with
        # already connected sessions.
        host_devices, target_props = self._get_potential_volume_paths(
            connection_properties,
            connect_to_portal=False,
            use_rescan=False)

        for path in host_devices:
            if os.path.exists(path):
                volume_paths.append(path)

        return volume_paths

    def _get_iscsi_sessions_full(self):
        """Get iSCSI session information as a list of tuples.

        Uses iscsiadm -m session and from a command output like
            tcp: [1] 192.168.121.250:3260,1 iqn.2010-10.org.openstack:volume-

        This method will drop the node type and return a list like this:
            [('tcp:', '1', '192.168.121.250:3260', '1',
              'iqn.2010-10.org.openstack:volume-')]
        """
        out, err = self._run_iscsi_session()
        if err:
            LOG.warning("Couldn't find iscsi sessions because "
                        "iscsiadm err: %s", err)
            return []

        # Parse and clean the output from iscsiadm, which is in the form of:
        # transport_name: [session_id] ip_address:port,tpgt iqn node_type
        lines = []
        for line in out.splitlines():
            if line:
                info = line.split()
                sid = info[1][1:-1]
                portal, tpgt = info[2].split(',')
                lines.append((info[0], sid, portal, tpgt, info[3]))
        return lines

    def _get_iscsi_nodes(self):
        """Get iSCSI node information (portal, iqn) as a list of tuples.

        Uses iscsi_adm -m node and from a command output like
            192.168.121.250:3260,1 iqn.2010-10.org.openstack:volume

        This method will drop the tpgt and return a list like this:
            [('192.168.121.250:3260', 'iqn.2010-10.org.openstack:volume')]
        """
        out, err = self._execute('iscsiadm', '-m', 'node', run_as_root=True,
                                 root_helper=self._root_helper,
                                 check_exit_code=False)
        if err:
            LOG.warning("Couldn't find iSCSI nodes because iscsiadm err: %s",
                        err)
            return []

        # Parse and clean the output from iscsiadm which is in the form of:
        # ip_addresss:port,tpgt iqn
        lines = []
        for line in out.splitlines():
            if line:
                info = line.split()
                lines.append((info[0].split(',')[0], info[1]))
        return lines

    def _get_iscsi_sessions(self):
        """Return portals for all existing sessions."""
        # entry: [tcp, [1], 192.168.121.250:3260,1 ...]
        return [entry[2] for entry in self._get_iscsi_sessions_full()]

    def _get_potential_volume_paths(self, connection_properties,
                                    connect_to_portal=True,
                                    use_rescan=True):
        """Build a list of potential volume paths that exist.

        Given a list of target_portals in the connection_properties,
        a list of paths might exist on the system during discovery.
        This method's job is to build that list of potential paths
        for a volume that might show up.

        This is used during connect_volume time, in which case we want
        to connect to the iSCSI target portal.

        During get_volume_paths time, we are looking to
        find a list of existing volume paths for the connection_properties.
        In this case, we don't want to connect to the portal.  If we
        blindly try and connect to a portal, it could create a new iSCSI
        session that didn't exist previously, and then leave it stale.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param connect_to_portal: Do we want to try a new connection to the
                                  target portal(s)?  Set this to False if you
                                  want to search for existing volumes, not
                                  discover new volumes.
        :param connect_to_portal: bool
        :param use_rescan: Issue iSCSI rescan during discovery?
        :type use_rescan: bool
        :returns: dict
        """

        target_props = None
        connected_to_portal = False
        if self.use_multipath:
            LOG.info("Multipath discovery for iSCSI enabled")
            # Multipath installed, discovering other targets if available
            try:
                ips_iqns_luns = self._discover_iscsi_portals(
                    connection_properties)
            except Exception:
                if 'target_portals' in connection_properties:
                    raise exception.TargetPortalsNotFound(
                        target_portals=connection_properties['target_portals'])
                elif 'target_portal' in connection_properties:
                    raise exception.TargetPortalNotFound(
                        target_portal=connection_properties['target_portal'])
                else:
                    raise

            if not connection_properties.get('target_iqns'):
                # There are two types of iSCSI multipath devices. One which
                # shares the same iqn between multiple portals, and the other
                # which use different iqns on different portals.
                # Try to identify the type by checking the iscsiadm output
                # if the iqn is used by multiple portals. If it is, it's
                # the former, so use the supplied iqn. Otherwise, it's the
                # latter, so try the ip,iqn combinations to find the targets
                # which constitutes the multipath device.
                main_iqn = connection_properties['target_iqn']
                all_portals = {(ip, lun) for ip, iqn, lun in ips_iqns_luns}
                match_portals = {(ip, lun) for ip, iqn, lun in ips_iqns_luns
                                 if iqn == main_iqn}
                if len(all_portals) == len(match_portals):
                    ips_iqns_luns = [(p[0], main_iqn, p[1])
                                     for p in all_portals]

            for ip, iqn, lun in ips_iqns_luns:
                props = copy.deepcopy(connection_properties)
                props['target_portal'] = ip
                props['target_iqn'] = iqn
                if connect_to_portal:
                    if self._connect_to_iscsi_portal(props):
                        connected_to_portal = True

            if use_rescan:
                self._rescan_iscsi(ips_iqns_luns)

            host_devices = self._get_device_path(connection_properties)
        else:
            LOG.info("Multipath discovery for iSCSI not enabled.")
            iscsi_sessions = []
            if not connect_to_portal:
                iscsi_sessions = self._get_iscsi_sessions()

            host_devices = []
            target_props = connection_properties
            for props in self._iterate_all_targets(connection_properties):
                if connect_to_portal:
                    if self._connect_to_iscsi_portal(props):
                        target_props = props
                        connected_to_portal = True
                        host_devices = self._get_device_path(props)
                        break
                    else:
                        LOG.warning(
                            'Failed to connect to iSCSI portal %(portal)s.',
                            {'portal': props['target_portal']})
                else:
                    # If we aren't trying to connect to the portal, we
                    # want to find ALL possible paths from all of the
                    # alternate portals
                    if props['target_portal'] in iscsi_sessions:
                        paths = self._get_device_path(props)
                        host_devices = list(set(paths + host_devices))

        if connect_to_portal and not connected_to_portal:
            msg = _("Could not login to any iSCSI portal.")
            LOG.error(msg)
            raise exception.FailedISCSITargetPortalLogin(message=msg)

        return host_devices, target_props

    def set_execute(self, execute):
        super(ISCSIConnector, self).set_execute(execute)
        self._linuxscsi.set_execute(execute)

    def _validate_iface_transport(self, transport_iface):
        """Check that given iscsi_iface uses only supported transports

        Accepted transport names for provided iface param are
        be2iscsi, bnx2i, cxgb3i, cxgb4i, default, qla4xxx, ocs or iser.
        Note the difference between transport and iface;
        unlike default(iscsi_tcp)/iser, this is not one and the same for
        offloaded transports, where the default format is
        transport_name.hwaddress

        :param transport_iface: The iscsi transport type.
        :type transport_iface: str
        :returns: str
        """
        # Note that default(iscsi_tcp) and iser do not require a separate
        # iface file, just the transport is enough and do not need to be
        # validated. This is not the case for the other entries in
        # supported_transports array.
        if transport_iface in ['default', 'iser']:
            return transport_iface
        # Will return (6) if iscsi_iface file was not found, or (2) if iscsid
        # could not be contacted
        out = self._run_iscsiadm_bare(['-m',
                                       'iface',
                                       '-I',
                                       transport_iface],
                                      check_exit_code=[0, 2, 6])[0] or ""
        LOG.debug("iscsiadm %(iface)s configuration: stdout=%(out)s.",
                  {'iface': transport_iface, 'out': out})
        for data in [line.split() for line in out.splitlines()]:
            if data[0] == 'iface.transport_name':
                if data[2] in self.supported_transports:
                    return transport_iface

        LOG.warning("No useable transport found for iscsi iface %s. "
                    "Falling back to default transport.",
                    transport_iface)
        return 'default'

    def _get_transport(self):
        return self.transport

    @staticmethod
    def _get_luns(con_props, iqns=None):
        luns = con_props.get('target_luns')
        num_luns = len(con_props['target_iqns']) if iqns is None else len(iqns)
        return luns or [con_props.get('target_lun')] * num_luns

    def _discover_iscsi_portals(self, connection_properties):
        if all([key in connection_properties for key in ('target_portals',
                                                         'target_iqns')]):
            # Use targets specified by connection_properties
            return list(zip(connection_properties['target_portals'],
                        connection_properties['target_iqns'],
                        self._get_luns(connection_properties)))

        out = None
        iscsi_transport = ('iser' if self._get_transport() == 'iser'
                           else 'default')
        if connection_properties.get('discovery_auth_method'):
            try:
                self._run_iscsiadm_update_discoverydb(connection_properties,
                                                      iscsi_transport)
            except putils.ProcessExecutionError as exception:
                # iscsiadm returns 6 for "db record not found"
                if exception.exit_code == 6:
                    # Create a new record for this target and update the db
                    self._run_iscsiadm_bare(
                        ['-m', 'discoverydb',
                         '-t', 'sendtargets',
                         '-p', connection_properties['target_portal'],
                         '-I', iscsi_transport,
                         '--op', 'new'],
                        check_exit_code=[0, 255])
                    self._run_iscsiadm_update_discoverydb(
                        connection_properties
                    )
                else:
                    LOG.error("Unable to find target portal: "
                              "%(target_portal)s.",
                              {'target_portal': connection_properties[
                                  'target_portal']})
                    raise
            out = self._run_iscsiadm_bare(
                ['-m', 'discoverydb',
                 '-t', 'sendtargets',
                 '-I', iscsi_transport,
                 '-p', connection_properties['target_portal'],
                 '--discover'],
                check_exit_code=[0, 255])[0] or ""
        else:
            out = self._run_iscsiadm_bare(
                ['-m', 'discovery',
                 '-t', 'sendtargets',
                 '-I', iscsi_transport,
                 '-p', connection_properties['target_portal']],
                check_exit_code=[0, 255])[0] or ""

        ips, iqns = self._get_target_portals_from_iscsiadm_output(out)
        luns = self._get_luns(connection_properties, iqns)
        return list(zip(ips, iqns, luns))

    def _run_iscsiadm_update_discoverydb(self, connection_properties,
                                         iscsi_transport='default'):
        return self._execute(
            'iscsiadm',
            '-m', 'discoverydb',
            '-t', 'sendtargets',
            '-I', iscsi_transport,
            '-p', connection_properties['target_portal'],
            '--op', 'update',
            '-n', "discovery.sendtargets.auth.authmethod",
            '-v', connection_properties['discovery_auth_method'],
            '-n', "discovery.sendtargets.auth.username",
            '-v', connection_properties['discovery_auth_username'],
            '-n', "discovery.sendtargets.auth.password",
            '-v', connection_properties['discovery_auth_password'],
            run_as_root=True,
            root_helper=self._root_helper)

    @utils.trace
    @synchronized('extend_volume')
    def extend_volume(self, connection_properties):
        """Update the local kernel's size information.

        Try and update the local kernel's size information
        for an iSCSI volume.
        """
        LOG.info("Extend volume for %s",
                 strutils.mask_dict_password(connection_properties))

        volume_paths = self.get_volume_paths(connection_properties)
        LOG.info("Found paths for volume %s", volume_paths)
        if volume_paths:
            return self._linuxscsi.extend_volume(volume_paths)
        else:
            LOG.warning("Couldn't find any volume paths on the host to "
                        "extend volume for %(props)s",
                        {'props': strutils.mask_dict_password(
                            connection_properties)})
            raise exception.VolumePathsNotFound()

    @utils.trace
    @synchronized('connect_volume')
    @utils.retry(exceptions=(exception.VolumeDeviceNotFound))
    def connect_volume(self, connection_properties):
        """Attach the volume to instance_name.

        NOTE: Will retry up to three times to handle the case where c-vol
        and n-cpu are both using os-brick to manage iSCSI sessions but they
        are on the same node and using different locking directories. In this
        case, even though this call is synchronized, they will be separate
        locks and can still overlap with connect and disconnect. Since a
        disconnect during an initial attach can't cause IO failure (the device
        has not been made available yet), we just try the connection again.

        :param connection_properties: The valid dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict

        connection_properties for iSCSI must include:
        target_portal(s) - ip and optional port
        target_iqn(s) - iSCSI Qualified Name
        target_lun(s) - LUN id of the volume
        Note that plural keys may be used when use_multipath=True
        """

        device_info = {'type': 'block'}

        # At this point the host_devices may be an empty list
        host_devices, target_props = self._get_potential_volume_paths(
            connection_properties)

        # The /dev/disk/by-path/... node is not always present immediately
        # TODO(justinsb): This retry-with-delay is a pattern, move to utils?
        tries = 0
        # Loop until at least 1 path becomes available
        while all(not os.path.exists(x) for x in host_devices):
            if tries >= self.device_scan_attempts:
                raise exception.VolumeDeviceNotFound(device=host_devices)

            LOG.info("ISCSI volume not yet found at: %(host_devices)s. "
                     "Will rescan & retry.  Try number: %(tries)s.",
                     {'host_devices': host_devices, 'tries': tries})

            if self.use_multipath:
                # We need to refresh the paths as the devices may be empty
                host_devices, target_props = (
                    self._get_potential_volume_paths(connection_properties))
            else:
                if tries:
                    host_devices = self._get_device_path(target_props)
                self._run_iscsiadm(target_props, ("--rescan",))

            tries += 1
            if all(not os.path.exists(x) for x in host_devices):
                time.sleep(tries ** 2)
            else:
                break

        if tries != 0:
            LOG.debug("Found iSCSI node %(host_devices)s "
                      "(after %(tries)s rescans)",
                      {'host_devices': host_devices, 'tries': tries})

        # Choose an accessible host device
        host_device = next(dev for dev in host_devices if os.path.exists(dev))

        # find out the WWN of the device
        device_wwn = self._linuxscsi.get_scsi_wwn(host_device)
        LOG.debug("Device WWN = '%(wwn)s'", {'wwn': device_wwn})
        device_info['scsi_wwn'] = device_wwn

        if self.use_multipath:
            (host_device, multipath_id) = (super(
                ISCSIConnector, self)._discover_mpath_device(
                device_wwn, connection_properties, host_device))
            if multipath_id:
                device_info['multipath_id'] = multipath_id

        device_info['path'] = host_device

        LOG.debug("connect_volume returning %s", device_info)
        return device_info

    def _get_connection_devices(self, connection_properties):
        """Get map of devices by sessions from our connection.

        For each of the TCP sessions that correspond to our connection
        properties we generate a map of (ip, iqn) to (belong, other) where
        belong is a set of devices in that session that populated our system
        when we did a connection using connection properties, and other are
        any other devices that share that same session but are the result of
        connecting with different connection properties.

        We also include all nodes from our connection that don't have a
        session.
        """
        ips_iqns_luns = self._get_all_targets(connection_properties)
        nodes = self._get_iscsi_nodes()
        sessions = self._get_iscsi_sessions_full()
        # Use (portal, iqn) to map the session value
        sessions_map = {(s[2], s[4]): s[1] for s in sessions if s[0] == 'tcp:'}
        # device_map will keep a tuple with devices from the connection and
        # others that don't belong to this connection" (belong, others)
        device_map = collections.defaultdict(lambda: (set(), set()))

        for ip, iqn, lun in ips_iqns_luns:
            session = sessions_map.get((ip, iqn))
            # Our nodes that don't have a session will be returned as empty
            if not session:
                if (ip, iqn) in nodes:
                    device_map[(ip, iqn)] = (set(), set())
                continue

            # Get all devices for the session
            paths = glob.glob('/sys/class/scsi_host/host*/device/session' +
                              session + '/target*/*:*:*:*/block/*')
            belong, others = device_map[(ip, iqn)]
            for path in paths:
                __, hctl, __, device = path.rsplit('/', 3)
                lun_path = int(hctl.rsplit(':', 1)[-1])
                # For partitions turn them into the whole device: sde1 -> sde
                device = device.strip('0123456789')
                if lun_path == lun:
                    belong.add(device)
                else:
                    others.add(device)

        return device_map

    @utils.trace
    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Detach the volume from instance_name.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict that must include:
                                     target_portal(s) - IP and optional port
                                     target_iqn(s) - iSCSI Qualified Name
                                     target_lun(s) - LUN id of the volume
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        :param force: Whether to forcefully disconnect even if flush fails.
        :type force: bool
        :param ignore_errors: When force is True, this will decide whether to
                              ignore errors or raise an exception once finished
                              the operation.  Default is False.
        :type ignore_errors: bool
        """
        exc = exception.ExceptionChainer()
        devices_map = self._get_connection_devices(connection_properties)

        # Remove devices and multipath from this connection
        remove_devices = set()
        for remove, __ in devices_map.values():
            remove_devices.update(remove)
        multipath_name = self._linuxscsi.remove_connection(remove_devices,
                                                           self.use_multipath,
                                                           force, exc)

        # Disconnect sessions and remove nodes that are left without devices
        disconnect = [conn for conn, (__, keep) in devices_map.items()
                      if not keep]
        self._disconnect_connection(connection_properties, disconnect, force,
                                    exc)

        # If flushing the multipath failed before, try now after we have
        # removed the devices and we may have even logged off (only reaches
        # here with multipath_name if force=True).
        if multipath_name:
            LOG.debug('Flushing again multipath %s now that we removed the '
                      'devices.', multipath_name)
            self._linuxscsi.flush_multipath_device(multipath_name)

        if exc:
            LOG.warning('There were errors removing %s, leftovers may remain '
                        'in the system', remove_devices)
            if not ignore_errors:
                raise exc

    def _munge_portal(self, target):
        """Remove brackets from portal.

        In case IPv6 address was used the udev path should not contain any
        brackets. Udev code specifically forbids that.
        """
        portal, iqn, lun = target
        return (portal.replace('[', '').replace(']', ''), iqn,
                self._linuxscsi.process_lun_id(lun))

    def _get_device_path(self, connection_properties):
        if self._get_transport() == "default":
            return ["/dev/disk/by-path/ip-%s-iscsi-%s-lun-%s" %
                    self._munge_portal(x) for x in
                    self._get_all_targets(connection_properties)]
        else:
            # we are looking for paths in the format :
            # /dev/disk/by-path/
            # pci-XXXX:XX:XX.X-ip-PORTAL:PORT-iscsi-IQN-lun-LUN_ID
            device_list = []
            for x in self._get_all_targets(connection_properties):
                look_for_device = glob.glob(
                    '/dev/disk/by-path/*ip-%s-iscsi-%s-lun-%s' %
                    self._munge_portal(x))
                if look_for_device:
                    device_list.extend(look_for_device)
            return device_list

    def get_initiator(self):
        """Secure helper to read file as root."""
        file_path = '/etc/iscsi/initiatorname.iscsi'
        try:
            lines, _err = self._execute('cat', file_path, run_as_root=True,
                                        root_helper=self._root_helper)

            for l in lines.split('\n'):
                if l.startswith('InitiatorName='):
                    return l[l.index('=') + 1:].strip()
        except putils.ProcessExecutionError:
            LOG.warning("Could not find the iSCSI Initiator File %s",
                        file_path)
            return None

    def _run_iscsiadm(self, connection_properties, iscsi_command, **kwargs):
        check_exit_code = kwargs.pop('check_exit_code', 0)
        attempts = kwargs.pop('attempts', 1)
        delay_on_retry = kwargs.pop('delay_on_retry', True)
        (out, err) = self._execute('iscsiadm', '-m', 'node', '-T',
                                   connection_properties['target_iqn'],
                                   '-p',
                                   connection_properties['target_portal'],
                                   *iscsi_command, run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=check_exit_code,
                                   attempts=attempts,
                                   delay_on_retry=delay_on_retry)
        msg = ("iscsiadm %(iscsi_command)s: stdout=%(out)s stderr=%(err)s" %
               {'iscsi_command': iscsi_command, 'out': out, 'err': err})
        # don't let passwords be shown in log output
        LOG.debug(strutils.mask_password(msg))

        return (out, err)

    def _iscsiadm_update(self, connection_properties, property_key,
                         property_value, **kwargs):
        iscsi_command = ('--op', 'update', '-n', property_key,
                         '-v', property_value)
        return self._run_iscsiadm(connection_properties, iscsi_command,
                                  **kwargs)

    def _get_target_portals_from_iscsiadm_output(self, output):
        # return both portals and iqns as 2 lists
        #
        # as we are parsing a command line utility, allow for the
        # possibility that additional debug data is spewed in the
        # stream, and only grab actual ip / iqn lines.
        ips = []
        iqns = []
        for data in [line.split() for line in output.splitlines()]:
            if len(data) == 2 and data[1].startswith('iqn.'):
                ips.append(data[0])
                iqns.append(data[1])
        return ips, iqns

    def _connect_to_iscsi_portal(self, connection_properties):
        # NOTE(vish): If we are on the same host as nova volume, the
        #             discovery makes the target so we don't need to
        #             run --op new. Therefore, we check to see if the
        #             target exists, and if we get 255 (Not Found), then
        #             we run --op new. This will also happen if another
        #             volume is using the same target.
        LOG.info("Trying to connect to iSCSI portal %(portal)s",
                 {"portal": connection_properties['target_portal']})
        try:
            self._run_iscsiadm(connection_properties, ())
        except putils.ProcessExecutionError as exc:
            # iscsiadm returns 21 for "No records found" after version 2.0-871
            if exc.exit_code in [21, 255]:
                self._run_iscsiadm(connection_properties,
                                   ('--interface', self._get_transport(),
                                    '--op', 'new'))
            else:
                raise

        if connection_properties.get('auth_method'):
            self._iscsiadm_update(connection_properties,
                                  "node.session.auth.authmethod",
                                  connection_properties['auth_method'])
            self._iscsiadm_update(connection_properties,
                                  "node.session.auth.username",
                                  connection_properties['auth_username'])
            self._iscsiadm_update(connection_properties,
                                  "node.session.auth.password",
                                  connection_properties['auth_password'])

        # Duplicate logins crash iscsiadm after load,
        # so we scan active sessions to see if the node is logged in.
        out = self._run_iscsiadm_bare(["-m", "session"],
                                      run_as_root=True,
                                      check_exit_code=[0, 1, 21])[0] or ""

        portals = [{'portal': p.split(" ")[2], 'iqn': p.split(" ")[3]}
                   for p in out.splitlines() if p.startswith("tcp:")]

        stripped_portal = connection_properties['target_portal'].split(",")[0]
        if len(portals) == 0 or len([s for s in portals
                                     if stripped_portal ==
                                     s['portal'].split(",")[0]
                                     and
                                     s['iqn'] ==
                                     connection_properties['target_iqn']]
                                    ) == 0:
            try:
                self._run_iscsiadm(connection_properties,
                                   ("--login",),
                                   check_exit_code=[0, 255])
            except putils.ProcessExecutionError as err:
                # exit_code=15 means the session already exists, so it should
                # be regarded as successful login.
                if err.exit_code not in [15]:
                    LOG.warning('Failed to login iSCSI target %(iqn)s '
                                'on portal %(portal)s (exit code '
                                '%(err)s).',
                                {'iqn': connection_properties['target_iqn'],
                                 'portal': connection_properties[
                                     'target_portal'],
                                 'err': err.exit_code})
                    return False

            self._iscsiadm_update(connection_properties,
                                  "node.startup",
                                  "automatic")
        return True

    def _disconnect_from_iscsi_portal(self, connection_properties):
        self._iscsiadm_update(connection_properties, "node.startup", "manual",
                              check_exit_code=[0, 21, 255])
        self._run_iscsiadm(connection_properties, ("--logout",),
                           check_exit_code=[0, 21, 255])
        self._run_iscsiadm(connection_properties, ('--op', 'delete'),
                           check_exit_code=[0, 21, 255],
                           attempts=5,
                           delay_on_retry=True)

    def _disconnect_connection(self, connection_properties, connections, force,
                               exc):
        LOG.debug('Disconnecting from: %s', connections)
        props = connection_properties.copy()
        for ip, iqn in connections:
            props['target_portal'] = ip
            props['target_iqn'] = iqn
            with exc.context(force, 'Disconnect from %s %s failed', ip, iqn):
                self._disconnect_from_iscsi_portal(props)

    def _run_iscsi_session(self):
        (out, err) = self._run_iscsiadm_bare(('-m', 'session'),
                                             check_exit_code=[0, 1, 21, 255])
        LOG.debug("iscsi session list stdout=%(out)s stderr=%(err)s",
                  {'out': out, 'err': err})
        return (out, err)

    def _run_iscsiadm_bare(self, iscsi_command, **kwargs):
        check_exit_code = kwargs.pop('check_exit_code', 0)
        (out, err) = self._execute('iscsiadm',
                                   *iscsi_command,
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=check_exit_code)
        LOG.debug("iscsiadm %(iscsi_command)s: stdout=%(out)s stderr=%(err)s",
                  {'iscsi_command': iscsi_command, 'out': out, 'err': err})
        return (out, err)

    def _run_multipath(self, multipath_command, **kwargs):
        check_exit_code = kwargs.pop('check_exit_code', 0)
        (out, err) = self._execute('multipath',
                                   *multipath_command,
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=check_exit_code)
        LOG.debug("multipath %(multipath_command)s: "
                  "stdout=%(out)s stderr=%(err)s",
                  {'multipath_command': multipath_command,
                   'out': out, 'err': err})
        return (out, err)

    @utils.retry(exception.HostChannelsTargetsNotFound, backoff_rate=1.5)
    def _get_hosts_channels_targets_luns(self, ips_iqns_luns):
        iqns = {iqn: lun for ip, iqn, lun in ips_iqns_luns}
        LOG.debug('Getting hosts, channels, and targets for iqns: %s',
                  iqns.keys())

        # Get all targets indexed by scsi host path
        targets_paths = glob.glob('/sys/class/scsi_host/host*/device/session*/'
                                  'target*')
        targets = collections.defaultdict(list)
        for path in targets_paths:
            target = path.split('/target')[1]
            host = path.split('/device/')[0]
            targets[host].append(target.split(':'))

        # Get all scsi targets
        sessions = glob.glob('/sys/class/scsi_host/host*/device/session*/'
                             'iscsi_session/session*/targetname')

        result = []
        for session in sessions:
            # Read iSCSI target name
            try:
                with open(session, 'r') as f:
                    targetname = f.read().strip('\n')
            except Exception:
                continue

            # If we are interested in it we store its target information
            if targetname in iqns:
                host = session.split('/device/')[0]
                for __, channel, target_id in targets[host]:
                    result.append((host, channel, target_id, iqns[targetname]))
                # Stop as soon as we have the info of all our iqns, even if
                # there are more sessions to check
                del iqns[targetname]
                if not iqns:
                    break

        # In some cases the login and udev triggers may not have been fast
        # enough to create all sysfs entries, so we want to retry.
        else:
            raise exception.HostChannelsTargetsNotFound(iqns=iqns.keys(),
                                                        found=result)
        return result

    def _rescan_iscsi(self, ips_iqns_luns):
        try:
            hctls = self._get_hosts_channels_targets_luns(ips_iqns_luns)
        except exception.HostChannelsTargetsNotFound as e:
            if not e.found:
                LOG.error('iSCSI scan failed: %s', e)
                return

            hctls = e.found
            LOG.warning('iSCSI scan: %(error)s\nScanning %(hosts)s',
                        {'error': e, 'hosts': [h for h, c, t, l in hctls]})

        for host_path, channel, target_id, target_lun in hctls:
            LOG.debug('Scanning host %(host)s c: %(channel)s, '
                      't: %(target)s, l: %(lun)s)',
                      {'host': host_path, 'channel': channel,
                       'target': target_id, 'lun': target_lun})
            self._linuxscsi.echo_scsi_command(
                "%s/scan" % host_path,
                "%(c)s %(t)s %(l)s" % {'c': channel,
                                       't': target_id,
                                       'l': target_lun})
