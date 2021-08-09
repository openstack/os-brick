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


from collections import defaultdict
import copy
import glob
import os
import re
import time
from typing import List, Tuple  # noqa: H301

from oslo_concurrency import lockutils
from oslo_concurrency import processutils as putils
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import strutils

from os_brick import exception
from os_brick import executor
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import base_iscsi
from os_brick.initiator import utils as initiator_utils
from os_brick import utils

synchronized = lockutils.synchronized_with_prefix('os-brick-')

LOG = logging.getLogger(__name__)


class ISCSIConnector(base.BaseLinuxConnector, base_iscsi.BaseISCSIConnector):
    """Connector class to attach/detach iSCSI volumes."""

    supported_transports = ['be2iscsi', 'bnx2i', 'cxgb3i', 'default',
                            'cxgb4i', 'qla4xxx', 'ocs', 'iser', 'tcp']
    VALID_SESSIONS_PREFIX = ('tcp:', 'iser:')

    def __init__(
            self, root_helper: str, driver=None,
            execute=None, use_multipath: bool = False,
            device_scan_attempts: int = initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
            transport='default', *args, **kwargs):
        super(ISCSIConnector, self).__init__(
            root_helper, driver=driver,
            execute=execute,
            device_scan_attempts=device_scan_attempts,
            transport=transport, *args, **kwargs)  # type: ignore
        self.use_multipath: bool = use_multipath
        self.transport: str = self._validate_iface_transport(transport)

    @staticmethod
    def get_connector_properties(root_helper: str, *args, **kwargs) -> dict:
        """The iSCSI connector properties."""
        props = {}
        iscsi = ISCSIConnector(root_helper=root_helper,
                               execute=kwargs.get('execute'))
        initiator = iscsi.get_initiator()
        if initiator:
            props['initiator'] = initiator

        return props

    def get_search_path(self) -> str:
        """Where do we look for iSCSI based volumes."""
        return '/dev/disk/by-path'

    def get_volume_paths(self, connection_properties: dict) -> list:
        """Get the list of existing paths for a volume.

        This method's job is to simply report what might/should
        already exist for a volume.  We aren't trying to attach/discover
        a new volume, but find any existing paths for a volume we
        think is already attached.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        """
        volume_paths: list = []

        # if there are no sessions, then target_portal won't exist
        if (('target_portal' not in connection_properties) and
           ('target_portals' not in connection_properties)):
            return volume_paths

        # Don't try and connect to the portals in the list as
        # this can create empty iSCSI sessions to hosts if they
        # didn't exist previously.
        # We are simply trying to find any existing volumes with
        # already connected sessions.
        host_devices = self._get_potential_volume_paths(connection_properties)
        for path in host_devices:
            if os.path.exists(path):
                volume_paths.append(path)

        return volume_paths

    def _get_iscsi_sessions_full(self) -> List[tuple]:
        """Get iSCSI session information as a list of tuples.

        Uses iscsiadm -m session and from a command output like
            tcp: [1] 192.168.121.250:3260,1 iqn.2010-10.org.openstack:
            volume- (non-flash)

        This method will drop the node type and return a list like this:
            [('tcp:', '1', '192.168.121.250:3260', '1',
              'iqn.2010-10.org.openstack:volume-')]
        """
        out, err = self._run_iscsi_session()
        if err:
            LOG.warning("iscsiadm stderr output when getting sessions: %s",
                        err)

        # Parse and clean the output from iscsiadm, which is in the form of:
        # transport_name: [session_id] ip_address:port,tpgt iqn node_type
        lines: List[tuple] = []
        for line in out.splitlines():
            if line:
                info = line.split()
                sid = info[1][1:-1]
                portal, tpgt = info[2].split(',')
                lines.append((info[0], sid, portal, tpgt, info[3]))
        return lines

    def _get_iscsi_nodes(self) -> List[tuple]:
        """Get iSCSI node information (portal, iqn) as a list of tuples.

        Uses iscsiadm -m node and from a command output like
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
        # ip_address:port,tpgt iqn
        lines: List[tuple] = []
        for line in out.splitlines():
            if line:
                info = line.split()
                try:
                    lines.append((info[0].split(',')[0], info[1]))
                except IndexError:
                    pass
        return lines

    def _get_iscsi_sessions(self) -> list:
        """Return portals for all existing sessions."""
        # entry: [tcp, [1], 192.168.121.250:3260,1 ...]
        return [entry[2] for entry in self._get_iscsi_sessions_full()]

    def _get_ips_iqns_luns(self,
                           connection_properties: dict,
                           discover: bool = True,
                           is_disconnect_call: bool = False):
        """Build a list of ips, iqns, and luns.

        Used when doing singlepath and multipath, and we have 4 cases:

        - All information is in the connection properties
        - We have to do an iSCSI discovery to get the information
        - We don't want to do another discovery and we query the discoverydb
        - Discovery failed because it was actually a single pathed attachment

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param discover: Whether doing an iSCSI discovery is acceptable.
        :type discover: bool
        :param is_disconnect_call: Whether this is a call coming from a user
                                   disconnect_volume call or a call from some
                                   other operation's cleanup.
        :type is_disconnect_call: bool
        :returns: list of tuples of (ip, iqn, lun)
        """
        # There are cases where we don't know if the local attach was done
        # using multipathing or single pathing, so assume multipathing.
        try:
            if ('target_portals' in connection_properties and
                    'target_iqns' in connection_properties):
                # Use targets specified by connection_properties
                ips_iqns_luns = self._get_all_targets(connection_properties)
            else:
                method = (self._discover_iscsi_portals if discover
                          else self._get_discoverydb_portals)
                ips_iqns_luns = method(connection_properties)
        except exception.TargetPortalNotFound:
            # Discovery failed, on disconnect this will happen if we
            # are detaching a single pathed connection, so we use the
            # connection properties to return the tuple.
            if is_disconnect_call:
                return self._get_all_targets(connection_properties)
            raise
        except Exception:
            LOG.exception('Exception encountered during portal discovery')
            if 'target_portals' in connection_properties:
                raise exception.TargetPortalsNotFound(
                    target_portals=connection_properties['target_portals'])
            if 'target_portal' in connection_properties:
                raise exception.TargetPortalNotFound(
                    target_portal=connection_properties['target_portal'])
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

        return ips_iqns_luns

    def _get_potential_volume_paths(self,
                                    connection_properties: dict) -> List[str]:
        """Build a list of potential volume paths that exist.

        Given a list of target_portals in the connection_properties,
        a list of paths might exist on the system during discovery.
        This method's job is to build that list of potential paths
        for a volume that might show up.

        This is only used during get_volume_paths time, we are looking to
        find a list of existing volume paths for the connection_properties.
        In this case, we don't want to connect to the portal.  If we
        blindly try and connect to a portal, it could create a new iSCSI
        session that didn't exist previously, and then leave it stale.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: list
        """
        if self.use_multipath:
            LOG.info("Multipath discovery for iSCSI enabled")
            # Multipath installed, discovering other targets if available
            host_devices = self._get_device_path(connection_properties)
        else:
            LOG.info("Multipath discovery for iSCSI not enabled.")
            iscsi_sessions = self._get_iscsi_sessions()

            host_devices = set()
            for props in self._iterate_all_targets(connection_properties):
                # If we aren't trying to connect to the portal, we
                # want to find ALL possible paths from all of the
                # alternate portals
                if props['target_portal'] in iscsi_sessions:
                    paths = self._get_device_path(props)
                    host_devices.update(paths)
            host_devices = list(host_devices)

        return host_devices

    def set_execute(self, execute):
        super(ISCSIConnector, self).set_execute(execute)
        self._linuxscsi.set_execute(execute)

    def _validate_iface_transport(self, transport_iface: str) -> str:
        """Check that given iscsi_iface uses only supported transports

        Accepted transport names for provided iface param are
        be2iscsi, bnx2i, cxgb3i, cxgb4i, default, qla4xxx, ocs, iser or tcp.
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

    def _get_transport(self) -> str:
        return self.transport

    def _get_discoverydb_portals(self,
                                 connection_properties: dict) -> List[tuple]:
        """Retrieve iscsi portals information from the discoverydb.

        Example of discoverydb command output:

        SENDTARGETS:
        DiscoveryAddress: 192.168.1.33,3260
        DiscoveryAddress: 192.168.1.2,3260
        Target: iqn.2004-04.com.qnap:ts-831x:iscsi.cinder-20170531114245.9eff88
            Portal: 192.168.1.3:3260,1
                Iface Name: default
            Portal: 192.168.1.2:3260,1
                Iface Name: default
        Target: iqn.2004-04.com.qnap:ts-831x:iscsi.cinder-20170531114447.9eff88
            Portal: 192.168.1.3:3260,1
                Iface Name: default
            Portal: 192.168.1.2:3260,1
                Iface Name: default
        DiscoveryAddress: 192.168.1.38,3260
        iSNS:
        No targets found.
        STATIC:
        No targets found.
        FIRMWARE:
        No targets found.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: list of tuples of (ip, iqn, lun)
        """
        ip, port = connection_properties['target_portal'].rsplit(':', 1)
        # NOTE(geguileo): I don't know if IPv6 will be reported with []
        # or not, so we'll make them optional.
        ip = ip.replace('[', r'\[?').replace(']', r'\]?')
        out = self._run_iscsiadm_bare(['-m', 'discoverydb',
                                       '-o', 'show',
                                       '-P', 1])[0] or ""
        regex = ''.join(('^SENDTARGETS:\n.*?^DiscoveryAddress: ',
                         ip, ',', port,
                         '.*?\n(.*?)^(?:DiscoveryAddress|iSNS):.*'))
        LOG.debug('Regex to get portals from discoverydb: %s', regex)

        info = re.search(regex, out, re.DOTALL | re.MULTILINE)

        ips = []
        iqns = []

        if info:
            iscsi_transport = ('iser' if self._get_transport() == 'iser'
                               else 'default')
            iface = 'Iface Name: ' + iscsi_transport
            current_iqn = ''
            current_ip = ''
            for line in info.group(1).splitlines():
                line = line.strip()
                if line.startswith('Target:'):
                    current_iqn = line[8:]
                elif line.startswith('Portal:'):
                    current_ip = line[8:].split(',')[0]
                elif line.startswith(iface):
                    if current_iqn and current_ip:
                        iqns.append(current_iqn)
                        ips.append(current_ip)
                    current_ip = ''

        if not iqns:
            raise exception.TargetPortalsNotFound(
                _('Unable to find target portals information on discoverydb.'))

        luns = self._get_luns(connection_properties, iqns)
        return list(zip(ips, iqns, luns))

    def _discover_iscsi_portals(self, connection_properties: dict) -> list:
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
            old_node_startups = self._get_node_startup_values(
                connection_properties)
            out = self._run_iscsiadm_bare(
                ['-m', 'discoverydb',
                 '-t', 'sendtargets',
                 '-I', iscsi_transport,
                 '-p', connection_properties['target_portal'],
                 '--discover'],
                check_exit_code=[0, 255])[0] or ""
            self._recover_node_startup_values(connection_properties,
                                              old_node_startups)
        else:
            old_node_startups = self._get_node_startup_values(
                connection_properties)
            out = self._run_iscsiadm_bare(
                ['-m', 'discovery',
                 '-t', 'sendtargets',
                 '-I', iscsi_transport,
                 '-p', connection_properties['target_portal']],
                check_exit_code=[0, 255])[0] or ""
            self._recover_node_startup_values(connection_properties,
                                              old_node_startups)

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
    def extend_volume(self, connection_properties: dict):
        """Update the local kernel's size information.

        Try and update the local kernel's size information
        for an iSCSI volume.
        """
        LOG.info("Extend volume for %s",
                 strutils.mask_dict_password(connection_properties))

        volume_paths = self.get_volume_paths(connection_properties)
        LOG.info("Found paths for volume %s", volume_paths)
        if volume_paths:
            return self._linuxscsi.extend_volume(
                volume_paths, use_multipath=self.use_multipath)
        else:
            LOG.warning("Couldn't find any volume paths on the host to "
                        "extend volume for %(props)s",
                        {'props': strutils.mask_dict_password(
                            connection_properties)})
            raise exception.VolumePathsNotFound()

    @utils.trace
    @synchronized('connect_volume')
    def connect_volume(self, connection_properties: dict):
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
        try:
            if self.use_multipath:
                return self._connect_multipath_volume(connection_properties)
            return self._connect_single_volume(connection_properties)
        except Exception:
            # NOTE(geguileo): By doing the cleanup here we ensure we only do
            # the logins once for multipath if they succeed, but retry if they
            # don't, which helps on bad network cases.
            with excutils.save_and_reraise_exception():
                self._cleanup_connection(connection_properties, force=True)

    @utils.retry((exception.VolumeDeviceNotFound))
    def _get_device_link(self, wwn, device, mpath):
        # These are the default symlinks that should always be there
        if mpath:
            symlink = '/dev/disk/by-id/dm-uuid-mpath-' + mpath
        else:
            symlink = '/dev/disk/by-id/scsi-' + wwn

        # If default symlinks are not there just search for anything that links
        # to our device.  In my experience this will return the last added link
        # first, so if we are going to succeed this should be fast.
        if not os.path.realpath(symlink) == device:
            links_path = '/dev/disk/by-id/'
            for symlink in os.listdir(links_path):
                symlink = links_path + symlink
                if os.path.realpath(symlink) == device:
                    break
            else:
                # Raising this will trigger the next retry
                raise exception.VolumeDeviceNotFound(device='/dev/disk/by-id')
        return symlink

    def _get_connect_result(self, con_props, wwn, devices_names, mpath=None):
        device = '/dev/' + (mpath or devices_names[0])

        # NOTE(geguileo): This is only necessary because of the current
        # encryption flow that requires that connect_volume returns a symlink
        # because first we do the volume attach, then the libvirt config is
        # generated using the path returned by the atach, and then we do the
        # encryption attach, which is forced to preserve the path that was used
        # in the libvirt config.  If we fix that flow in OS-brick, Nova, and
        # Cinder we can remove this and just return the real path.
        if con_props.get('encrypted'):
            device = self._get_device_link(wwn, device, mpath)

        result = {'type': 'block', 'scsi_wwn': wwn, 'path': device}
        if mpath:
            result['multipath_id'] = wwn
        return result

    @utils.retry((exception.VolumeDeviceNotFound))
    def _connect_single_volume(self, connection_properties):
        """Connect to a volume using a single path."""
        data = {'stop_connecting': False, 'num_logins': 0, 'failed_logins': 0,
                'stopped_threads': 0, 'found_devices': [],
                'just_added_devices': []}

        for props in self._iterate_all_targets(connection_properties):
            self._connect_vol(self.device_scan_attempts, props, data)
            found_devs = data['found_devices']
            if found_devs:
                for __ in range(10):
                    wwn = self._linuxscsi.get_sysfs_wwn(found_devs)
                    if wwn:
                        break
                    time.sleep(1)
                else:
                    LOG.debug('Could not find the WWN for %s.',
                              found_devs[0])  # type: ignore
                return self._get_connect_result(connection_properties,
                                                wwn, found_devs)

            # If we failed we must cleanup the connection, as we could be
            # leaving the node entry if it's not being used by another device.
            ips_iqns_luns = ((props['target_portal'], props['target_iqn'],
                              props['target_lun']), )
            self._cleanup_connection(props, ips_iqns_luns, force=True,
                                     ignore_errors=True)
            # Reset connection result values for next try
            data.update(num_logins=0, failed_logins=0, found_devices=[])

        raise exception.VolumeDeviceNotFound(device='')

    def _connect_vol(self, rescans, props, data):
        """Make a connection to a volume, send scans and wait for the device.

        This method is specifically designed to support multithreading and
        share the results via a shared dictionary with fixed keys, which is
        thread safe.

        Since the heaviest operations are run via subprocesses we don't worry
        too much about the GIL or how the eventlets will handle the context
        switching.

        The method will only try to log in once, since iscsid's initiator
        already tries 8 times by default to do the login, or whatever value we
        have as node.session.initial_login_retry_max in our system.

        Shared dictionary has the following keys:
        - stop_connecting: When the caller wants us to stop the rescans
        - num_logins: Count of how many threads have successfully logged in
        - failed_logins: Count of how many threads have failed to log in
        - stopped_threads: How many threads have finished.  This may be
                           different than num_logins + failed_logins, since
                           some threads may still be waiting for a device.
        - found_devices: List of devices the connections have found
        - just_added_devices: Devices that have been found and still have not
                              been processed by the main thread that manages
                              all the connecting threads.

        :param rescans: Number of rescans to perform before giving up.
        :param props: Properties of the connection.
        :param data: Shared data.
        """
        device = hctl = None
        portal = props['target_portal']
        try:
            session, manual_scan = self._connect_to_iscsi_portal(props)
        except Exception:
            LOG.exception('Exception connecting to %s', portal)
            session = None

        if session:
            do_scans = rescans > 0 or manual_scan
            # Scan is sent on connect by iscsid, but we must do it manually on
            # manual scan mode.  This scan cannot count towards total rescans.
            if manual_scan:
                num_rescans = -1
                seconds_next_scan = 0
            else:
                num_rescans = 0
                seconds_next_scan = 4

            data['num_logins'] += 1
            LOG.debug('Connected to %s', portal)
            while do_scans:
                try:
                    if not hctl:
                        hctl = self._linuxscsi.get_hctl(session,
                                                        props['target_lun'])
                    if hctl:
                        if seconds_next_scan <= 0:
                            num_rescans += 1
                            self._linuxscsi.scan_iscsi(*hctl)
                            # 4 seconds on 1st rescan, 9s on 2nd, 16s on 3rd
                            seconds_next_scan = (num_rescans + 2) ** 2

                        device = self._linuxscsi.device_name_by_hctl(session,
                                                                     hctl)
                        if device:
                            break

                except Exception:
                    LOG.exception('Exception scanning %s', portal)
                    pass
                do_scans = (num_rescans <= rescans and
                            not (device or data['stop_connecting']))
                if do_scans:
                    time.sleep(1)
                    seconds_next_scan -= 1

            if device:
                LOG.debug('Connected to %s using %s', device,
                          strutils.mask_password(props))
            else:
                LOG.warning('LUN %(lun)s on iSCSI portal %(portal)s not found '
                            'on sysfs after logging in.',
                            {'lun': props['target_lun'], 'portal': portal})
        else:
            LOG.warning('Failed to connect to iSCSI portal %s.', portal)
            data['failed_logins'] += 1

        if device:
            data['found_devices'].append(device)
            data['just_added_devices'].append(device)
        data['stopped_threads'] += 1

    @utils.retry((exception.VolumeDeviceNotFound))
    def _connect_multipath_volume(self, connection_properties):
        """Connect to a multipathed volume launching parallel login requests.

        We will be doing parallel login requests, which will considerably speed
        up the process when we have flaky connections.

        We'll always try to return a multipath device even if there's only one
        path discovered, that way we can return once we have logged in in all
        the portals, because the paths will come up later.

        To make this possible we tell multipathd that the wwid is a multipath
        as soon as we have one device, and then hint multipathd to reconsider
        that volume for a multipath asking to add the path, because even if
        it's already known by multipathd it would have been discarded if it
        was the first time this volume was seen here.
        """
        wwn = mpath = None
        wwn_added = False
        last_try_on = 0.0
        found: list = []
        just_added_devices: list = []
        # Dict used to communicate with threads as detailed in _connect_vol
        data = {'stop_connecting': False, 'num_logins': 0, 'failed_logins': 0,
                'stopped_threads': 0, 'found_devices': found,
                'just_added_devices': just_added_devices}

        ips_iqns_luns = self._get_ips_iqns_luns(connection_properties)
        # Launch individual threads for each session with the own properties
        retries = self.device_scan_attempts
        threads = []
        for ip, iqn, lun in ips_iqns_luns:
            props = connection_properties.copy()
            props.update(target_portal=ip, target_iqn=iqn, target_lun=lun)

            # NOTE(yenai): The method _connect_vol is used for parallelize
            # logins, we shouldn't give these arguments; and it will make a
            # mess in the debug message in _connect_vol. So, kick them out:
            for key in ('target_portals', 'target_iqns', 'target_luns'):
                props.pop(key, None)

            threads.append(executor.Thread(target=self._connect_vol,
                                           args=(retries, props, data)))
        for thread in threads:
            thread.start()

        # Continue until:
        # - All connection attempts have finished and none has logged in
        # - Multipath has been found and connection attempts have either
        #   finished or have already logged in
        # - We have finished in all threads, logged in, found some device, and
        #   10 seconds have passed, which should be enough with up to 10%
        #   network package drops.
        while not ((len(ips_iqns_luns) == data['stopped_threads'] and
                    not found) or
                   (mpath and len(ips_iqns_luns) == data['num_logins'] +
                    data['failed_logins'])):
            # We have devices but we don't know the wwn yet
            if not wwn and found:
                wwn = self._linuxscsi.get_sysfs_wwn(found, mpath)
            if not mpath and found:
                mpath = self._linuxscsi.find_sysfs_multipath_dm(found)
                # We have the wwn but not a multipath
                if wwn and not(mpath or wwn_added):
                    # Tell multipathd that this wwn is a multipath and hint
                    # multipathd to recheck all the devices we have just
                    # connected.  We only do this once, since for any new
                    # device multipathd will already know it is a multipath.
                    # This is only useful if we have multipathd configured with
                    # find_multipaths set to yes, and has no effect if it's set
                    # to no.
                    wwn_added = self._linuxscsi.multipath_add_wwid(wwn)
                    while not mpath and just_added_devices:
                        device_path = '/dev/' + just_added_devices.pop(0)
                        self._linuxscsi.multipath_add_path(device_path)
                        mpath = self._linuxscsi.find_sysfs_multipath_dm(found)
            # Give some extra time after all threads have finished.
            if (not last_try_on and found and
                    len(ips_iqns_luns) == data['stopped_threads']):
                LOG.debug('All connection threads finished, giving 10 seconds '
                          'for dm to appear.')
                last_try_on = time.time() + 10
            elif last_try_on and last_try_on < time.time():
                break
            time.sleep(1)
        data['stop_connecting'] = True
        for thread in threads:
            thread.join()

        # If we haven't found any devices let the caller do the cleanup
        if not found:
            raise exception.VolumeDeviceNotFound(device='')

        # NOTE(geguileo): If we cannot find the dm it's because all paths are
        # really bad, so we might as well raise a not found exception, but
        # in our best effort we'll return a device even if it's probably
        # useless.
        if not mpath:
            LOG.warning('No dm was created, connection to volume is probably '
                        'bad and will perform poorly.')
        elif not wwn:
            wwn = self._linuxscsi.get_sysfs_wwn(found, mpath)
        return self._get_connect_result(connection_properties, wwn, found,
                                        mpath)

    def _get_connection_devices(self, connection_properties,
                                ips_iqns_luns=None, is_disconnect_call=False):
        """Get map of devices by sessions from our connection.

        For each of the TCP sessions that correspond to our connection
        properties we generate a map of (ip, iqn) to (belong, other) where
        belong is a set of devices in that session that populated our system
        when we did a connection using connection properties, and other are
        any other devices that share that same session but are the result of
        connecting with different connection properties.

        We also include all nodes from our connection that don't have a
        session.

        If ips_iqns_luns parameter is provided connection_properties won't be
        used to get them.

        When doing multipath we may not have all the information on the
        connection properties (sendtargets was used on connect) so we may have
        to retrieve the info from the discoverydb.  Call _get_ips_iqns_luns to
        do the right things.

        This method currently assumes that it's only called by the
        _cleanup_conection method.
        """
        if not ips_iqns_luns:
            # This is a cleanup, don't do discovery
            ips_iqns_luns = self._get_ips_iqns_luns(
                connection_properties, discover=False,
                is_disconnect_call=is_disconnect_call)
        LOG.debug('Getting connected devices for (ips,iqns,luns)=%s',
                  ips_iqns_luns)
        nodes = self._get_iscsi_nodes()
        sessions = self._get_iscsi_sessions_full()
        # Use (portal, iqn) to map the session value
        sessions_map = {(s[2], s[4]): s[1] for s in sessions
                        if s[0] in self.VALID_SESSIONS_PREFIX}
        # device_map will keep a tuple with devices from the connection and
        # others that don't belong to this connection" (belong, others)
        device_map: defaultdict = defaultdict(lambda: (set(), set()))

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

        LOG.debug('Resulting device map %s', device_map)
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
        return self._cleanup_connection(connection_properties, force=force,
                                        ignore_errors=ignore_errors,
                                        device_info=device_info,
                                        is_disconnect_call=True)

    def _cleanup_connection(self, connection_properties, ips_iqns_luns=None,
                            force=False, ignore_errors=False,
                            device_info=None, is_disconnect_call=False):
        """Cleans up connection flushing and removing devices and multipath.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict that must include:
                                     target_portal(s) - IP and optional port
                                     target_iqn(s) - iSCSI Qualified Name
                                     target_lun(s) - LUN id of the volume
        :param ips_iqns_luns: Use this list of tuples instead of information
                              from the connection_properties.
        :param force: Whether to forcefully disconnect even if flush fails.
        :type force: bool
        :param ignore_errors: When force is True, this will decide whether to
                              ignore errors or raise an exception once finished
                              the operation.  Default is False.
        :param device_info: Attached device information.
        :param is_disconnect_call: Whether this is a call coming from a user
                                   disconnect_volume call or a call from some
                                   other operation's cleanup.
        :type is_disconnect_call: bool
        :type ignore_errors: bool
        """
        exc = exception.ExceptionChainer()
        try:
            devices_map = self._get_connection_devices(connection_properties,
                                                       ips_iqns_luns,
                                                       is_disconnect_call)
        except exception.TargetPortalNotFound as exc:
            # When discovery sendtargets failed on connect there is no
            # information in the discoverydb, so there's nothing to clean.
            LOG.debug('Skipping cleanup %s', exc)
            return

        # Remove devices and multipath from this connection
        remove_devices = set()
        for remove, __ in devices_map.values():
            remove_devices.update(remove)

        path_used = self._linuxscsi.get_dev_path(connection_properties,
                                                 device_info)
        was_multipath = (path_used.startswith('/dev/dm-') or
                         'mpath' in path_used)
        multipath_name = self._linuxscsi.remove_connection(
            remove_devices, force,
            exc, path_used, was_multipath)  # type: ignore

        # Disconnect sessions and remove nodes that are left without devices
        disconnect = [conn for conn, (__, keep) in devices_map.items()
                      if not keep]

        # The "type:" comment works around mypy issue #6647
        self._disconnect_connection(connection_properties, disconnect, force,
                                    exc)  # type:ignore

        # If flushing the multipath failed before, try now after we have
        # removed the devices and we may have even logged off (only reaches
        # here with multipath_name if force=True).
        if multipath_name:
            LOG.debug('Flushing again multipath %s now that we removed the '
                      'devices.', multipath_name)
            self._linuxscsi.flush_multipath_device(multipath_name)

        if exc:  # type: ignore
            LOG.warning('There were errors removing %s, leftovers may remain '
                        'in the system', remove_devices)
            if not ignore_errors:
                raise exc  # type: ignore

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

            for line in lines.split('\n'):
                if line.startswith('InitiatorName='):
                    return line[line.index('=') + 1:].strip()
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
                ips.append(data[0].split(',')[0])
                iqns.append(data[1])
        return ips, iqns

    def _connect_to_iscsi_portal(self, connection_properties):
        """Connect to an iSCSI portal-target an return the session id."""
        portal = connection_properties['target_portal'].split(",")[0]
        target_iqn = connection_properties['target_iqn']

        # NOTE(vish): If we are on the same host as nova volume, the
        #             discovery makes the target so we don't need to
        #             run --op new. Therefore, we check to see if the
        #             target exists, and if we get 255 (Not Found), then
        #             we run --op new. This will also happen if another
        #             volume is using the same target.
        # iscsiadm returns 21 for "No records found" after version 2.0-871
        LOG.info("Trying to connect to iSCSI portal %s", portal)
        out, err = self._run_iscsiadm(connection_properties, (),
                                      check_exit_code=(0, 21, 255))
        if err:
            self._run_iscsiadm(connection_properties,
                               ('--interface', self._get_transport(),
                                '--op', 'new'))
        # Try to set the scan mode to manual
        res = self._iscsiadm_update(connection_properties,
                                    'node.session.scan', 'manual',
                                    check_exit_code=False)
        manual_scan = not res[1]
        # Update global indicator of manual scan support used for
        # shared_targets locking so we support upgrading open iscsi to a
        # version supporting the manual scan feature without restarting Nova
        # or Cinder.
        initiator_utils.ISCSI_SUPPORTS_MANUAL_SCAN = manual_scan

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

        # We exit once we are logged in or once we fail login
        while True:
            # Duplicate logins crash iscsiadm after load, so we scan active
            # sessions to see if the node is logged in.
            sessions = self._get_iscsi_sessions_full()
            for s in sessions:
                # Found our session, return session_id
                if (s[0] in self.VALID_SESSIONS_PREFIX and
                        portal.lower() == s[2].lower() and s[4] == target_iqn):
                    return s[1], manual_scan

            try:
                # exit_code=15 means the session already exists, so it should
                # be regarded as successful login.
                self._run_iscsiadm(connection_properties, ("--login",),
                                   check_exit_code=(0, 15, 255))
            except putils.ProcessExecutionError as err:
                LOG.warning('Failed to login iSCSI target %(iqn)s on portal '
                            '%(portal)s (exit code %(err)s).',
                            {'iqn': target_iqn, 'portal': portal,
                             'err': err.exit_code})
                return None, None
            self._iscsiadm_update(connection_properties,
                                  "node.startup",
                                  "automatic")

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
                                             check_exit_code=[0, 21, 255])
        LOG.debug("iscsi session list stdout=%(out)s stderr=%(err)s",
                  {'out': out, 'err': err})
        return (out, err)

    def _run_iscsiadm_bare(self, iscsi_command, **kwargs) -> Tuple[str, str]:
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

    def _get_node_startup_values(self, connection_properties):
        # Exit code 21 (ISCSI_ERR_NO_OBJS_FOUND) occurs when no nodes
        # exist - must consider this an empty (successful) result.
        out, __ = self._run_iscsiadm_bare(
            ['-m', 'node', '--op', 'show', '-p',
             connection_properties['target_portal']],
            check_exit_code=(0, 21)) or ""
        node_values_str = out.strip()
        node_values = node_values_str.split("\n")
        iqn = None
        startup = None
        startup_values = {}

        for node_value in node_values:
            node_keys = node_value.split()
            try:
                if node_keys[0] == "node.name":
                    iqn = node_keys[2]
                elif node_keys[0] == "node.startup":
                    startup = node_keys[2]

                if iqn and startup:
                    startup_values[iqn] = startup
                    iqn = None
                    startup = None
            except IndexError:
                pass

        return startup_values

    def _recover_node_startup_values(self, connection_properties,
                                     old_node_startups):
        node_startups = self._get_node_startup_values(connection_properties)
        for iqn, node_startup in node_startups.items():
            old_node_startup = old_node_startups.get(iqn, None)
            if old_node_startup and node_startup != old_node_startup:
                # _iscsiadm_update() only uses "target_portal" and "target_iqn"
                # of connection_properties.
                # And the recovering target belongs to the same target_portal
                # as discovering target.
                # So target_iqn is updated, and other values aren't updated.
                recover_connection = copy.deepcopy(connection_properties)
                recover_connection['target_iqn'] = iqn
                self._iscsiadm_update(recover_connection,
                                      "node.startup",
                                      old_node_startup)
