# Copyright 2013 OpenStack Foundation.
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
""" Brick Connector objects for each supported transport protocol.

.. module: connector

The connectors here are responsible for discovering and removing volumes for
each of the supported transport protocols.
"""

import abc
import copy
import glob
import json
import os
import platform
import re
import requests
import socket
import struct
import sys
import tempfile
import time

from oslo_concurrency import lockutils
from oslo_concurrency import processutils as putils
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import importutils
from oslo_utils import strutils
import six
from six.moves import urllib

from os_brick import exception
from os_brick import executor
from os_brick import utils

from os_brick.initiator import host_driver
from os_brick.initiator import linuxfc
from os_brick.initiator import linuxrbd
from os_brick.initiator import linuxscsi
from os_brick.initiator import linuxsheepdog
from os_brick.remotefs import remotefs
from os_brick.i18n import _, _LE, _LI, _LW

LOG = logging.getLogger(__name__)

synchronized = lockutils.synchronized_with_prefix('os-brick-')
DEVICE_SCAN_ATTEMPTS_DEFAULT = 3
MULTIPATH_ERROR_REGEX = re.compile("\w{3} \d+ \d\d:\d\d:\d\d \|.*$")
MULTIPATH_DEV_CHECK_REGEX = re.compile("\s+dm-\d+\s+")
MULTIPATH_PATH_CHECK_REGEX = re.compile("\s+\d+:\d+:\d+:\d+\s+")

PLATFORM_ALL = 'ALL'
PLATFORM_x86 = 'X86'
PLATFORM_S390 = 'S390'
OS_TYPE_ALL = 'ALL'
OS_TYPE_LINUX = 'LINUX'

S390X = "s390x"
S390 = "s390"

ISCSI = "ISCSI"
ISER = "ISER"
FIBRE_CHANNEL = "FIBRE_CHANNEL"
AOE = "AOE"
DRBD = "DRBD"
NFS = "NFS"
GLUSTERFS = "GLUSTERFS"
LOCAL = "LOCAL"
HUAWEISDSHYPERVISOR = "HUAWEISDSHYPERVISOR"
HGST = "HGST"
RBD = "RBD"
SCALEIO = "SCALEIO"
SCALITY = "SCALITY"
QUOBYTE = "QUOBYTE"
DISCO = "DISCO"
VZSTORAGE = "VZSTORAGE"
SHEEPDOG = "SHEEPDOG"

connector_list = [
    'os_brick.initiator.connector.BaseLinuxConnector',
    'os_brick.initiator.connector.ISCSIConnector',
    'os_brick.initiator.connector.FibreChannelConnector',
    'os_brick.initiator.connector.FibreChannelConnectorS390X',
    'os_brick.initiator.connector.AoEConnector',
    'os_brick.initiator.connector.RemoteFsConnector',
    'os_brick.initiator.connector.RBDConnector',
    'os_brick.initiator.connector.LocalConnector',
    'os_brick.initiator.connector.DRBDConnector',
    'os_brick.initiator.connector.HuaweiStorHyperConnector',
    'os_brick.initiator.connector.HGSTConnector',
    'os_brick.initiator.connector.ScaleIOConnector',
    'os_brick.initiator.connector.DISCOConnector',
]


def get_connector_properties(root_helper, my_ip, multipath, enforce_multipath,
                             host=None):
    """Get the connection properties for all protocols.

    When the connector wants to use multipath, multipath=True should be
    specified. If enforce_multipath=True is specified too, an exception is
    thrown when multipathd is not running. Otherwise, it falls back to
    multipath=False and only the first path shown up is used.
    For the compatibility reason, even if multipath=False is specified,
    some cinder storage drivers may export the target for multipath, which
    can be found via sendtargets discovery.

    :param root_helper: The command prefix for executing as root.
    :type root_helper: str
    :param my_ip: The IP address of the local host.
    :type my_ip: str
    :param multipath: Enable multipath?
    :type multipath: bool
    :param enforce_multipath: Should we enforce that the multipath daemon is
                              running?  If the daemon isn't running then the
                              return dict will have multipath as False.
    :type enforce_multipath: bool
    :returns: dict containing all of the collected initiator values.
    """
    props = {}
    props['platform'] = platform.machine()
    props['os_type'] = sys.platform
    props['ip'] = my_ip
    props['host'] = host if host else socket.gethostname()

    for item in connector_list:
        connector = importutils.import_class(item)

        if (utils.platform_matches(props['platform'], connector.platform) and
           utils.os_matches(props['os_type'], connector.os_type)):
            LOG.debug("Fetching connector for %s" % connector.__name__)
            props = utils.merge_dict(props,
                                     connector.get_connector_properties(
                                         root_helper,
                                         host=host,
                                         multipath=multipath,
                                         enforce_multipath=enforce_multipath))

    return props


@six.add_metaclass(abc.ABCMeta)
class InitiatorConnector(executor.Executor):

    # This object can be used on any platform (x86, S390)
    platform = PLATFORM_ALL

    # This object can be used on any os type (linux, windows)
    os_type = OS_TYPE_ALL

    def __init__(self, root_helper, driver=None, execute=None,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(InitiatorConnector, self).__init__(root_helper, execute=execute,
                                                 *args, **kwargs)
        self.device_scan_attempts = device_scan_attempts

    def set_driver(self, driver):
        """The driver is used to find used LUNs."""
        self.driver = driver

    @abc.abstractmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The generic connector properties."""
        pass

    @staticmethod
    def factory(protocol, root_helper, driver=None,
                use_multipath=False,
                device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                arch=None,
                *args, **kwargs):
        """Build a Connector object based upon protocol and architecture."""

        # We do this instead of assigning it in the definition
        # to help mocking for unit tests
        if arch is None:
            arch = platform.machine()

        LOG.debug("Factory for %(protocol)s on %(arch)s",
                  {'protocol': protocol, 'arch': arch})
        protocol = protocol.upper()
        if protocol in [ISCSI, ISER]:
            # override transport kwarg for requests not comming
            # from the nova LibvirtISERVolumeDriver
            if protocol == ISER:
                kwargs.update({'transport': 'iser'})
            return ISCSIConnector(root_helper=root_helper,
                                  driver=driver,
                                  use_multipath=use_multipath,
                                  device_scan_attempts=device_scan_attempts,
                                  *args, **kwargs)
        elif protocol == FIBRE_CHANNEL:
            if arch in (S390, S390X):
                return FibreChannelConnectorS390X(
                    root_helper=root_helper,
                    driver=driver,
                    use_multipath=use_multipath,
                    device_scan_attempts=device_scan_attempts,
                    *args, **kwargs)
            else:
                return FibreChannelConnector(
                    root_helper=root_helper,
                    driver=driver,
                    use_multipath=use_multipath,
                    device_scan_attempts=device_scan_attempts,
                    *args, **kwargs)
        elif protocol == AOE:
            return AoEConnector(root_helper=root_helper,
                                driver=driver,
                                device_scan_attempts=device_scan_attempts,
                                *args, **kwargs)
        elif protocol in (NFS, GLUSTERFS, SCALITY, QUOBYTE, VZSTORAGE):
            return RemoteFsConnector(mount_type=protocol.lower(),
                                     root_helper=root_helper,
                                     driver=driver,
                                     device_scan_attempts=device_scan_attempts,
                                     *args, **kwargs)
        elif protocol == DRBD:
            return DRBDConnector(root_helper=root_helper,
                                 driver=driver,
                                 *args, **kwargs)
        elif protocol == LOCAL:
            return LocalConnector(root_helper=root_helper,
                                  driver=driver,
                                  device_scan_attempts=device_scan_attempts,
                                  *args, **kwargs)
        elif protocol == HUAWEISDSHYPERVISOR:
            return HuaweiStorHyperConnector(
                root_helper=root_helper,
                driver=driver,
                device_scan_attempts=device_scan_attempts,
                *args, **kwargs)
        elif protocol == HGST:
            return HGSTConnector(root_helper=root_helper,
                                 driver=driver,
                                 device_scan_attempts=device_scan_attempts,
                                 *args, **kwargs)
        elif protocol == RBD:
            return RBDConnector(root_helper=root_helper,
                                driver=driver,
                                device_scan_attempts=device_scan_attempts,
                                *args, **kwargs)
        elif protocol == SCALEIO:
            return ScaleIOConnector(
                root_helper=root_helper,
                driver=driver,
                device_scan_attempts=device_scan_attempts,
                *args, **kwargs)
        elif protocol == DISCO:
            return DISCOConnector(
                root_helper=root_helper,
                driver=driver,
                device_scan_attempts=device_scan_attempts,
                *args, **kwargs
            )
        elif protocol == SHEEPDOG:
            return SheepdogConnector(root_helper=root_helper,
                                     driver=driver,
                                     device_scan_attempts=device_scan_attempts,
                                     *args, **kwargs)
        else:
            msg = (_("Invalid InitiatorConnector protocol "
                     "specified %(protocol)s") %
                   dict(protocol=protocol))
            raise ValueError(msg)

    @abc.abstractmethod
    def check_valid_device(self, path, run_as_root=True):
        """Test to see if the device path is a real device.

        :param path: The file system path for the device.
        :type path: str
        :param run_as_root: run the tests as root user?
        :type run_as_root: bool
        :returns: bool
        """
        pass

    @abc.abstractmethod
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        The connection_properties describes the information needed by
        the specific protocol to use to make the connection.

        The connection_properties is a dictionary that describes the target
        volume.  It varies slightly by protocol type (iscsi, fibre_channel),
        but the structure is usually the same.


        An example for iSCSI:

        {'driver_volume_type': 'iscsi',
         'data': {
             'target_luns': [0, 2],
             'target_iqns': ['iqn.2000-05.com.3pardata:20810002ac00383d',
                             'iqn.2000-05.com.3pardata:21810002ac00383d'],
             'target_discovered': True,
             'encrypted': False,
             'qos_specs': None,
             'target_portals': ['10.52.1.11:3260', '10.52.2.11:3260'],
             'access_mode': 'rw',
        }}

        An example for fibre_channel:

        {'driver_volume_type': 'fibre_channel',
         'data': {
            'initiator_target_map': {'100010604b010459': ['21230002AC00383D'],
                                     '100010604b01045d': ['21230002AC00383D']
                                    },
            'target_discovered': True,
            'encrypted': False,
            'qos_specs': None,
            'target_lun': 1,
            'access_mode': 'rw',
            'target_wwn': [
                '20210002AC00383D',
                '20220002AC00383D',
                ],
         }}


        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """
        pass

    @abc.abstractmethod
    def disconnect_volume(self, connection_properties, device_info):
        """Disconnect a volume from the local host.

        The connection_properties are the same as from connect_volume.
        The device_info is returned from connect_volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        pass

    @abc.abstractmethod
    def get_volume_paths(self, connection_properties):
        """Return the list of existing paths for a volume.

        The job of this method is to find out what paths in
        the system are associated with a volume as described
        by the connection_properties.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        """
        pass

    @abc.abstractmethod
    def get_search_path(self):
        """Return the directory where a Connector looks for volumes.

        Some Connectors need the information in the
        connection_properties to determine the search path.
        """
        pass

    @abc.abstractmethod
    def extend_volume(self, connection_properties):
        """Update the attached volume's size.

        This method will attempt to update the local hosts's
        volume after the volume has been extended on the remote
        system.  The new volume size in bytes will be returned.
        If there is a failure to update, then None will be returned.

        :param connection_properties: The volume connection properties.
        :returns: new size of the volume.
        """
        pass

    @abc.abstractmethod
    def get_all_available_volumes(self, connection_properties=None):
        """Return all volumes that exist in the search directory.

        At connect_volume time, a Connector looks in a specific
        directory to discover a volume's paths showing up.
        This method's job is to return all paths in the directory
        that connect_volume uses to find a volume.

        This method is used in coordination with get_volume_paths()
        to verify that volumes have gone away after disconnect_volume
        has been called.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        """
        pass

    def check_IO_handle_valid(self, handle, data_type, protocol):
        """Check IO handle has correct data type."""
        if (handle and not isinstance(handle, data_type)):
            raise exception.InvalidIOHandleObject(
                protocol=protocol,
                actual_type=type(handle))


class BaseLinuxConnector(InitiatorConnector):
    os_type = OS_TYPE_LINUX

    def __init__(self, root_helper, driver=None, execute=None,
                 *args, **kwargs):
        self._linuxscsi = linuxscsi.LinuxSCSI(root_helper, execute=execute)

        if not driver:
            driver = host_driver.HostDriver()
        self.set_driver(driver)

        super(BaseLinuxConnector, self).__init__(root_helper, execute=execute,
                                                 *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The generic connector properties."""
        multipath = kwargs['multipath']
        enforce_multipath = kwargs['enforce_multipath']
        props = {}

        props['multipath'] = (multipath and
                              linuxscsi.LinuxSCSI.is_multipath_running(
                                  enforce_multipath, root_helper))

        return props

    def check_valid_device(self, path, run_as_root=True):
        cmd = ('dd', 'if=%(path)s' % {"path": path},
               'of=/dev/null', 'count=1')
        out, info = None, None
        try:
            out, info = self._execute(*cmd, run_as_root=run_as_root,
                                      root_helper=self._root_helper)
        except putils.ProcessExecutionError as e:
            LOG.error(_LE("Failed to access the device on the path "
                          "%(path)s: %(error)s %(info)s."),
                      {"path": path, "error": e.stderr,
                       "info": info})
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

    def _discover_mpath_device(self, device_wwn, connection_properties,
                               device_name):
        """This method discovers a multipath device.

        Discover a multipath device based on a defined connection_property
        and a device_wwn and return the multipath_id and path of the multipath
        enabled device if there is one.
        """

        path = self._linuxscsi.find_multipath_device_path(device_wwn)
        device_path = None
        multipath_id = None

        if path is None:
            mpath_info = self._linuxscsi.find_multipath_device(
                device_name)
            if mpath_info:
                device_path = mpath_info['device']
                multipath_id = device_wwn
            else:
                # we didn't find a multipath device.
                # so we assume the kernel only sees 1 device
                device_path = self.host_device
                LOG.debug("Unable to find multipath device name for "
                          "volume. Using path %(device)s for volume.",
                          {'device': self.host_device})
        else:
            device_path = path
            multipath_id = device_wwn
        if connection_properties.get('access_mode', '') != 'ro':
            try:
                # Sometimes the multipath devices will show up as read only
                # initially and need additional time/rescans to get to RW.
                self._linuxscsi.wait_for_rw(device_wwn, device_path)
            except exception.BlockDeviceReadOnly:
                LOG.warning(_LW('Block device %s is still read-only. '
                                'Continuing anyway.'), device_path)
        return device_path, multipath_id


class FakeConnector(BaseLinuxConnector):

    fake_path = '/dev/vdFAKE'

    def connect_volume(self, connection_properties):
        fake_device_info = {'type': 'fake',
                            'path': self.fake_path}
        return fake_device_info

    def disconnect_volume(self, connection_properties, device_info):
        pass

    def get_volume_paths(self, connection_properties):
        return [self.fake_path]

    def get_search_path(self):
        return '/dev/disk/by-path'

    def extend_volume(self, connection_properties):
        return None

    def get_all_available_volumes(self, connection_properties=None):
        return ['/dev/disk/by-path/fake-volume-1',
                '/dev/disk/by-path/fake-volume-X']


class ISCSIConnector(BaseLinuxConnector):
    """Connector class to attach/detach iSCSI volumes."""
    supported_transports = ['be2iscsi', 'bnx2i', 'cxgb3i', 'default',
                            'cxgb4i', 'qla4xxx', 'ocs', 'iser']

    def __init__(self, root_helper, driver=None,
                 execute=None, use_multipath=False,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
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
        iscsi = ISCSIConnector(root_helper=root_helper)
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

    def _get_iscsi_sessions(self):
        out, err = self._run_iscsi_session()

        iscsi_sessions = []

        if err:
            LOG.warning(_LW("Couldn't find iscsi sessions because "
                        "iscsiadm err: %s"),
                        err)
        else:
            # parse the output from iscsiadm
            # lines are in the format of
            # tcp: [1] 192.168.121.250:3260,1 iqn.2010-10.org.openstack:volume-
            lines = out.split('\n')
            for line in lines:
                if line:
                    entries = line.split()
                    portal = entries[2].split(',')
                    iscsi_sessions.append(portal[0])

        return iscsi_sessions

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
            LOG.info(_LI("Multipath discovery for iSCSI enabled"))
            # Multipath installed, discovering other targets if available
            try:
                ips_iqns = self._discover_iscsi_portals(connection_properties)
            except Exception:
                if 'target_portals' in connection_properties:
                    raise exception.TargetPortalsNotFound(
                        target_portal=connection_properties['target_portals'])
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
                all_portals = set([ip for ip, iqn in ips_iqns])
                match_portals = set([ip for ip, iqn in ips_iqns
                                     if iqn == main_iqn])
                if len(all_portals) == len(match_portals):
                    ips_iqns = zip(all_portals, [main_iqn] * len(all_portals))

            for ip, iqn in ips_iqns:
                props = copy.deepcopy(connection_properties)
                props['target_portal'] = ip
                props['target_iqn'] = iqn
                if connect_to_portal:
                    if self._connect_to_iscsi_portal(props):
                        connected_to_portal = True

            if use_rescan:
                self._rescan_iscsi()
            host_devices = self._get_device_path(connection_properties)
        else:
            LOG.info(_LI("Multipath discovery for iSCSI not enabled."))
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
                        LOG.warning(_LW(
                            'Failed to connect to iSCSI portal %(portal)s.'),
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

        LOG.warning(_LW("No useable transport found for iscsi iface %s. "
                        "Falling back to default transport."),
                    transport_iface)
        return 'default'

    def _get_transport(self):
        return self.transport

    def _iterate_all_targets(self, connection_properties):
        for ip, iqn, lun in self._get_all_targets(connection_properties):
            props = copy.deepcopy(connection_properties)
            props['target_portal'] = ip
            props['target_iqn'] = iqn
            props['target_lun'] = lun
            for key in ('target_portals', 'target_iqns', 'target_luns'):
                props.pop(key, None)
            yield props

    def _get_all_targets(self, connection_properties):
        if all([key in connection_properties for key in ('target_portals',
                                                         'target_iqns',
                                                         'target_luns')]):
            return zip(connection_properties['target_portals'],
                       connection_properties['target_iqns'],
                       connection_properties['target_luns'])

        return [(connection_properties['target_portal'],
                 connection_properties['target_iqn'],
                 connection_properties.get('target_lun', 0))]

    def _discover_iscsi_portals(self, connection_properties):
        if all([key in connection_properties for key in ('target_portals',
                                                         'target_iqns')]):
            # Use targets specified by connection_properties
            return zip(connection_properties['target_portals'],
                       connection_properties['target_iqns'])

        out = None
        if connection_properties.get('discovery_auth_method'):
            try:
                self._run_iscsiadm_update_discoverydb(connection_properties)
            except putils.ProcessExecutionError as exception:
                # iscsiadm returns 6 for "db record not found"
                if exception.exit_code == 6:
                    # Create a new record for this target and update the db
                    self._run_iscsiadm_bare(
                        ['-m', 'discoverydb',
                         '-t', 'sendtargets',
                         '-p', connection_properties['target_portal'],
                         '--op', 'new'],
                        check_exit_code=[0, 255])
                    self._run_iscsiadm_update_discoverydb(
                        connection_properties
                    )
                else:
                    LOG.error(_LE("Unable to find target portal: "
                                  "%(target_portal)s."),
                              {'target_portal': connection_properties[
                                  'target_portal']})
                    raise
            out = self._run_iscsiadm_bare(
                ['-m', 'discoverydb',
                 '-t', 'sendtargets',
                 '-p', connection_properties['target_portal'],
                 '--discover'],
                check_exit_code=[0, 255])[0] or ""
        else:
            out = self._run_iscsiadm_bare(
                ['-m', 'discovery',
                 '-t', 'sendtargets',
                 '-p', connection_properties['target_portal']],
                check_exit_code=[0, 255])[0] or ""

        return self._get_target_portals_from_iscsiadm_output(out)

    def _run_iscsiadm_update_discoverydb(self, connection_properties):
        return self._execute(
            'iscsiadm',
            '-m', 'discoverydb',
            '-t', 'sendtargets',
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

    @synchronized('extend_volume')
    def extend_volume(self, connection_properties):
        """Update the local kernel's size information.

        Try and update the local kernel's size information
        for an iSCSI volume.
        """
        LOG.info(_LI("Extend volume for %s"), connection_properties)

        volume_paths = self.get_volume_paths(connection_properties)
        LOG.info(_LI("Found paths for volume %s"), volume_paths)
        if volume_paths:
            return self._linuxscsi.extend_volume(volume_paths[0])
        else:
            LOG.warning(_LW("Couldn't find any volume paths on the host to "
                            "extend volume for %(props)s"),
                        {'props': connection_properties})
            raise exception.VolumePathsNotFound()

    @synchronized('connect_volume')
    def connect_volume(self, connection_properties):
        """Attach the volume to instance_name.

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

        host_devices, target_props = self._get_potential_volume_paths(
            connection_properties)

        # The /dev/disk/by-path/... node is not always present immediately
        # TODO(justinsb): This retry-with-delay is a pattern, move to utils?
        tries = 0
        # Loop until at least 1 path becomes available
        while all(map(lambda x: not os.path.exists(x), host_devices)):
            if tries >= self.device_scan_attempts:
                raise exception.VolumeDeviceNotFound(device=host_devices)

            LOG.warning(_LW("ISCSI volume not yet found at: %(host_devices)s. "
                            "Will rescan & retry.  Try number: %(tries)s."),
                        {'host_devices': host_devices,
                         'tries': tries})

            # The rescan isn't documented as being necessary(?), but it helps
            if self.use_multipath:
                self._rescan_iscsi()
            else:
                if (tries):
                    host_devices = self._get_device_path(target_props)
                self._run_iscsiadm(target_props, ("--rescan",))

            tries = tries + 1
            if all(map(lambda x: not os.path.exists(x), host_devices)):
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

    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info):
        """Detach the volume from instance_name.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict

        connection_properties for iSCSI must include:
        target_portal(s) - IP and optional port
        target_iqn(s) - iSCSI Qualified Name
        target_lun(s) - LUN id of the volume
        """
        if self.use_multipath:
            self._rescan_multipath()
            host_device = multipath_device = None
            host_devices = self._get_device_path(connection_properties)
            # Choose an accessible host device
            for dev in host_devices:
                if os.path.exists(dev):
                    host_device = dev
                    device_wwn = self._linuxscsi.get_scsi_wwn(dev)
                    (multipath_device, multipath_id) = (super(
                        ISCSIConnector, self)._discover_mpath_device(
                            device_wwn, connection_properties, dev))
                    if multipath_device:
                        break
            if not host_device:
                LOG.error(_LE("No accessible volume device: %(host_devices)s"),
                          {'host_devices': host_devices})
                raise exception.VolumeDeviceNotFound(device=host_devices)

            if multipath_device:
                device_realpath = os.path.realpath(host_device)
                self._linuxscsi.remove_multipath_device(device_realpath)
                return self._disconnect_volume_multipath_iscsi(
                    connection_properties, multipath_device)

        # When multiple portals/iqns/luns are specified, we need to remove
        # unused devices created by logging into other LUNs' session.
        for props in self._iterate_all_targets(connection_properties):
            self._disconnect_volume_iscsi(props)

    def _disconnect_volume_iscsi(self, connection_properties):
        # remove the device from the scsi subsystem
        # this eliminates any stale entries until logout
        host_devices = self._get_device_path(connection_properties)

        if host_devices:
            host_device = host_devices[0]
        else:
            return

        dev_name = self._linuxscsi.get_name_from_path(host_device)
        if dev_name:
            self._linuxscsi.remove_scsi_device(dev_name)

            # NOTE(jdg): On busy systems we can have a race here
            # where remove_iscsi_device is called before the device file
            # has actually been removed.   The result is an orphaned
            # iscsi session that never gets logged out.  The following
            # call to wait addresses that issue.
            self._linuxscsi.wait_for_volume_removal(host_device)

        # NOTE(vish): Only disconnect from the target if no luns from the
        #             target are in use.
        device_byname = ("ip-%(portal)s-iscsi-%(iqn)s-lun-" %
                         {'portal': connection_properties['target_portal'],
                          'iqn': connection_properties['target_iqn']})
        devices = self.driver.get_all_block_devices()
        devices = [dev for dev in devices if (device_byname in dev
                                              and
                                              dev.startswith(
                                                  '/dev/disk/by-path/'))
                   and os.path.exists(dev)]
        if not devices:
            self._disconnect_from_iscsi_portal(connection_properties)

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
            # /dev/disk/by-path/pci-XXXX:XX:XX.X-ip-PORTAL:PORT-iscsi-IQN-lun-LUN_ID
            device_list = []
            for x in self._get_all_targets(connection_properties):
                look_for_device = glob.glob('/dev/disk/by-path/*ip-%s-iscsi-%s-lun-%s'  # noqa
                                            % self._munge_portal(x))
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
            LOG.warning(_LW("Could not find the iSCSI Initiator File %s"),
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
        # return both portals and iqns
        #
        # as we are parsing a command line utility, allow for the
        # possibility that additional debug data is spewed in the
        # stream, and only grab actual ip / iqn lines.
        targets = []
        for data in [line.split() for line in output.splitlines()]:
            if len(data) == 2 and data[1].startswith('iqn.'):
                targets.append(data)
        return targets

    def _disconnect_volume_multipath_iscsi(self, connection_properties,
                                           multipath_name):
        """This removes a multipath device and it's LUNs."""
        LOG.debug("Disconnect multipath device %s", multipath_name)
        mpath_map = self._get_multipath_device_map()
        block_devices = self.driver.get_all_block_devices()
        devices = []
        for dev in block_devices:
            if os.path.exists(dev):
                if "/mapper/" in dev:
                    devices.append(dev)
                else:
                    mpdev = mpath_map.get(dev)
                    if mpdev:
                        devices.append(mpdev)

        # Do a discovery to find all targets.
        # Targets for multiple paths for the same multipath device
        # may not be the same.
        all_ips_iqns = self._discover_iscsi_portals(connection_properties)

        # As discovery result may contain other targets' iqns, extract targets
        # to be disconnected whose block devices are already deleted here.
        ips_iqns = []
        entries = [device.lstrip('ip-').split('-lun-')[0]
                   for device in self._get_iscsi_devices()]
        for ip, iqn in all_ips_iqns:
            ip_iqn = "%s-iscsi-%s" % (ip.split(",")[0], iqn)
            if ip_iqn not in entries:
                ips_iqns.append([ip, iqn])

        if not devices:
            # disconnect if no other multipath devices
            self._disconnect_mpath(connection_properties, ips_iqns)
            return

        # Get a target for all other multipath devices
        other_iqns = self._get_multipath_iqns(devices, mpath_map)

        # Get all the targets for the current multipath device
        current_iqns = [iqn for ip, iqn in ips_iqns]

        in_use = False
        for current in current_iqns:
            if current in other_iqns:
                in_use = True
                break

        # If no other multipath device attached has the same iqn
        # as the current device
        if not in_use:
            # disconnect if no other multipath devices with same iqn
            self._disconnect_mpath(connection_properties, ips_iqns)
            return

        # else do not disconnect iscsi portals,
        # as they are used for other luns
        return

    def _connect_to_iscsi_portal(self, connection_properties):
        # NOTE(vish): If we are on the same host as nova volume, the
        #             discovery makes the target so we don't need to
        #             run --op new. Therefore, we check to see if the
        #             target exists, and if we get 255 (Not Found), then
        #             we run --op new. This will also happen if another
        #             volume is using the same target.
        LOG.info(_LI("Trying to connect to iSCSI portal %(portal)s"),
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
                    LOG.warning(_LW('Failed to login iSCSI target %(iqn)s '
                                    'on portal %(portal)s (exit code '
                                    '%(err)s).'),
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

    def _get_iscsi_devices(self):
        try:
            devices = list(os.walk('/dev/disk/by-path'))[0][-1]
        except IndexError:
            return []
        # For iSCSI HBAs, look at an offset of len('pci-0000:00:00.0')
        return [entry for entry in devices if (entry.startswith("ip-")
                                               or (entry.startswith("pci-")
                                                   and
                                                   entry.find("ip-", 16, 21)
                                                   >= 16))]

    def _disconnect_mpath(self, connection_properties, ips_iqns):
        for ip, iqn in ips_iqns:
            props = copy.deepcopy(connection_properties)
            props['target_portal'] = ip
            props['target_iqn'] = iqn
            self._disconnect_from_iscsi_portal(props)

        self._rescan_multipath()

    def _get_multipath_iqns(self, multipath_devices, mpath_map):
        entries = self._get_iscsi_devices()
        iqns = []
        for entry in entries:
            entry_real_path = os.path.realpath("/dev/disk/by-path/%s" % entry)
            entry_multipath = mpath_map.get(entry_real_path)
            if entry_multipath and entry_multipath in multipath_devices:
                iqns.append(entry.split("iscsi-")[1].split("-lun")[0])
        return iqns

    def _get_multipath_device_map(self):
        out = self._run_multipath(['-ll'], check_exit_code=[0, 1])[0]
        mpath_line = [line for line in out.splitlines()
                      if not re.match(MULTIPATH_ERROR_REGEX, line)]
        mpath_dev = None
        mpath_map = {}
        for line in out.splitlines():
            m = MULTIPATH_DEV_CHECK_REGEX.split(line)
            if len(m) >= 2:
                mpath_dev = '/dev/mapper/' + m[0].split(" ")[0]
                continue
            m = MULTIPATH_PATH_CHECK_REGEX.split(line)
            if len(m) >= 2:
                mpath_map['/dev/' + m[1].split(" ")[0]] = mpath_dev

        if mpath_line and not mpath_map:
            LOG.warning(_LW("Failed to parse the output of multipath -ll. "
                            "stdout: %s"), out)
        return mpath_map

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

    def _rescan_iscsi(self):
        self._run_iscsiadm_bare(('-m', 'node', '--rescan'),
                                check_exit_code=[0, 1, 21, 255])
        self._run_iscsiadm_bare(('-m', 'session', '--rescan'),
                                check_exit_code=[0, 1, 21, 255])

    def _rescan_multipath(self):
        self._run_multipath(['-r'], check_exit_code=[0, 1, 21])


class FibreChannelConnector(BaseLinuxConnector):
    """Connector class to attach/detach Fibre Channel volumes."""

    def __init__(self, root_helper, driver=None,
                 execute=None, use_multipath=False,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        self._linuxfc = linuxfc.LinuxFibreChannel(root_helper, execute)
        super(FibreChannelConnector, self).__init__(
            root_helper, driver=driver,
            execute=execute,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)
        self.use_multipath = use_multipath

    def set_execute(self, execute):
        super(FibreChannelConnector, self).set_execute(execute)
        self._linuxscsi.set_execute(execute)
        self._linuxfc.set_execute(execute)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The Fibre Channel connector properties."""
        props = {}
        fc = linuxfc.LinuxFibreChannel(root_helper)

        wwpns = fc.get_fc_wwpns()
        if wwpns:
            props['wwpns'] = wwpns
        wwnns = fc.get_fc_wwnns()
        if wwnns:
            props['wwnns'] = wwnns

        return props

    def get_search_path(self):
        """Where do we look for FC based volumes."""
        return '/dev/disk/by-path'

    def _get_possible_volume_paths(self, connection_properties, hbas):
        ports = connection_properties['target_wwn']
        possible_devs = self._get_possible_devices(hbas, ports)

        lun = connection_properties.get('target_lun', 0)
        host_paths = self._get_host_devices(possible_devs, lun)
        return host_paths

    def get_volume_paths(self, connection_properties):
        volume_paths = []
        # first fetch all of the potential paths that might exist
        # how the FC fabric is zoned may alter the actual list
        # that shows up on the system.  So, we verify each path.
        hbas = self._linuxfc.get_fc_hbas_info()
        device_paths = self._get_possible_volume_paths(
            connection_properties, hbas)
        for path in device_paths:
            if os.path.exists(path):
                volume_paths.append(path)

        return volume_paths

    @synchronized('extend_volume')
    def extend_volume(self, connection_properties):
        """Update the local kernel's size information.

        Try and update the local kernel's size information
        for an FC volume.
        """
        volume_paths = self.get_volume_paths(connection_properties)
        if volume_paths:
            return self._linuxscsi.extend_volume(volume_paths[0])
        else:
            LOG.warning(_LW("Couldn't find any volume paths on the host to "
                            "extend volume for %(props)s"),
                        {'props': connection_properties})
            raise exception.VolumePathsNotFound()

    @synchronized('connect_volume')
    def connect_volume(self, connection_properties):
        """Attach the volume to instance_name.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict

        connection_properties for Fibre Channel must include:
        target_wwn - World Wide Name
        target_lun - LUN id of the volume
        """
        LOG.debug("execute = %s", self._execute)
        device_info = {'type': 'block'}

        hbas = self._linuxfc.get_fc_hbas_info()
        host_devices = self._get_possible_volume_paths(
            connection_properties, hbas)

        if len(host_devices) == 0:
            # this is empty because we don't have any FC HBAs
            LOG.warning(
                _LW("We are unable to locate any Fibre Channel devices"))
            raise exception.NoFibreChannelHostsFound()

        # The /dev/disk/by-path/... node is not always present immediately
        # We only need to find the first device.  Once we see the first device
        # multipath will have any others.
        def _wait_for_device_discovery(host_devices):
            tries = self.tries
            for device in host_devices:
                LOG.debug("Looking for Fibre Channel dev %(device)s",
                          {'device': device})
                if os.path.exists(device):
                    self.host_device = device
                    # get the /dev/sdX device.  This is used
                    # to find the multipath device.
                    self.device_name = os.path.realpath(device)
                    raise loopingcall.LoopingCallDone()

            if self.tries >= self.device_scan_attempts:
                LOG.error(_LE("Fibre Channel volume device not found."))
                raise exception.NoFibreChannelVolumeDeviceFound()

            LOG.warning(_LW("Fibre Channel volume device not yet found. "
                            "Will rescan & retry.  Try number: %(tries)s."),
                        {'tries': tries})

            self._linuxfc.rescan_hosts(hbas)
            self.tries = self.tries + 1

        self.host_device = None
        self.device_name = None
        self.tries = 0
        timer = loopingcall.FixedIntervalLoopingCall(
            _wait_for_device_discovery, host_devices)
        timer.start(interval=2).wait()

        tries = self.tries
        if self.host_device is not None and self.device_name is not None:
            LOG.debug("Found Fibre Channel volume %(name)s "
                      "(after %(tries)s rescans)",
                      {'name': self.device_name, 'tries': tries})

        # find out the WWN of the device
        device_wwn = self._linuxscsi.get_scsi_wwn(self.host_device)
        LOG.debug("Device WWN = '%(wwn)s'", {'wwn': device_wwn})
        device_info['scsi_wwn'] = device_wwn

        # see if the new drive is part of a multipath
        # device.  If so, we'll use the multipath device.
        if self.use_multipath:
            (device_path, multipath_id) = (super(
                FibreChannelConnector, self)._discover_mpath_device(
                device_wwn, connection_properties, self.device_name))
            if multipath_id:
                # only set the multipath_id if we found one
                device_info['multipath_id'] = multipath_id

        else:
            device_path = self.host_device

        device_info['path'] = device_path
        LOG.debug("connect_volume returning %s", device_info)
        return device_info

    def _get_host_devices(self, possible_devs, lun):
        host_devices = []
        for pci_num, target_wwn in possible_devs:
            host_device = "/dev/disk/by-path/pci-%s-fc-%s-lun-%s" % (
                pci_num,
                target_wwn,
                self._linuxscsi.process_lun_id(lun))
            host_devices.append(host_device)
        return host_devices

    def _get_possible_devices(self, hbas, wwnports):
        """Compute the possible fibre channel device options.

        :param hbas: available hba devices.
        :param wwnports: possible wwn addresses. Can either be string
        or list of strings.

        :returns: list of (pci_id, wwn) tuples

        Given one or more wwn (mac addresses for fibre channel) ports
        do the matrix math to figure out a set of pci device, wwn
        tuples that are potentially valid (they won't all be). This
        provides a search space for the device connection.

        """
        # the wwn (think mac addresses for fiber channel devices) can
        # either be a single value or a list. Normalize it to a list
        # for further operations.
        wwns = []
        if isinstance(wwnports, list):
            for wwn in wwnports:
                wwns.append(str(wwn))
        elif isinstance(wwnports, six.string_types):
            wwns.append(str(wwnports))

        raw_devices = []
        for hba in hbas:
            pci_num = self._get_pci_num(hba)
            if pci_num is not None:
                for wwn in wwns:
                    target_wwn = "0x%s" % wwn.lower()
                    raw_devices.append((pci_num, target_wwn))
        return raw_devices

    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info):
        """Detach the volume from instance_name.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict

        connection_properties for Fibre Channel must include:
        target_wwn - World Wide Name
        target_lun - LUN id of the volume
        """

        devices = []
        volume_paths = self.get_volume_paths(connection_properties)
        wwn = None
        for path in volume_paths:
            real_path = self._linuxscsi.get_name_from_path(path)
            if not wwn:
                wwn = self._linuxscsi.get_scsi_wwn(path)
            device_info = self._linuxscsi.get_device_info(real_path)
            devices.append(device_info)

        LOG.debug("devices to remove = %s", devices)
        self._remove_devices(connection_properties, devices)

        if self.use_multipath:
            # There is a bug in multipath where the flushing
            # doesn't remove the entry if friendly names are on
            # we'll try anyway.
            self._linuxscsi.flush_multipath_device(wwn)

    def _remove_devices(self, connection_properties, devices):
        # There may have been more than 1 device mounted
        # by the kernel for this volume.  We have to remove
        # all of them
        for device in devices:
            self._linuxscsi.remove_scsi_device(device["device"])

    def _get_pci_num(self, hba):
        # NOTE(walter-boring)
        # device path is in format of (FC and FCoE) :
        # /sys/devices/pci0000:00/0000:00:03.0/0000:05:00.3/host2/fc_host/host2
        # /sys/devices/pci0000:20/0000:20:03.0/0000:21:00.2/net/ens2f2/ctlr_2
        # /host3/fc_host/host3
        # we always want the value prior to the host or net value
        if hba is not None:
            if "device_path" in hba:
                device_path = hba['device_path'].split('/')
                for index, value in enumerate(device_path):
                    if value.startswith('net') or value.startswith('host'):
                        return device_path[index - 1]
        return None


class FibreChannelConnectorS390X(FibreChannelConnector):
    """Connector class to attach/detach Fibre Channel volumes on S390X arch."""
    platform = PLATFORM_S390

    def __init__(self, root_helper, driver=None,
                 execute=None, use_multipath=False,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
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

    def _get_host_devices(self, possible_devs, lun):
        host_devices = []
        for pci_num, target_wwn in possible_devs:
            target_lun = self._get_lun_string(lun)
            host_device = self._get_device_file_path(
                pci_num,
                target_wwn,
                target_lun)
            self._linuxfc.configure_scsi_device(pci_num, target_wwn,
                                                target_lun)
            host_devices.append(host_device)
        return host_devices

    def _get_lun_string(self, lun):
        target_lun = 0
        if lun <= 0xffff:
            target_lun = "0x%04x000000000000" % lun
        elif lun <= 0xffffffff:
            target_lun = "0x%08x00000000" % lun
        return target_lun

    def _get_device_file_path(self, pci_num, target_wwn, target_lun):
        host_device = "/dev/disk/by-path/ccw-%s-zfcp-%s:%s" % (
            pci_num,
            target_wwn,
            target_lun)
        return host_device

    def _remove_devices(self, connection_properties, devices):
        hbas = self._linuxfc.get_fc_hbas_info()
        ports = connection_properties['target_wwn']
        possible_devs = self._get_possible_devices(hbas, ports)
        lun = connection_properties.get('target_lun', 0)
        target_lun = self._get_lun_string(lun)
        for pci_num, target_wwn in possible_devs:
            self._linuxfc.deconfigure_scsi_device(pci_num,
                                                  target_wwn,
                                                  target_lun)


class AoEConnector(BaseLinuxConnector):
    """Connector class to attach/detach AoE volumes."""

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(AoEConnector, self).__init__(
            root_helper,
            driver=driver,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The AoE connector properties."""
        return {}

    def get_search_path(self):
        return '/dev/etherd'

    def get_volume_paths(self, connection_properties):
        aoe_device, aoe_path = self._get_aoe_info(connection_properties)
        volume_paths = []
        if os.path.exists(aoe_path):
            volume_paths.append(aoe_path)

        return volume_paths

    def _get_aoe_info(self, connection_properties):
        shelf = connection_properties['target_shelf']
        lun = connection_properties['target_lun']
        aoe_device = 'e%(shelf)s.%(lun)s' % {'shelf': shelf,
                                             'lun': lun}
        path = self.get_search_path()
        aoe_path = '%(path)s/%(device)s' % {'path': path,
                                            'device': aoe_device}
        return aoe_device, aoe_path

    @lockutils.synchronized('aoe_control', 'aoe-')
    def connect_volume(self, connection_properties):
        """Discover and attach the volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict

        connection_properties for AoE must include:
        target_shelf - shelf id of volume
        target_lun - lun id of volume
        """
        aoe_device, aoe_path = self._get_aoe_info(connection_properties)

        device_info = {
            'type': 'block',
            'device': aoe_device,
            'path': aoe_path,
        }

        if os.path.exists(aoe_path):
            self._aoe_revalidate(aoe_device)
        else:
            self._aoe_discover()

        waiting_status = {'tries': 0}

        # NOTE(jbr_): Device path is not always present immediately
        def _wait_for_discovery(aoe_path):
            if os.path.exists(aoe_path):
                raise loopingcall.LoopingCallDone

            if waiting_status['tries'] >= self.device_scan_attempts:
                raise exception.VolumeDeviceNotFound(device=aoe_path)

            LOG.warning(_LW("AoE volume not yet found at: %(path)s. "
                            "Try number: %(tries)s"),
                        {'path': aoe_device,
                         'tries': waiting_status['tries']})

            self._aoe_discover()
            waiting_status['tries'] += 1

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_discovery,
                                                     aoe_path)
        timer.start(interval=2).wait()

        if waiting_status['tries']:
            LOG.debug("Found AoE device %(path)s "
                      "(after %(tries)s rediscover)",
                      {'path': aoe_path,
                       'tries': waiting_status['tries']})

        return device_info

    @lockutils.synchronized('aoe_control', 'aoe-')
    def disconnect_volume(self, connection_properties, device_info):
        """Detach and flush the volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict

        connection_properties for AoE must include:
        target_shelf - shelf id of volume
        target_lun - lun id of volume
        """
        aoe_device, aoe_path = self._get_aoe_info(connection_properties)

        if os.path.exists(aoe_path):
            self._aoe_flush(aoe_device)

    def _aoe_discover(self):
        (out, err) = self._execute('aoe-discover',
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=0)

        LOG.debug('aoe-discover: stdout=%(out)s stderr%(err)s',
                  {'out': out, 'err': err})

    def _aoe_revalidate(self, aoe_device):
        (out, err) = self._execute('aoe-revalidate',
                                   aoe_device,
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=0)

        LOG.debug('aoe-revalidate %(dev)s: stdout=%(out)s stderr%(err)s',
                  {'dev': aoe_device, 'out': out, 'err': err})

    def _aoe_flush(self, aoe_device):
        (out, err) = self._execute('aoe-flush',
                                   aoe_device,
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=0)
        LOG.debug('aoe-flush %(dev)s: stdout=%(out)s stderr%(err)s',
                  {'dev': aoe_device, 'out': out, 'err': err})

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class RemoteFsConnector(BaseLinuxConnector):
    """Connector class to attach/detach NFS and GlusterFS volumes."""

    def __init__(self, mount_type, root_helper, driver=None,
                 execute=None,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        kwargs = kwargs or {}
        conn = kwargs.get('conn')
        mount_type_lower = mount_type.lower()
        if conn:
            mount_point_base = conn.get('mount_point_base')
            if mount_type_lower in ('nfs', 'glusterfs', 'scality',
                                    'quobyte', 'vzstorage'):
                kwargs[mount_type_lower + '_mount_point_base'] = (
                    kwargs.get(mount_type_lower + '_mount_point_base') or
                    mount_point_base)
        else:
            LOG.warning(_LW("Connection details not present."
                            " RemoteFsClient may not initialize properly."))

        if mount_type_lower == 'scality':
            cls = remotefs.ScalityRemoteFsClient
        else:
            cls = remotefs.RemoteFsClient
        self._remotefsclient = cls(mount_type, root_helper, execute=execute,
                                   *args, **kwargs)

        super(RemoteFsConnector, self).__init__(
            root_helper, driver=driver,
            execute=execute,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The RemoteFS connector properties."""
        return {}

    def set_execute(self, execute):
        super(RemoteFsConnector, self).set_execute(execute)
        self._remotefsclient.set_execute(execute)

    def get_search_path(self):
        return self._remotefsclient.get_mount_base()

    def _get_volume_path(self, connection_properties):
        mnt_flags = []
        if connection_properties.get('options'):
            mnt_flags = connection_properties['options'].split()

        nfs_share = connection_properties['export']
        self._remotefsclient.mount(nfs_share, mnt_flags)
        mount_point = self._remotefsclient.get_mount_point(nfs_share)
        path = mount_point + '/' + connection_properties['name']
        return path

    def get_volume_paths(self, connection_properties):
        path = self._get_volume_path(connection_properties)
        return [path]

    def connect_volume(self, connection_properties):
        """Ensure that the filesystem containing the volume is mounted.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
             connection_properties must include:
             export - remote filesystem device (e.g. '172.18.194.100:/var/nfs')
             name - file name within the filesystem
        :type connection_properties: dict
        :returns: dict


        connection_properties may optionally include:
        options - options to pass to mount
        """
        path = self._get_volume_path(connection_properties)
        return {'path': path}

    def disconnect_volume(self, connection_properties, device_info):
        """No need to do anything to disconnect a volume in a filesystem.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class RBDConnector(BaseLinuxConnector):
    """"Connector class to attach/detach RBD volumes."""

    def __init__(self, root_helper, driver=None, use_multipath=False,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):

        super(RBDConnector, self).__init__(root_helper, driver=driver,
                                           device_scan_attempts=
                                           device_scan_attempts,
                                           *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The RBD connector properties."""
        return {}

    def get_volume_paths(self, connection_properties):
        # TODO(walter-boring): don't know where the connector
        # looks for RBD volumes.
        return []

    def get_search_path(self):
        # TODO(walter-boring): don't know where the connector
        # looks for RBD volumes.
        return None

    def get_all_available_volumes(self, connection_properties=None):
        # TODO(walter-boring): not sure what to return here for RBD
        return []

    def _get_rbd_handle(self, connection_properties):
        try:
            user = connection_properties['auth_username']
            pool, volume = connection_properties['name'].split('/')
        except IndexError:
            msg = _("Connect volume failed, malformed connection properties")
            raise exception.BrickException(msg=msg)

        rbd_client = linuxrbd.RBDClient(user, pool)
        rbd_volume = linuxrbd.RBDVolume(rbd_client, volume)
        rbd_handle = linuxrbd.RBDVolumeIOWrapper(rbd_volume)
        return rbd_handle

    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """

        rbd_handle = self._get_rbd_handle(connection_properties)
        return {'path': rbd_handle}

    def disconnect_volume(self, connection_properties, device_info):
        """Disconnect a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        if device_info:
            rbd_handle = device_info.get('path', None)
            if rbd_handle is not None:
                rbd_handle.close()

    def check_valid_device(self, path, run_as_root=True):
        """Verify an existing RBD handle is connected and valid."""
        rbd_handle = path

        if rbd_handle is None:
            return False

        original_offset = rbd_handle.tell()

        try:
            rbd_handle.read(4096)
        except Exception as e:
            LOG.error(_LE("Failed to access RBD device handle: %(error)s"),
                      {"error": e})
            return False
        finally:
            rbd_handle.seek(original_offset, 0)

        return True

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class LocalConnector(BaseLinuxConnector):
    """"Connector class to attach/detach File System backed volumes."""

    def __init__(self, root_helper, driver=None,
                 *args, **kwargs):
        super(LocalConnector, self).__init__(root_helper, driver=driver,
                                             *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The Local connector properties."""
        return {}

    def get_volume_paths(self, connection_properties):
        path = connection_properties['device_path']
        return [path]

    def get_search_path(self):
        return None

    def get_all_available_volumes(self, connection_properties=None):
        # TODO(walter-boring): not sure what to return here.
        return []

    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
               connection_properties must include:
               device_path - path to the volume to be connected
        :type connection_properties: dict
        :returns: dict
        """
        if 'device_path' not in connection_properties:
            msg = (_("Invalid connection_properties specified "
                     "no device_path attribute"))
            raise ValueError(msg)

        device_info = {'type': 'local',
                       'path': connection_properties['device_path']}
        return device_info

    def disconnect_volume(self, connection_properties, device_info):
        """Disconnect a volume from the local host.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        pass

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class DRBDConnector(BaseLinuxConnector):
    """"Connector class to attach/detach DRBD resources."""

    def __init__(self, root_helper, driver=None,
                 execute=putils.execute, *args, **kwargs):

        super(DRBDConnector, self).__init__(root_helper, driver=driver,
                                            execute=execute, *args, **kwargs)

        self._execute = execute
        self._root_helper = root_helper

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The DRBD connector properties."""
        return {}

    def check_valid_device(self, path, run_as_root=True):
        """Verify an existing volume."""
        # TODO(linbit): check via drbdsetup first, to avoid blocking/hanging
        # in case of network problems?

        return super(DRBDConnector, self).check_valid_device(path, run_as_root)

    def get_all_available_volumes(self, connection_properties=None):

        base = "/dev/"
        blkdev_list = []

        for e in os.listdir(base):
            path = base + e
            if os.path.isblk(path):
                blkdev_list.append(path)

        return blkdev_list

    def _drbdadm_command(self, cmd, data_dict, sh_secret):
        # TODO(linbit): Write that resource file to a permanent location?
        tmp = tempfile.NamedTemporaryFile(suffix="res", delete=False, mode="w")
        try:
            kv = {'shared-secret': sh_secret}
            tmp.write(data_dict['config'] % kv)
            tmp.close()

            (out, err) = self._execute('drbdadm', cmd,
                                       "-c", tmp.name,
                                       data_dict['name'],
                                       run_as_root=True,
                                       root_helper=self._root_helper)
        finally:
            os.unlink(tmp.name)

        return (out, err)

    def connect_volume(self, connection_properties):
        """Attach the volume."""

        self._drbdadm_command("adjust", connection_properties,
                              connection_properties['provider_auth'])

        device_info = {
            'type': 'block',
            'path': connection_properties['device'],
        }

        return device_info

    def disconnect_volume(self, connection_properties, device_info):
        """Detach the volume."""

        self._drbdadm_command("down", connection_properties,
                              connection_properties['provider_auth'])

    def get_volume_paths(self, connection_properties):
        path = connection_properties['device']
        return [path]

    def get_search_path(self):
        # TODO(linbit): is it allowed to return "/dev", or is that too broad?
        return None

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class HuaweiStorHyperConnector(BaseLinuxConnector):
    """"Connector class to attach/detach SDSHypervisor volumes."""

    attached_success_code = 0
    has_been_attached_code = 50151401
    attach_mnid_done_code = 50151405
    vbs_unnormal_code = 50151209
    not_mount_node_code = 50155007
    iscliexist = True

    def __init__(self, root_helper, driver=None,
                 *args, **kwargs):
        self.cli_path = os.getenv('HUAWEISDSHYPERVISORCLI_PATH')
        if not self.cli_path:
            self.cli_path = '/usr/local/bin/sds/sds_cli'
            LOG.debug("CLI path is not configured, using default %s.",
                      self.cli_path)
        if not os.path.isfile(self.cli_path):
            self.iscliexist = False
            LOG.error(_LE('SDS CLI file not found, '
                          'HuaweiStorHyperConnector init failed.'))
        super(HuaweiStorHyperConnector, self).__init__(root_helper,
                                                       driver=driver,
                                                       *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The HuaweiStor connector properties."""
        return {}

    def get_search_path(self):
        # TODO(walter-boring): Where is the location on the filesystem to
        # look for Huawei volumes to show up?
        return None

    def get_all_available_volumes(self, connection_properties=None):
        # TODO(walter-boring): what to return here for all Huawei volumes ?
        return []

    def get_volume_paths(self, connection_properties):
        volume_path = None
        try:
            volume_path = self._get_volume_path(connection_properties)
        except Exception:
            msg = _("Couldn't find a volume.")
            LOG.warning(msg)
            raise exception.BrickException(message=msg)
        return [volume_path]

    def _get_volume_path(self, connection_properties):
        out = self._query_attached_volume(
            connection_properties['volume_id'])
        if not out or int(out['ret_code']) != 0:
            msg = _("Couldn't find attached volume.")
            LOG.error(msg)
            raise exception.BrickException(message=msg)
        return out['dev_addr']

    @synchronized('connect_volume')
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """
        LOG.debug("Connect_volume connection properties: %s.",
                  connection_properties)
        out = self._attach_volume(connection_properties['volume_id'])
        if not out or int(out['ret_code']) not in (self.attached_success_code,
                                                   self.has_been_attached_code,
                                                   self.attach_mnid_done_code):
            msg = (_("Attach volume failed, "
                   "error code is %s") % out['ret_code'])
            raise exception.BrickException(message=msg)

        try:
            volume_path = self._get_volume_path(connection_properties)
        except Exception:
            msg = _("query attached volume failed or volume not attached.")
            LOG.error(msg)
            raise exception.BrickException(message=msg)

        device_info = {'type': 'block',
                       'path': volume_path}
        return device_info

    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info):
        """Disconnect a volume from the local host.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        LOG.debug("Disconnect_volume: %s.", connection_properties)
        out = self._detach_volume(connection_properties['volume_id'])
        if not out or int(out['ret_code']) not in (self.attached_success_code,
                                                   self.vbs_unnormal_code,
                                                   self.not_mount_node_code):
            msg = (_("Disconnect_volume failed, "
                   "error code is %s") % out['ret_code'])
            raise exception.BrickException(message=msg)

    def is_volume_connected(self, volume_name):
        """Check if volume already connected to host"""
        LOG.debug('Check if volume %s already connected to a host.',
                  volume_name)
        out = self._query_attached_volume(volume_name)
        if out:
            return int(out['ret_code']) == 0
        return False

    def _attach_volume(self, volume_name):
        return self._cli_cmd('attach', volume_name)

    def _detach_volume(self, volume_name):
        return self._cli_cmd('detach', volume_name)

    def _query_attached_volume(self, volume_name):
        return self._cli_cmd('querydev', volume_name)

    def _cli_cmd(self, method, volume_name):
        LOG.debug("Enter into _cli_cmd.")
        if not self.iscliexist:
            msg = _("SDS command line doesn't exist, "
                    "can't execute SDS command.")
            raise exception.BrickException(message=msg)
        if not method or volume_name is None:
            return
        cmd = [self.cli_path, '-c', method, '-v', volume_name]
        out, clilog = self._execute(*cmd, run_as_root=False,
                                    root_helper=self._root_helper)
        analyse_result = self._analyze_output(out)
        LOG.debug('%(method)s volume returns %(analyse_result)s.',
                  {'method': method, 'analyse_result': analyse_result})
        if clilog:
            LOG.error(_LE("SDS CLI output some log: %s."), clilog)
        return analyse_result

    def _analyze_output(self, out):
        LOG.debug("Enter into _analyze_output.")
        if out:
            analyse_result = {}
            out_temp = out.split('\n')
            for line in out_temp:
                LOG.debug("Line is %s.", line)
                if line.find('=') != -1:
                    key, val = line.split('=', 1)
                    LOG.debug("%(key)s = %(val)s", {'key': key, 'val': val})
                    if key in ['ret_code', 'ret_desc', 'dev_addr']:
                        analyse_result[key] = val
            return analyse_result
        else:
            return None

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class HGSTConnector(BaseLinuxConnector):
    """Connector class to attach/detach HGST volumes."""

    VGCCLUSTER = 'vgc-cluster'

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(HGSTConnector, self).__init__(root_helper, driver=driver,
                                            device_scan_attempts=
                                            device_scan_attempts,
                                            *args, **kwargs)
        self._vgc_host = None

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The HGST connector properties."""
        return {}

    def _log_cli_err(self, err):
        """Dumps the full command output to a logfile in error cases."""
        LOG.error(_LE("CLI fail: '%(cmd)s' = %(code)s\nout: %(stdout)s\n"
                      "err: %(stderr)s"),
                  {'cmd': err.cmd, 'code': err.exit_code,
                   'stdout': err.stdout, 'stderr': err.stderr})

    def _find_vgc_host(self):
        """Finds vgc-cluster hostname for this box."""
        params = [self.VGCCLUSTER, "domain-list", "-1"]
        try:
            out, unused = self._execute(*params, run_as_root=True,
                                        root_helper=self._root_helper)
        except putils.ProcessExecutionError as err:
            self._log_cli_err(err)
            msg = _("Unable to get list of domain members, check that "
                    "the cluster is running.")
            raise exception.BrickException(message=msg)
        domain = out.splitlines()
        params = ["ip", "addr", "list"]
        try:
            out, unused = self._execute(*params, run_as_root=False)
        except putils.ProcessExecutionError as err:
            self._log_cli_err(err)
            msg = _("Unable to get list of IP addresses on this host, "
                    "check permissions and networking.")
            raise exception.BrickException(message=msg)
        nets = out.splitlines()
        for host in domain:
            try:
                ip = socket.gethostbyname(host)
                for l in nets:
                    x = l.strip()
                    if x.startswith("inet %s/" % ip):
                        return host
            except socket.error:
                pass
        msg = _("Current host isn't part of HGST domain.")
        raise exception.BrickException(message=msg)

    def _hostname(self):
        """Returns hostname to use for cluster operations on this box."""
        if self._vgc_host is None:
            self._vgc_host = self._find_vgc_host()
        return self._vgc_host

    def get_search_path(self):
        return "/dev"

    def get_volume_paths(self, connection_properties):
        path = ("%(path)s/%(name)s" %
                {'path': self.get_search_path(),
                 'name': connection_properties['name']})
        volume_path = None
        if os.path.exists(path):
            volume_path = path
        return [volume_path]

    def connect_volume(self, connection_properties):
        """Attach a Space volume to running host.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
            connection_properties for HGST must include:
            name - Name of space to attach
        :type connection_properties: dict
        :returns: dict
        """
        if connection_properties is None:
            msg = _("Connection properties passed in as None.")
            raise exception.BrickException(message=msg)
        if 'name' not in connection_properties:
            msg = _("Connection properties missing 'name' field.")
            raise exception.BrickException(message=msg)
        device_info = {
            'type': 'block',
            'device': connection_properties['name'],
            'path': '/dev/' + connection_properties['name']
        }
        volname = device_info['device']
        params = [self.VGCCLUSTER, 'space-set-apphosts']
        params += ['-n', volname]
        params += ['-A', self._hostname()]
        params += ['--action', 'ADD']
        try:
            self._execute(*params, run_as_root=True,
                          root_helper=self._root_helper)
        except putils.ProcessExecutionError as err:
            self._log_cli_err(err)
            msg = (_("Unable to set apphost for space %s") % volname)
            raise exception.BrickException(message=msg)

        return device_info

    def disconnect_volume(self, connection_properties, device_info):
        """Detach and flush the volume.

        :param connection_properties: The dictionary that describes all
               of the target volume attributes.
               For HGST must include:
               name - Name of space to detach
               noremovehost - Host which should never be removed
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        if connection_properties is None:
            msg = _("Connection properties passed in as None.")
            raise exception.BrickException(message=msg)
        if 'name' not in connection_properties:
            msg = _("Connection properties missing 'name' field.")
            raise exception.BrickException(message=msg)
        if 'noremovehost' not in connection_properties:
            msg = _("Connection properties missing 'noremovehost' field.")
            raise exception.BrickException(message=msg)
        if connection_properties['noremovehost'] != self._hostname():
            params = [self.VGCCLUSTER, 'space-set-apphosts']
            params += ['-n', connection_properties['name']]
            params += ['-A', self._hostname()]
            params += ['--action', 'DELETE']
            try:
                self._execute(*params, run_as_root=True,
                              root_helper=self._root_helper)
            except putils.ProcessExecutionError as err:
                self._log_cli_err(err)
                msg = (_("Unable to set apphost for space %s") %
                       connection_properties['name'])
                raise exception.BrickException(message=msg)

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class ScaleIOConnector(BaseLinuxConnector):
    """Class implements the connector driver for ScaleIO."""

    OK_STATUS_CODE = 200
    VOLUME_NOT_MAPPED_ERROR = 84
    VOLUME_ALREADY_MAPPED_ERROR = 81
    GET_GUID_CMD = ['/opt/emc/scaleio/sdc/bin/drv_cfg', '--query_guid']

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(ScaleIOConnector, self).__init__(
            root_helper,
            driver=driver,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs
        )

        self.local_sdc_ip = None
        self.server_ip = None
        self.server_port = None
        self.server_username = None
        self.server_password = None
        self.server_token = None
        self.volume_id = None
        self.volume_name = None
        self.volume_path = None
        self.iops_limit = None
        self.bandwidth_limit = None

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The ScaleIO connector properties."""
        return {}

    def get_search_path(self):
        return "/dev/disk/by-id"

    def get_volume_paths(self, connection_properties):
        self.get_config(connection_properties)
        volume_paths = []
        device_paths = [self._find_volume_path()]
        for path in device_paths:
            if os.path.exists(path):
                volume_paths.append(path)
        return volume_paths

    def _find_volume_path(self):
        LOG.info(_LI(
            "Looking for volume %(volume_id)s, maximum tries: %(tries)s"),
            {'volume_id': self.volume_id, 'tries': self.device_scan_attempts}
        )

        # look for the volume in /dev/disk/by-id directory
        by_id_path = self.get_search_path()

        disk_filename = self._wait_for_volume_path(by_id_path)
        full_disk_name = ("%(path)s/%(filename)s" %
                          {'path': by_id_path, 'filename': disk_filename})
        LOG.info(_LI("Full disk name is %(full_path)s"),
                 {'full_path': full_disk_name})
        return full_disk_name

    # NOTE: Usually 3 retries is enough to find the volume.
    # If there are network issues, it could take much longer. Set
    # the max retries to 15 to make sure we can find the volume.
    @utils.retry(exceptions=exception.BrickException,
                 retries=15,
                 backoff_rate=1)
    def _wait_for_volume_path(self, path):
        if not os.path.isdir(path):
            msg = (
                _("ScaleIO volume %(volume_id)s not found at "
                  "expected path.") % {'volume_id': self.volume_id}
                )

            LOG.debug(msg)
            raise exception.BrickException(message=msg)

        disk_filename = None
        filenames = os.listdir(path)
        LOG.info(_LI(
            "Files found in %(path)s path: %(files)s "),
            {'path': path, 'files': filenames}
        )

        for filename in filenames:
            if (filename.startswith("emc-vol") and
                    filename.endswith(self.volume_id)):
                disk_filename = filename
                break

        if not disk_filename:
            msg = (_("ScaleIO volume %(volume_id)s not found.") %
                   {'volume_id': self.volume_id})
            LOG.debug(msg)
            raise exception.BrickException(message=msg)

        return disk_filename

    def _get_client_id(self):
        request = (
            "https://%(server_ip)s:%(server_port)s/"
            "api/types/Client/instances/getByIp::%(sdc_ip)s/" %
            {
                'server_ip': self.server_ip,
                'server_port': self.server_port,
                'sdc_ip': self.local_sdc_ip
            }
        )

        LOG.info(_LI("ScaleIO get client id by ip request: %(request)s"),
                 {'request': request})

        r = requests.get(
            request,
            auth=(self.server_username, self.server_token),
            verify=False
        )

        r = self._check_response(r, request)
        sdc_id = r.json()
        if not sdc_id:
            msg = (_("Client with ip %(sdc_ip)s was not found.") %
                   {'sdc_ip': self.local_sdc_ip})
            raise exception.BrickException(message=msg)

        if r.status_code != 200 and "errorCode" in sdc_id:
            msg = (_("Error getting sdc id from ip %(sdc_ip)s: %(err)s") %
                   {'sdc_ip': self.local_sdc_ip, 'err': sdc_id['message']})

            LOG.error(msg)
            raise exception.BrickException(message=msg)

        LOG.info(_LI("ScaleIO sdc id is %(sdc_id)s."),
                 {'sdc_id': sdc_id})
        return sdc_id

    def _get_volume_id(self):
        volname_encoded = urllib.parse.quote(self.volume_name, '')
        volname_double_encoded = urllib.parse.quote(volname_encoded, '')
        LOG.debug(_(
            "Volume name after double encoding is %(volume_name)s."),
            {'volume_name': volname_double_encoded}
        )

        request = (
            "https://%(server_ip)s:%(server_port)s/api/types/Volume/instances"
            "/getByName::%(encoded_volume_name)s" %
            {
                'server_ip': self.server_ip,
                'server_port': self.server_port,
                'encoded_volume_name': volname_double_encoded
            }
        )

        LOG.info(
            _LI("ScaleIO get volume id by name request: %(request)s"),
            {'request': request}
        )

        r = requests.get(request,
                         auth=(self.server_username, self.server_token),
                         verify=False)

        r = self._check_response(r, request)

        volume_id = r.json()
        if not volume_id:
            msg = (_("Volume with name %(volume_name)s wasn't found.") %
                   {'volume_name': self.volume_name})

            LOG.error(msg)
            raise exception.BrickException(message=msg)

        if r.status_code != self.OK_STATUS_CODE and "errorCode" in volume_id:
            msg = (
                _("Error getting volume id from name %(volume_name)s: "
                  "%(err)s") %
                {'volume_name': self.volume_name, 'err': volume_id['message']}
            )

            LOG.error(msg)
            raise exception.BrickException(message=msg)

        LOG.info(_LI("ScaleIO volume id is %(volume_id)s."),
                 {'volume_id': volume_id})
        return volume_id

    def _check_response(self, response, request, is_get_request=True,
                        params=None):
        if response.status_code == 401 or response.status_code == 403:
            LOG.info(_LI("Token is invalid, "
                         "going to re-login to get a new one"))

            login_request = (
                "https://%(server_ip)s:%(server_port)s/api/login" %
                {'server_ip': self.server_ip, 'server_port': self.server_port}
            )

            r = requests.get(
                login_request,
                auth=(self.server_username, self.server_password),
                verify=False
            )

            token = r.json()
            # repeat request with valid token
            LOG.debug(_("Going to perform request %(request)s again "
                        "with valid token"), {'request': request})

            if is_get_request:
                res = requests.get(request,
                                   auth=(self.server_username, token),
                                   verify=False)
            else:
                headers = {'content-type': 'application/json'}
                res = requests.post(
                    request,
                    data=json.dumps(params),
                    headers=headers,
                    auth=(self.server_username, token),
                    verify=False
                )

            self.server_token = token
            return res

        return response

    def get_config(self, connection_properties):
        self.local_sdc_ip = connection_properties['hostIP']
        self.volume_name = connection_properties['scaleIO_volname']
        self.server_ip = connection_properties['serverIP']
        self.server_port = connection_properties['serverPort']
        self.server_username = connection_properties['serverUsername']
        self.server_password = connection_properties['serverPassword']
        self.server_token = connection_properties['serverToken']
        self.iops_limit = connection_properties['iopsLimit']
        self.bandwidth_limit = connection_properties['bandwidthLimit']
        device_info = {'type': 'block',
                       'path': self.volume_path}
        return device_info

    @lockutils.synchronized('scaleio', 'scaleio-')
    def connect_volume(self, connection_properties):
        """Connect the volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """
        device_info = self.get_config(connection_properties)
        LOG.debug(
            _(
                "scaleIO Volume name: %(volume_name)s, SDC IP: %(sdc_ip)s, "
                "REST Server IP: %(server_ip)s, "
                "REST Server username: %(username)s, "
                "iops limit:%(iops_limit)s, "
                "bandwidth limit: %(bandwidth_limit)s."
            ), {
                'volume_name': self.volume_name,
                'sdc_ip': self.local_sdc_ip,
                'server_ip': self.server_ip,
                'username': self.server_username,
                'iops_limit': self.iops_limit,
                'bandwidth_limit': self.bandwidth_limit
            }
        )

        LOG.info(_LI("ScaleIO sdc query guid command: %(cmd)s"),
                 {'cmd': self.GET_GUID_CMD})

        try:
            (out, err) = self._execute(*self.GET_GUID_CMD, run_as_root=True,
                                       root_helper=self._root_helper)

            LOG.info(_LI("Map volume %(cmd)s: stdout=%(out)s "
                         "stderr=%(err)s"),
                     {'cmd': self.GET_GUID_CMD, 'out': out, 'err': err})

        except putils.ProcessExecutionError as e:
            msg = (_("Error querying sdc guid: %(err)s") % {'err': e.stderr})
            LOG.error(msg)
            raise exception.BrickException(message=msg)

        guid = out
        LOG.info(_LI("Current sdc guid: %(guid)s"), {'guid': guid})
        params = {'guid': guid, 'allowMultipleMappings': 'TRUE'}
        self.volume_id = self._get_volume_id()

        headers = {'content-type': 'application/json'}
        request = (
            "https://%(server_ip)s:%(server_port)s/api/instances/"
            "Volume::%(volume_id)s/action/addMappedSdc" %
            {'server_ip': self.server_ip, 'server_port': self.server_port,
             'volume_id': self.volume_id}
        )

        LOG.info(_LI("map volume request: %(request)s"), {'request': request})
        r = requests.post(
            request,
            data=json.dumps(params),
            headers=headers,
            auth=(self.server_username, self.server_token),
            verify=False
        )

        r = self._check_response(r, request, False, params)
        if r.status_code != self.OK_STATUS_CODE:
            response = r.json()
            error_code = response['errorCode']
            if error_code == self.VOLUME_ALREADY_MAPPED_ERROR:
                LOG.warning(_LW(
                    "Ignoring error mapping volume %(volume_name)s: "
                    "volume already mapped."),
                    {'volume_name': self.volume_name}
                )
            else:
                msg = (
                    _("Error mapping volume %(volume_name)s: %(err)s") %
                    {'volume_name': self.volume_name,
                     'err': response['message']}
                )

                LOG.error(msg)
                raise exception.BrickException(message=msg)

        self.volume_path = self._find_volume_path()
        device_info['path'] = self.volume_path

        # Set QoS settings after map was performed
        if self.iops_limit is not None or self.bandwidth_limit is not None:
            params = {'guid': guid}
            if self.bandwidth_limit is not None:
                params['bandwidthLimitInKbps'] = self.bandwidth_limit
            if self.iops_limit is not None:
                params['iopsLimit'] = self.iops_limit

            request = (
                "https://%(server_ip)s:%(server_port)s/api/instances/"
                "Volume::%(volume_id)s/action/setMappedSdcLimits" %
                {'server_ip': self.server_ip, 'server_port': self.server_port,
                 'volume_id': self.volume_id}
            )

            LOG.info(_LI("Set client limit request: %(request)s"),
                     {'request': request})

            r = requests.post(
                request,
                data=json.dumps(params),
                headers=headers,
                auth=(self.server_username, self.server_token),
                verify=False
            )
            r = self._check_response(r, request, False, params)
            if r.status_code != self.OK_STATUS_CODE:
                response = r.json()
                LOG.info(_LI("Set client limit response: %(response)s"),
                         {'response': response})
                msg = (
                    _("Error setting client limits for volume "
                      "%(volume_name)s: %(err)s") %
                    {'volume_name': self.volume_name,
                     'err': response['message']}
                )

                LOG.error(msg)

        return device_info

    @lockutils.synchronized('scaleio', 'scaleio-')
    def disconnect_volume(self, connection_properties, device_info):
        """Disconnect the ScaleIO volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        self.get_config(connection_properties)
        self.volume_id = self._get_volume_id()
        LOG.info(_LI(
            "ScaleIO disconnect volume in ScaleIO brick volume driver."
        ))

        LOG.debug(
            _("ScaleIO Volume name: %(volume_name)s, SDC IP: %(sdc_ip)s, "
              "REST Server IP: %(server_ip)s"),
            {'volume_name': self.volume_name, 'sdc_ip': self.local_sdc_ip,
             'server_ip': self.server_ip}
        )

        LOG.info(_LI("ScaleIO sdc query guid command: %(cmd)s"),
                 {'cmd': self.GET_GUID_CMD})

        try:
            (out, err) = self._execute(*self.GET_GUID_CMD, run_as_root=True,
                                       root_helper=self._root_helper)
            LOG.info(
                _LI("Unmap volume %(cmd)s: stdout=%(out)s stderr=%(err)s"),
                {'cmd': self.GET_GUID_CMD, 'out': out, 'err': err}
            )

        except putils.ProcessExecutionError as e:
            msg = _("Error querying sdc guid: %(err)s") % {'err': e.stderr}
            LOG.error(msg)
            raise exception.BrickException(message=msg)

        guid = out
        LOG.info(_LI("Current sdc guid: %(guid)s"), {'guid': guid})

        params = {'guid': guid}
        headers = {'content-type': 'application/json'}
        request = (
            "https://%(server_ip)s:%(server_port)s/api/instances/"
            "Volume::%(volume_id)s/action/removeMappedSdc" %
            {'server_ip': self.server_ip, 'server_port': self.server_port,
             'volume_id': self.volume_id}
        )

        LOG.info(_LI("Unmap volume request: %(request)s"),
                 {'request': request})
        r = requests.post(
            request,
            data=json.dumps(params),
            headers=headers,
            auth=(self.server_username, self.server_token),
            verify=False
        )

        r = self._check_response(r, request, False, params)
        if r.status_code != self.OK_STATUS_CODE:
            response = r.json()
            error_code = response['errorCode']
            if error_code == self.VOLUME_NOT_MAPPED_ERROR:
                LOG.warning(_LW(
                    "Ignoring error unmapping volume %(volume_id)s: "
                    "volume not mapped."), {'volume_id': self.volume_name}
                )
            else:
                msg = (_("Error unmapping volume %(volume_id)s: %(err)s") %
                       {'volume_id': self.volume_name,
                        'err': response['message']})
                LOG.error(msg)
                raise exception.BrickException(message=msg)

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError


class DISCOConnector(BaseLinuxConnector):
    """Class implements the connector driver for DISCO."""

    DISCO_PREFIX = 'dms'

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        """Init DISCO connector."""
        super(DISCOConnector, self).__init__(
            root_helper,
            driver=driver,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs
        )
        LOG.info(_LI("Init DISCO connector"))

        self.server_port = None
        self.server_ip = None

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The DISCO connector properties."""
        return {}

    def get_search_path(self):
        """Get directory path where to get DISCO volumes."""
        return "/dev"

    def get_volume_paths(self, connection_properties):
        """Get config for DISCO volume driver."""
        self.get_config(connection_properties)
        volume_paths = []
        disco_id = connection_properties['disco_id']
        disco_dev = '/dev/dms%s' % (disco_id)
        device_paths = [disco_dev]
        for path in device_paths:
            if os.path.exists(path):
                volume_paths.append(path)
        return volume_paths

    def get_all_available_volumes(self, connection_properties=None):
        """Return all DISCO volumes that exist in the search directory."""
        path = self.get_search_path()

        if os.path.isdir(path):
            path_items = [path, '/', self.DISCO_PREFIX, '*']
            file_filter = ''.join(path_items)
            return glob.glob(file_filter)
        else:
            return []

    def get_config(self, connection_properties):
        """Get config for DISCO volume driver."""
        self.server_port = (
            six.text_type(connection_properties['conf']['server_port']))
        self.server_ip = (
            six.text_type(connection_properties['conf']['server_ip']))

        disco_id = connection_properties['disco_id']
        disco_dev = '/dev/dms%s' % (disco_id)
        device_info = {'type': 'block',
                       'path': disco_dev}
        return device_info

    @synchronized('connect_volume')
    def connect_volume(self, connection_properties):
        """Connect the volume. Returns xml for libvirt."""
        LOG.debug("Enter in DISCO connect_volume")
        device_info = self.get_config(connection_properties)
        LOG.debug("Device info : %s.", device_info)
        disco_id = connection_properties['disco_id']
        disco_dev = '/dev/dms%s' % (disco_id)
        LOG.debug("Attaching %s", disco_dev)

        self._mount_disco_volume(disco_dev, disco_id)
        return device_info

    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info):
        """Detach the volume from instance."""
        disco_id = connection_properties['disco_id']
        disco_dev = '/dev/dms%s' % (disco_id)
        LOG.debug("detaching %s", disco_dev)

        if os.path.exists(disco_dev):
            ret = self._send_disco_vol_cmd(self.server_ip,
                                           self.server_port,
                                           2,
                                           disco_id)
            if ret is not None:
                msg = _("Detach volume failed")
                raise exception.BrickException(message=msg)
        else:
            LOG.info(_LI("Volume already detached from host"))

    def _mount_disco_volume(self, path, volume_id):
        """Send request to mount volume on physical host."""
        LOG.debug("Enter in mount disco volume %(port)s "
                  "and %(ip)s." %
                  {'port': self.server_port,
                   'ip': self.server_ip})

        if not os.path.exists(path):
            ret = self._send_disco_vol_cmd(self.server_ip,
                                           self.server_port,
                                           1,
                                           volume_id)
            if ret is not None:
                msg = _("Attach volume failed")
                raise exception.BrickException(message=msg)
        else:
            LOG.info(_LI("Volume already attached to host"))

    def _connect_tcp_socket(self, client_ip, client_port):
        """Connect to TCP socket."""
        sock = None

        for res in socket.getaddrinfo(client_ip,
                                      client_port,
                                      socket.AF_UNSPEC,
                                      socket.SOCK_STREAM):
                aff, socktype, proto, canonname, saa = res
                try:
                    sock = socket.socket(aff, socktype, proto)
                except socket.error:
                    sock = None
                    continue
                try:
                    sock.connect(saa)
                except socket.error:
                    sock.close()
                    sock = None
                    continue
                break

        if sock is None:
            LOG.error(_LE("Cannot connect TCP socket"))
        return sock

    def _send_disco_vol_cmd(self, client_ip, client_port, op_code, vol_id):
        """Send DISCO client socket command."""
        s = self._connect_tcp_socket(client_ip, int(client_port))

        if s is not None:
            inst_id = 'DEFAULT-INSTID'
            pktlen = 2 + 8 + len(inst_id)
            LOG.debug("pktlen=%(plen)s op=%(op)s "
                      "vol_id=%(vol_id)s, inst_id=%(inst_id)s",
                      {'plen': pktlen, 'op': op_code,
                       'vol_id': vol_id, 'inst_id': inst_id})
            data = struct.pack("!HHQ14s",
                               pktlen,
                               op_code,
                               int(vol_id),
                               inst_id)
            s.sendall(data)
            ret = s.recv(4)
            s.close()

            LOG.debug("Received ret len=%(lenR)d, ret=%(ret)s",
                      {'lenR': len(repr(ret)), 'ret': repr(ret)})

            ret_val = "".join("%02x" % ord(c) for c in ret)

            if ret_val != '00000000':
                return 'ERROR'
        return None

    def extend_volume(self, connection_properties):
        raise NotImplementedError


class SheepdogConnector(BaseLinuxConnector):
    """"Connector class to attach/detach sheepdog volumes."""

    def __init__(self, root_helper, driver=None, use_multipath=False,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):

        super(SheepdogConnector, self).__init__(root_helper, driver=driver,
                                                device_scan_attempts=
                                                device_scan_attempts,
                                                *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The Sheepdog connector properties."""
        return {}

    def get_volume_paths(self, connection_properties):
        # TODO(lixiaoy1): don't know where the connector
        # looks for sheepdog volumes.
        return []

    def get_search_path(self):
        # TODO(lixiaoy1): don't know where the connector
        # looks for sheepdog volumes.
        return None

    def get_all_available_volumes(self, connection_properties=None):
        # TODO(lixiaoy1): not sure what to return here for sheepdog
        return []

    def _get_sheepdog_handle(self, connection_properties):
        try:
            host = connection_properties['hosts'][0]
            name = connection_properties['name']
            port = connection_properties['ports'][0]
        except IndexError:
            msg = _("Connect volume failed, malformed connection properties")
            raise exception.BrickException(msg=msg)

        sheepdog_handle = linuxsheepdog.SheepdogVolumeIOWrapper(
            host, port, name)
        return sheepdog_handle

    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """

        sheepdog_handle = self._get_sheepdog_handle(connection_properties)
        return {'path': sheepdog_handle}

    def disconnect_volume(self, connection_properties, device_info):
        """Disconnect a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        if device_info:
            sheepdog_handle = device_info.get('path', None)
            self.check_IO_handle_valid(sheepdog_handle,
                                       linuxsheepdog.SheepdogVolumeIOWrapper,
                                       'Sheepdog')
            if sheepdog_handle is not None:
                sheepdog_handle.close()

    def check_valid_device(self, path, run_as_root=True):
        """Verify an existing sheepdog handle is connected and valid."""
        sheepdog_handle = path

        if sheepdog_handle is None:
            return False

        original_offset = sheepdog_handle.tell()

        try:
            sheepdog_handle.read(4096)
        except Exception as e:
            LOG.error(_LE("Failed to access sheepdog device "
                          "handle: %(error)s"),
                      {"error": e})
            return False
        finally:
            sheepdog_handle.seek(original_offset, 0)

        return True

    def extend_volume(self, connection_properties):
        # TODO(lixiaoy1): is this possible?
        raise NotImplementedError
