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

# Look in the NVMeOFConnProps class docstring to see the format of the NVMe-oF
# connection properties

from __future__ import annotations

import errno
import functools
import glob
import json
import os.path
import time
from typing import (Callable, Optional, Sequence, Type, Union)  # noqa: H301
import uuid as uuid_lib

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator.connectors import base
try:
    from os_brick.initiator.connectors import nvmeof_agent
except ImportError:
    nvmeof_agent = None
from os_brick.privileged import nvmeof as priv_nvmeof
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick import utils

DEV_SEARCH_PATH = '/dev/'
RAID_PATH = '/dev/md/'
NVME_CTRL_SYSFS_PATH = '/sys/class/nvme-fabrics/ctl/'
BLK_SYSFS_PATH = '/sys/class/block/'

DEVICE_SCAN_ATTEMPTS_DEFAULT = 5

LOG = logging.getLogger(__name__)


# #########################################################
# CONNECTION PROPERTIES KEYS start

# Only present in the old connection info format
OLD_NQN = 'nqn'
TRANSPORT = 'transport_type'
PORTAL = 'target_portal'
PORT = 'target_port'

# These were only present in the old connection info, but now we'll allow
# both in the old format, the new format, and as part of a volume_replicas
# element.
NGUID = 'volume_nguid'
NSID = 'ns_id'
HOST_NQN = 'host_nqn'

# Present in the new new connection info format
UUID = 'vol_uuid'
NQN = 'target_nqn'
PORTALS = 'portals'
ALIAS = 'alias'
REPLICAS = 'volume_replicas'
REPLICA_COUNT = 'replica_count'

# CONNECTION PROPERTIES KEYS end
# #########################################################


# #########################################################
# UTILITY METHODS start

def ctrl_property(prop_name: str, ctrl_name: str) -> Optional[str]:
    """Get a sysfs property of an nvme controller."""
    return sysfs_property(prop_name, NVME_CTRL_SYSFS_PATH + ctrl_name)


def blk_property(prop_name: str, blk_name: str) -> Optional[str]:
    """Get a sysfs property of a block device."""
    return sysfs_property(prop_name, BLK_SYSFS_PATH + blk_name)


def sysfs_property(prop_name: str, path_or_name: str) -> Optional[str]:
    """Get sysfs property by path returning None if not possible."""
    filename = os.path.join(path_or_name, prop_name)
    LOG.debug('Checking property at %s', filename)
    try:
        with open(filename, 'r') as f:
            result = f.read().strip()
            LOG.debug('Contents: %s', result)
            return result

    except (FileNotFoundError, IOError) as exc:
        # May happens on race conditions with device removals
        LOG.debug('Error reading file %s', exc)
        return None


def nvme_basename(path: str) -> str:
    """Convert a sysfs control path into a namespace device.

    We can have a basic namespace devices such as nvme0n10 which is already in
    the desired form, but there's also channels when ANA is enabled on the
    kernel which have the form nvme0c2n10 which need to be converted to
    nvme0n10 to get the actual device.
    """
    basename = os.path.basename(path)
    if 'c' not in basename:  # nvme0n10
        return basename

    # nvme0c1n10 ==> nvme0n10
    ctrl, rest = basename.split('c', 1)
    ns = rest[rest.index('n'):]
    return ctrl + ns

# UTILITY METHODS end
# #########################################################


# #########################################################
# AUXILIARY CLASSES start

class Portal(object):
    """Representation of an NVMe-oF Portal with some related operations."""
    LIVE = 'live'
    MISSING = None  # Unkown or not present in the system
    CONNECTING = 'connecting'
    # Default value of reconnect_delay in sysfs
    DEFAULT_RECONNECT_DELAY = 10
    controller: Optional[str] = None  # Don't know controller name on start

    def __str__(self) -> str:
        return (f'Portal {self.transport} at {self.address}:{self.port} '
                f'(ctrl: {self.controller})')

    __repr__ = __str__

    def __init__(self,
                 parent_target: 'Target',
                 address: str,
                 port: Union[str, int],
                 transport: str) -> None:
        self.parent_target = parent_target
        self.address = address
        self.port = str(port)

        # Convert the transport into our internal representation
        if transport in ('RoCEv2', 'rdma'):
            self.transport = 'rdma'
        else:
            self.transport = 'tcp'

    @property
    def is_live(self) -> bool:
        """Check if the portal is live.

        Not being live can mean many things, such as being connecting because
        the connection to the backend was lost, not knowing the controller name
        because we haven't searched for it, or not being connected to the
        backend.
        """
        LOG.debug('Checking if %s is live', self)
        return self.state == self.LIVE

    @property
    def state(self) -> Optional[str]:
        """Return the state if the controller is known, None otherwise."""
        # Does not automatically search for the controller
        if self.controller:
            return ctrl_property('state', self.controller)
        return None

    @property
    def reconnect_delay(self) -> int:
        # 10 seconds is the default value of reconnect_delay
        if self.controller:
            res = ctrl_property('reconnect_delay', self.controller)
            if res is not None:
                return int(res)
        return self.DEFAULT_RECONNECT_DELAY

    def get_device(self) -> Optional[str]:
        """Get a device path using available volume identification markers.

        Priority is given to the uuid, since that must be unique across ALL
        devices, then nguid which is backend specific but a backend can reuse
        in other connections after it has been disconnected, and then using
        the namespace id (nsid) which changes based on the subsystem and the
        moment the volume is connected.

        If the target in the connection information didn't have any of those
        identifiers, then let the parent Target instance try to figure out the
        device based on the devices that existed when we started connecting and
        the ones available now.

        None is returned when a device cannot be found.
        """
        target = self.parent_target
        if target.uuid:
            return self.get_device_by_property('uuid', target.uuid)

        if target.nguid:
            return self.get_device_by_property('nguid', target.nguid)

        if target.ns_id:
            return self.get_device_by_property('nsid', target.ns_id)

        # Fallback to using the target to do the search
        LOG.warning('Using unreliable mechanism to find device: '
                    '"devices_on_start"')
        return target.get_device_path_by_initial_devices()

    def get_all_namespaces_ctrl_paths(self) -> list[str]:
        """Return all nvme sysfs control paths for this portal.

        The basename of the path can be single volume or a channel to an ANA
        volume.

        For example for the nvme1 controller we could return:

            ['/sys/class/nvme-fabrics/ctl/nvme1n1 ',
             '/sys/class/nvme-fabrics/ctl/nvme0c1n1']
        """
        if not self.controller:
            return []
        # Look under the controller, where we will have normal devices and ANA
        # channel devices. For nvme1 we could find nvme1n1 or nvme0c1n1)
        return glob.glob(f'{NVME_CTRL_SYSFS_PATH}{self.controller}/nvme*')

    def get_device_by_property(self,
                               prop_name: str,
                               value: str) -> Optional[str]:
        """Look for a specific device (namespace) within a controller.

        Use a specific property to identify the namespace within the
        controller and returns the device path under /dev.

        Returns None if device is not found.
        """
        LOG.debug('Looking for device where %s=%s on controller %s',
                  prop_name, value, self.controller)

        for path in self.get_all_namespaces_ctrl_paths():
            prop_value = sysfs_property(prop_name, path)
            if prop_value == value:
                # Convert path to the namespace device name
                result = DEV_SEARCH_PATH + nvme_basename(path)
                LOG.debug('Device found at %s, using %s', path, result)
                return result

            LOG.debug('Block %s is not the one we are looking for (%s != %s)',
                      path, prop_value, value)

        LOG.debug('No device Found on controller %s', self.controller)
        return None

    def can_disconnect(self) -> bool:
        """Check if this portal can be disconnected.

        A portal can be disconnected if it is connected (has a controller name)
        and the subsystem has no namespaces left or if it has only one and it
        is from this target.
        """
        if not self.controller:
            LOG.debug('Portal %s is not present', self)
            return False

        ns_ctrl_paths = self.get_all_namespaces_ctrl_paths()
        num_namespaces = len(ns_ctrl_paths)
        # No namespaces => disconnect, >1 ns => can't disconnect
        if num_namespaces != 1:
            result = not bool(num_namespaces)
            LOG.debug('There are %s namespaces on %s so we %s disconnect',
                      num_namespaces, self, 'can' if result else 'cannot')
            return result

        # With only 1 namespace, check if it belongs to the portal
        # Get the device on this target's portal (may be None)
        portal_dev = os.path.basename(self.get_device() or '')
        result = portal_dev == nvme_basename(ns_ctrl_paths[0])
        LOG.debug("The only namespace on portal %s is %s and %s this target's",
                  self, portal_dev, "matches" if result else "doesn't match")
        return result


class Target(object):
    """Representation of an NVMe-oF Target and some related operations."""
    # Only used if the target has no uuid, nguid, or ns_id information
    devices_on_start = None
    # Cache the device we find for cases where we do retries
    _device = None

    def __str__(self) -> str:
        return f'Target {self.nqn} at {self.portals}'

    __repr__ = __str__

    @classmethod
    def factory(cls: Type['Target'],
                source_conn_props: 'NVMeOFConnProps',
                target_nqn: str,
                portals: list[str],
                vol_uuid: Optional[str] = None,
                volume_nguid: Optional[str] = None,
                ns_id: Optional[str] = None,
                host_nqn: Optional[str] = None,
                find_controllers=False,
                **ignore) -> 'Target':
        """Create an instance from the connection properties keys.

        Extra keyword arguments are accepted (and ignored) for convenience, so
        they don't need to be removed when calling the factory.
        """
        target = cls(source_conn_props, target_nqn, portals, vol_uuid,
                     volume_nguid, ns_id, host_nqn, find_controllers)
        return target

    def __init__(self,
                 source_conn_props: 'NVMeOFConnProps',
                 nqn: str,
                 portals: list[str],
                 uuid: Optional[str] = None,
                 nguid: Optional[str] = None,
                 ns_id: Optional[str] = None,
                 host_nqn=None,
                 find_controllers=False) -> None:
        """Initialize instance.

        Portals are converted from a list of length 3 tuple/list into a list of
        Portal instances.

        The find_controllers parameter controls the search of the controller
        names in the system for each of the portals.
        """
        self.source_conn_props = source_conn_props
        self.nqn = nqn
        self.portals = [Portal(self, *portal) for portal in portals]
        self.uuid = uuid and str(uuid_lib.UUID(uuid))
        self.nguid = nguid and str(uuid_lib.UUID(nguid))
        self.ns_id = ns_id
        self.host_nqn = host_nqn

        if find_controllers:
            self.set_portals_controllers()

        # This only happens with some old connection properties format, where
        # we may not have a way to identify the new volume and we'll have to
        # try to guess it looking at existing volumes before the attach.
        if not (uuid or nguid or ns_id):
            self.devices_on_start = self._get_nvme_devices()
            LOG.debug('Devices on start are: %s', self.devices_on_start)

    @staticmethod
    def _get_nvme_devices() -> list[str]:
        """Get all NVMe devices present in the system."""
        pattern = '/dev/nvme*n*'  # e.g. /dev/nvme10n10
        return glob.glob(pattern)

    @property
    def live_portals(self) -> list[Portal]:
        """Get live portals.

        Must have called set_portals_controllers first since portals without a
        controller name will be skipped.
        """
        return [p for p in self.portals if p.is_live]

    @property
    def present_portals(self) -> list[Portal]:
        """Get present portals.

        Must have called set_portals_controllers first since portals without a
        controller name will be skipped.
        """
        return [p for p in self.portals if p.state is not None]

    def set_portals_controllers(self) -> None:
        """Search and set controller names in the target's portals.

        Compare the address, port, and transport protocol for each portal
        against existing nvme subsystem controllers.
        """
        if all(p.controller for p in self.portals):  # all have been found
            return

        hostnqn: Optional[str] = self.host_nqn or utils.get_host_nqn()

        # List of portal addresses and transports for this target
        # Unlike "nvme list-subsys -o json" sysfs addr is separated by a comma
        sysfs_portals: list[tuple[Optional[str],
                                  Optional[str],
                                  Optional[Union[str, utils.Anything]],
                                  Optional[Union[str, utils.Anything]]]] = [
            (p.address, p.port, p.transport, hostnqn)
            for p in self.portals
        ]
        known_names: list[str] = [p.controller for p in self.portals
                                  if p.controller]

        warned = False
        LOG.debug('Search controllers for portals %s', sysfs_portals)
        ctrl_paths = glob.glob(NVME_CTRL_SYSFS_PATH + 'nvme*')
        for ctrl_path in ctrl_paths:
            ctrl_name = os.path.basename(ctrl_path)
            if ctrl_name in known_names:
                continue
            LOG.debug('Checking controller %s', ctrl_name)

            nqn = sysfs_property('subsysnqn', ctrl_path)
            if nqn != self.nqn:
                LOG.debug("Skipping %s, doesn't match %s", nqn, self.nqn)
                continue

            # The right subsystem, but must also be the right portal
            ctrl_transport = sysfs_property('transport', ctrl_path)

            # Address in sysfs may contain src_addr in some systems. Parse and
            # only use destination addr and port
            address = sysfs_property('address', ctrl_path)
            if not address:
                LOG.error("Couldn't read address for %s", ctrl_path)
                continue
            ctrl_address = dict((x.split('=')
                                 for x in address.split(',')))

            ctrl_addr = ctrl_address['traddr']
            ctrl_port = ctrl_address['trsvcid']

            # hostnqn value not present in all OSs.  Ignore when not present
            ctrl_hostnqn = sysfs_property('hostnqn', ctrl_path) or utils.ANY
            # Warn once per target for OS not presenting the hostnqn on sysfs
            if ctrl_hostnqn is utils.ANY and not warned:
                LOG.warning("OS doesn't present the host nqn information. "
                            "Controller may be incorrectly matched.")
                warned = True

            ctrl_portal = (ctrl_addr, ctrl_port, ctrl_transport, ctrl_hostnqn)
            try:
                index = sysfs_portals.index(ctrl_portal)

                LOG.debug('Found a valid portal at %s', ctrl_portal)
                # Update the portal with the found controller name
                self.portals[index].controller = ctrl_name
                known_names.append(ctrl_name)  # One more controller found
            except ValueError:
                # If it's not one of our controllers ignore it
                LOG.debug('Skipping %s, not part of portals %s',
                          ctrl_portal, sysfs_portals)

            # short circuit if no more portals to find
            if len(known_names) == len(sysfs_portals):
                return

    def get_devices(self, only_live=False, get_one=False) -> list[str]:
        """Return devices for this target

        Optionally only return devices from portals that are live and also
        optionally return on first device found.

        Returns an empty list when not found.
        """
        LOG.debug('Looking for volume at %s', self.nqn)

        # Use a set because multiple portals can return the same device when
        # using ANA (even if we are not intentionally doing multipathing)
        result = set()
        portals = self.live_portals if only_live else self.present_portals

        for portal in portals:
            device = portal.get_device()
            if device:
                result.add(device)
                if get_one:
                    break

        return list(result)

    # NOTE: Don't change to a property, as it would hide VolumeDeviceNotFound
    @utils.retry(exception.VolumeDeviceNotFound, retries=5)
    def find_device(self) -> str:
        """Search for a device that is on a live subsystem

        Must have called set_portals_controllers first since portals without a
        controller name will be skipped.

        Retries up to 5 times with exponential backoff to give time in case the
        subsystem is currently reconnecting.  Raises VolumeDeviceNotFound when
        finally gives up trying.
        """
        if not self._device:
            devices = self.get_devices(only_live=True, get_one=True)
            if not devices:
                raise exception.VolumeDeviceNotFound(device=self.nqn)
            self._device = devices[0]
        return self._device

    def get_device_path_by_initial_devices(self) -> Optional[str]:
        """Find target's device path from devices that were present before."""
        ctrls = [p.controller for p in self.portals if p.controller]

        def discard(devices):
            """Discard devices that don't belong to our controllers."""
            if not devices:
                return set()

            return set(dev for dev in devices
                       if os.path.basename(dev).rsplit('n', 1)[0] in ctrls)

        current_devices = self._get_nvme_devices()
        LOG.debug('Initial devices: %s. Current devices %s. Controllers: %s',
                  self.devices_on_start, current_devices, ctrls)
        devices = discard(current_devices) - discard(self.devices_on_start)
        if not devices:
            return None

        if len(devices) == 1:
            return devices.pop()

        # With multiple devices they must all have the same uuid
        if (len(devices) > 1 and
                1 < len(set(blk_property('uuid', os.path.basename(d))
                            for d in devices))):
            msg = _('Too many different volumes found for %s') % ctrls
            LOG.error(msg)
            return None

        return devices.pop()  # They are the same volume, return any of them


class NVMeOFConnProps(object):
    """Internal representation of the NVMe-oF connection properties

    There is an old and a newer connection properties format, which result
    in 2 variants for replicated connections and 2 for non replicated:

    1- New format with multiples replicas information
    2- New format with single replica information
    3- New format with no replica information
    4- Original format

    Case #1 and #2 format:
      {
       'vol_uuid': <cinder_volume_id>,
       'alias': <raid_alias>,
       'volume_replicas': [ <target>, ... ],
       'replica_count': len(volume_replicas),
      }

      Where:
        cinder_volume_id ==> Cinder id, could be different from NVMe UUID.
                             with/without hyphens, uppper/lower cased.
        target :== {
                    'target_nqn': <target_nqn>,
                    'vol_uuid': <nvme_volume_uuid>,
                    'portals': [ <portal>, ... ],
                   }

        nvme_volume_uuid ==>  NVMe UUID. Can be different than cinder's id.
                              With/without hyphens, uppper/lower cased
        portal ::= tuple/list(
                    <target_portal>,
                    <target_port>,
                    <transport_type>
                   )
        transport_type ::= 'RoCEv2' | <anything>  # anything => tcp

    Case #3 format:
      <target>  ==> As defined in case #1 & #2

    Case #4 format:
      {
       'nqn': <nqn>,
       'transport_type': <transport_type>,
       'target_portal': <target_address>,
       'target_port': <target_port>,
       'volume_nguid': <volume_nguid>,
       'ns_id': <target_namespace_id>,
       'host_nqn': <connector_host_nqn>,
      }

      Where:
        transport_type ::= 'rdma' | 'tcp'
        volume_nguid ==> Optional, with/without hyphens, uppper/lower cased
        target_namespace_id ==> Optional
        connector_host_nqn> ==> Optional

    This class unifies the representation of all these in the following
    attributes:

      replica_count: None for non replicated
      alias: None for non replicated
      cinder_volume_id: None for non replicated
      is_replicated: True if replica count > 1, None if count = 1 else False
      targets: List of Target instances
      device_path: None if not present (it's set by Nova)

    In this unification case#4 is treated as case#3 where the vol_uuid is None
    and leaving all the additional information in the dictionary.  This way non
    replicated cases are always handled in the same way and we have a common
    <target>" definition for all cases:

      target :== {
                  'target_nqn': <target_nqn>,
                  'vol_uuid': <nvme_volume_uuid>,
                  'portals': [ <new_portal>, ... ],
                  'volume_nguid': <volume_nguid>,
                  'ns_id': <target_namespace_id>,
                  'host_nqn': <connector_host_nqn>,
                 }
      new_portal ::= tuple/list(
                      <target_address>,
                      <target_port>,
                      <new_transport_type>
                     )
      new_transport_type ::= 'rdma' | 'tcp'

    Portals change the transport_type to the internal representation where:
        'RoCEv2' ==> 'rdma'
        <else> ==> 'tcp'

    This means that the new connection format now accepts vol_uuid set to None,
    and accepts ns_id, volume_nguid, and host_nqn parameters, as described in
    the connect_volume docstring.
    """
    RO = 'ro'
    RW = 'rw'
    replica_count = None
    cinder_volume_id: Optional[str] = None

    def __init__(self, conn_props: dict,
                 find_controllers: bool = False) -> None:
        # Generic connection properties fields used by Nova
        self.qos_specs = conn_props.get('qos_specs')
        self.readonly = conn_props.get('access_mode', self.RW) == self.RO
        self.encrypted = conn_props.get('encrypted', False)
        self.cacheable = conn_props.get('cacheable', False)
        self.discard = conn_props.get('discard', False)

        # old connection properties format
        if REPLICAS not in conn_props and NQN not in conn_props:
            LOG.debug('Converting old connection info to new format')
            conn_props[UUID] = None
            conn_props[NQN] = conn_props.pop(OLD_NQN)
            conn_props[PORTALS] = [(conn_props.pop(PORTAL),
                                    conn_props.pop(PORT),
                                    conn_props.pop(TRANSPORT))]
            # Leave other fields as they are: volume_nguid, ns_id, host_nqn

        # NVMe-oF specific fields below
        self.alias = conn_props.get(ALIAS)

        if REPLICAS in conn_props:
            self.replica_count = (conn_props[REPLICA_COUNT] or
                                  len(conn_props[REPLICAS]))
            self.is_replicated = True if self.replica_count > 1 else None
            targets = conn_props[REPLICAS]
            self.cinder_volume_id = str(uuid_lib.UUID(conn_props[UUID]))
        else:
            self.is_replicated = False
            targets = [conn_props]

        self.targets = [Target.factory(source_conn_props=self,
                                       find_controllers=find_controllers,
                                       **target) for target in targets]

        # Below fields may have been added by nova
        self.device_path = conn_props.get('device_path')

    def get_devices(self, only_live: bool = False) -> list[str]:
        """Get all device paths present in the system for all targets."""
        result = []
        for target in self.targets:
            result.extend(target.get_devices(only_live))
        return result

    @classmethod
    def from_dictionary_parameter(cls: Type['NVMeOFConnProps'],
                                  func: Callable) -> Callable:
        """Decorator to convert connection properties dictionary.

        It converts the connection properties into a NVMeOFConnProps instance
        and finds the controller names for all portals present in the system.
        """
        @functools.wraps(func)
        def wrapper(self, connection_properties, *args, **kwargs):
            conn_props = cls(connection_properties, find_controllers=True)
            return func(self, conn_props, *args, **kwargs)
        return wrapper

# AUXILIARY CLASSES end
# #########################################################


# #########################################################
# CONNECTOR CLASS start

class NVMeOFConnector(base.BaseLinuxConnector):
    """Connector class to attach/detach NVMe-oF volumes."""

    # Use a class attribute since a restart is needed to change it on the host
    native_multipath_supported = None
    # Time we think is more than reasonable to establish an NVMe-oF connection
    TIME_TO_CONNECT = 10

    def __init__(self,
                 root_helper: str,
                 driver: Optional[base.host_driver.HostDriver] = None,
                 use_multipath: bool = False,
                 device_scan_attempts: int = DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs) -> None:
        super(NVMeOFConnector, self).__init__(
            root_helper,
            driver,
            device_scan_attemps=device_scan_attempts,
            *args, **kwargs)
        self.use_multipath = use_multipath
        self._set_native_multipath_supported()
        if self.use_multipath and not self.native_multipath_supported:
            LOG.warning('native multipath is not enabled')

    @staticmethod
    def get_search_path() -> str:
        """Necessary implementation for an os-brick connector."""
        return DEV_SEARCH_PATH

    def get_volume_paths(
            self,
            connection_properties: NVMeOFConnProps,
            device_info: Optional[dict[str, str]] = None) -> list[str]:
        """Return paths where the volume is present."""
        # Priority is on the value returned by connect_volume method
        if device_info and device_info.get('path'):
            return [device_info['path']]

        # Nova may add the path on the connection properties as a device_path
        device_path = connection_properties.device_path
        if device_path:
            return [device_path]

        # If we don't get the info on the connection properties it could be
        # problematic because we could have multiple devices and not know which
        # one we used.
        LOG.warning('We are being called without the path information!')
        # TODO: For raids it would be good to ensure they are actually there
        if connection_properties.is_replicated:
            if connection_properties.alias is None:
                raise exception.BrickException('Alias missing in connection '
                                               'info')
            return [RAID_PATH + connection_properties.alias]

        # TODO: Return live devices first?
        devices = connection_properties.get_devices()

        # If we are not sure if it's replicated or not, find out
        if connection_properties.is_replicated is None:
            if any(self._is_raid_device(dev) for dev in devices):
                if connection_properties.alias is None:
                    raise exception.BrickException('Alias missing in '
                                                   'connection info')
                return [RAID_PATH + connection_properties.alias]

        return devices

    # #######  Connector Properties methods ########

    @classmethod
    def nvme_present(cls: type) -> bool:
        """Check if the nvme CLI is present."""
        try:
            priv_rootwrap.custom_execute('nvme', 'version')
            return True
        except Exception as exc:
            if isinstance(exc, OSError) and exc.errno == errno.ENOENT:
                LOG.debug('nvme not present on system')
            else:
                LOG.warning('Unknown error when checking presence of nvme: %s',
                            exc)
        return False

    @classmethod
    def get_connector_properties(cls, root_helper, *args, **kwargs) -> dict:
        """The NVMe-oF connector properties (initiator uuid and nqn.)"""
        execute = kwargs.get('execute') or priv_rootwrap.execute
        nvmf = NVMeOFConnector(root_helper=root_helper, execute=execute)
        ret = {}

        nqn = None
        hostid = None
        uuid = nvmf._get_host_uuid()
        suuid = priv_nvmeof.get_system_uuid()
        if cls.nvme_present():
            nqn = utils.get_host_nqn(suuid)
            # Ensure /etc/nvme/hostid exists and defaults to the system uuid,
            # or a random value.
            hostid = utils.get_nvme_host_id(suuid)
        if hostid:
            ret['nvme_hostid'] = hostid
        if uuid:
            ret['uuid'] = uuid
        if suuid:
            ret['system uuid'] = suuid  # compatibility
        if nqn:
            ret['nqn'] = nqn
        ret['nvme_native_multipath'] = cls._set_native_multipath_supported()
        return ret

    def _get_host_uuid(self) -> Optional[str]:
        """Get the UUID of the first mounted filesystem."""
        cmd = ('findmnt', '-v', '/', '-n', '-o', 'SOURCE')
        try:
            lines, err = self._execute(
                *cmd, run_as_root=True, root_helper=self._root_helper)
            source = lines.split('\n')[0]
            # In a container this could be 'overlay', which causes the blkid
            # command to fail.
            if source == "overlay":
                return None
            blkid_cmd = (
                'blkid', source, '-s', 'UUID', '-o', 'value')
            lines, _err = self._execute(
                *blkid_cmd, run_as_root=True, root_helper=self._root_helper)
            return lines.split('\n')[0]
        except putils.ProcessExecutionError as e:
            LOG.warning(
                "Process execution error in _get_host_uuid: %s", e)
            return None

    @classmethod
    def _set_native_multipath_supported(cls):
        if cls.native_multipath_supported is None:
            cls.native_multipath_supported = \
                cls._is_native_multipath_supported()
        return cls.native_multipath_supported

    @staticmethod
    def _is_native_multipath_supported():
        try:
            with open('/sys/module/nvme_core/parameters/multipath', 'rt') as f:
                return f.read().strip() == 'Y'
        except Exception:
            LOG.warning("Could not find nvme_core/parameters/multipath")
        return False

    # #######  Connect Volume methods ########

    @utils.trace
    @utils.connect_volume_prepare_result
    @base.synchronized('connect_volume', external=True)
    @NVMeOFConnProps.from_dictionary_parameter
    def connect_volume(
            self, connection_properties: NVMeOFConnProps) -> dict[str, str]:
        """Attach and discover the volume."""
        try:
            if connection_properties.is_replicated is False:
                LOG.debug('Starting non replicated connection')
                path = self._connect_target(connection_properties.targets[0])

            else:  # If we know it's replicated or we don't yet know
                LOG.debug('Starting replicated connection')
                path = self._connect_volume_replicated(connection_properties)
        except Exception:
            self._try_disconnect_all(connection_properties)
            raise

        return {'type': 'block', 'path': path}

    def _do_multipath(self):
        return self.use_multipath and self.native_multipath_supported

    @utils.retry(exception.VolumeDeviceNotFound, interval=2)
    def _connect_target(self, target: Target) -> str:
        """Attach a specific target to present a volume on the system

        If we are already connected to any of the portals (and it's live) we
        send a rescan (because the backend may not support AER messages),
        otherwise we iterate through the portals trying to do an nvme-of
        connection.

        This method assumes that the controllers for the portals have already
        been set.  For example using the from_dictionary_parameter decorator
        in the NVMeOFConnProps class.

        Returns the path of the connected device.
        """
        connected = False
        missing_portals = []
        reconnecting_portals = []

        for portal in target.portals:
            state = portal.state  # store it so we read only once from sysfs
            # Rescan live controllers in case backend doesn't support AER
            if state == portal.LIVE:
                connected = True
                self.rescan(portal.controller)  # type: ignore
            # Remember portals that are not present in the system
            elif state == portal.MISSING:
                missing_portals.append(portal)
            elif state == portal.CONNECTING:
                LOG.debug('%s is reconnecting', portal)
                reconnecting_portals.append(portal)
            # Ignore reconnecting/dead portals
            else:
                LOG.debug('%s exists but is %s', portal, state)

        # If no live portals exist or if we want to use multipath
        do_multipath = self._do_multipath()
        if do_multipath or not connected:
            for portal in missing_portals:
                cmd = ['connect', '-a', portal.address, '-s', portal.port,
                       '-t', portal.transport, '-n', target.nqn, '-Q', '128',
                       '-l', '-1']
                if target.host_nqn:
                    cmd.extend(['-q', target.host_nqn])
                try:
                    self.run_nvme_cli(cmd)
                    connected = True
                except putils.ProcessExecutionError as exc:
                    # In some nvme versions code 70 means target is already
                    # connected, but in newer versions code is EALREADY.
                    # Those should only happen if there is a race condition
                    # because something is incorrectly configured (n-cpu and
                    # c-vol running on same node with different lock paths) or
                    # an admin is touching things manually. Not passing these
                    # exit codes in check_exit_code parameter to _execute so we
                    # can log it.  nvme cli v2 returns 1, so we parse the
                    # message. Some nvme cli versions return errors in stdout,
                    # so we look in stderr and stdout.
                    if not (exc.exit_code in (70, errno.EALREADY) or
                            (exc.exit_code == 1 and
                             'already connected' in exc.stderr + exc.stdout)):
                        LOG.error('Could not connect to %s: exit_code: %s, '
                                  'stdout: "%s", stderr: "%s",', portal,
                                  exc.exit_code, exc.stdout, exc.stderr)
                        continue

                    LOG.warning('Race condition with some other application '
                                'when connecting to %s, please check your '
                                'system configuration.', portal)
                    state = portal.state
                    if state == portal.LIVE:
                        connected = True
                    elif state == portal.CONNECTING:
                        reconnecting_portals.append(portal)
                    else:
                        LOG.error('Ignoring %s due to unknown state (%s)',
                                  portal, state)

                if not do_multipath:
                    break  # We are connected

        if not connected and reconnecting_portals:
            delay = self.TIME_TO_CONNECT + max(p.reconnect_delay
                                               for p in reconnecting_portals)
            LOG.debug('Waiting %s seconds for some nvme controllers to '
                      'reconnect', delay)
            timeout = time.time() + delay
            while time.time() < timeout:
                time.sleep(1)
                if any(p.is_live for p in reconnecting_portals):
                    LOG.debug('Reconnected')
                    connected = True
                    break
            LOG.debug('No controller reconnected')

        if not connected:
            raise exception.VolumeDeviceNotFound(device=target.nqn)

        # Ensure controller names of new connections are set
        target.set_portals_controllers()
        dev_path = target.find_device()
        return dev_path

    @utils.trace
    def _connect_volume_replicated(
            self, connection_properties: NVMeOFConnProps) -> str:
        """Connect to a replicated volume and prepare the RAID

        Connection properties must contain all the necessary replica
        information, even if there is only 1 replica.

        Returns the /dev/md path

        Raises VolumeDeviceNotFound when cannot present the device in the
        system.
        """
        host_device_paths = []

        if not connection_properties.alias:
            raise exception.BrickException('Alias missing in connection info')

        for replica in connection_properties.targets:
            try:
                rep_host_device_path = self._connect_target(replica)
                host_device_paths.append(rep_host_device_path)
            except Exception as ex:
                LOG.error("_connect_target: %s", ex)

        if not host_device_paths:
            raise exception.VolumeDeviceNotFound(
                device=connection_properties.targets)

        if connection_properties.is_replicated:
            device_path = self._handle_replicated_volume(
                host_device_paths, connection_properties)
        else:
            device_path = self._handle_single_replica(
                host_device_paths, connection_properties.alias)

        if nvmeof_agent:
            nvmeof_agent.NVMeOFAgent.ensure_running(self)

        return device_path

    def _handle_replicated_volume(self,
                                  host_device_paths: list[str],
                                  conn_props: NVMeOFConnProps) -> str:
        """Assemble the raid from found devices."""
        path_in_raid = False
        for dev_path in host_device_paths:
            path_in_raid = self._is_device_in_raid(dev_path)
            if path_in_raid:
                break
        device_path = RAID_PATH + conn_props.alias  # type: ignore
        if path_in_raid:
            self.stop_and_assemble_raid(host_device_paths, device_path, False)
        else:
            paths_found = len(host_device_paths)
            if conn_props.replica_count > paths_found:  # type: ignore
                LOG.error(
                    'Cannot create MD as %s out of %s legs were found.',
                    paths_found, conn_props.replica_count)
                raise exception.VolumeDeviceNotFound(device=conn_props.alias)
            self.create_raid(host_device_paths, '1',
                             conn_props.alias,  # type: ignore
                             conn_props.alias,  # type: ignore
                             False)

        return device_path

    def _handle_single_replica(self,
                               host_device_paths: list[str],
                               volume_alias: str) -> str:
        """Assemble the raid from a single device."""
        if self._is_raid_device(host_device_paths[0]):
            md_path = RAID_PATH + volume_alias
            self.stop_and_assemble_raid(host_device_paths, md_path, False)
            return md_path
        return host_device_paths[0]

    # #######  Disconnect methods ########

    @utils.trace
    @base.synchronized('connect_volume', external=True)
    @utils.connect_volume_undo_prepare_result(unlink_after=True)
    def disconnect_volume(self,
                          connection_properties: dict,
                          device_info: dict[str, str],
                          force: bool = False,
                          ignore_errors: bool = False) -> None:
        """Flush the volume.

        Disconnect of volumes happens on storage system side. Here we could
        remove connections to subsystems if no volumes are left. But new
        volumes can pop up asynchronously in the meantime. So the only thing
        left is flushing or disassembly of a correspondng RAID device.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes as
                                      described in connect_volume but also with
                                      the "device_path" key containing the path
                                      to the volume that was connected (this is
                                      added by Nova).
        :type connection_properties: dict

        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        # NOTE: Cannot use NVMeOFConnProps's decorator to create instance from
        # conn props because "connect_volume_undo_prepare_result" must be the
        # first decorator and it expects a dictionary.
        conn_props = NVMeOFConnProps(connection_properties)
        try:
            device_path = self.get_volume_paths(conn_props, device_info)[0]
        except IndexError:
            LOG.warning(
                "Cannot find the device for %s, assuming it's not there.",
                conn_props.cinder_volume_id or conn_props.targets[0].nqn)
            return

        exc = exception.ExceptionChainer()

        if not os.path.exists(device_path):
            LOG.warning("Trying to disconnect device %(device_path)s, but "
                        "it is not connected. Skipping.",
                        {'device_path': device_path})
            return

        # We assume that raid devices are flushed when ending the raid
        if device_path.startswith(RAID_PATH):
            with exc.context(force, 'Failed to end raid %s', device_path):
                self.end_raid(device_path)

        else:
            with exc.context(force, 'Failed to flush %s', device_path):
                self._linuxscsi.flush_device_io(device_path)

        self._try_disconnect_all(conn_props, exc)

        if exc:
            LOG.warning('There were errors removing %s', device_path)
            if not ignore_errors:
                raise exc

    def _try_disconnect_all(
            self,
            conn_props: NVMeOFConnProps,
            exc: Optional[exception.ExceptionChainer] = None) -> None:
        """Disconnect all subsystems that are not being used.

        Only sees if it has to disconnect this connection properties portals,
        leaves other alone.

        Since this is unrelated to the flushing of the devices failures will be
        logged but they won't be raised.
        """
        if exc is None:
            exc = exception.ExceptionChainer()

        for target in conn_props.targets:
            # Associate each portal with its controller name
            target.set_portals_controllers()
            for portal in target.portals:
                # Ignore exceptions to disconnect as many as possible.
                with exc.context(True, 'Failed to disconnect %s', portal):
                    self._try_disconnect(portal)

    def _try_disconnect(self, portal: Portal) -> None:
        """Disconnect a specific subsystem if it's safe.

        Only disconnect if it has no namespaces left or has only one left and
        it is from this connection.
        """
        LOG.debug('Checking if %s can be disconnected', portal)
        if portal.can_disconnect():
            self._execute('nvme', 'disconnect',
                          '-d', '/dev/' + portal.controller,  # type: ignore
                          root_helper=self._root_helper, run_as_root=True)

    # #######  Extend methods ########

    @staticmethod
    def _get_sizes_from_lba(ns_data: dict) -> tuple[Optional[int],
                                                    Optional[int]]:
        """Return size in bytes and the nsze of the volume from NVMe NS data.

        nsze is the namespace size that defines the total size of the namespace
        in logical blocks (LBA 0 through n-1), as per NVMe-oF specs.

        Returns a tuple of nsze and size
        """
        try:
            lbads = ns_data['lbafs'][0]['ds']

            # Don't know what to do with more than 1 LBA and as per NVMe specs
            # if LBADS < 9 then LBA is not supported
            if len(ns_data['lbafs']) != 1 or lbads < 9:
                LOG.warning("Cannot calculate new size with LBAs")
                return None, None
            nsze = ns_data['nsze']
            new_size = nsze * (1 << lbads)
        except Exception:
            return None, None

        LOG.debug('New volume size is %s and nsze is %s', new_size, nsze)
        return nsze, new_size

    @utils.trace
    @base.synchronized('extend_volume', external=True)
    @utils.connect_volume_undo_prepare_result
    def extend_volume(self, connection_properties: dict[str, str]) -> int:
        """Update an attached volume to reflect the current size after extend

        The only way to reflect the new size of an NVMe-oF volume on the host
        is a rescan, which rescans the whole subsystem.  This is a problem on
        attach_volume and detach_volume, but not here, since we will have at
        least the namespace we are operating on in the subsystem.

        The tricky part is knowing when a rescan has already been completed and
        the volume size on sysfs is final.  The rescan may already have
        happened before this method is called due to an AER message or we may
        need to trigger it here.

        Scans can be triggered manually with 'nvme ns-rescan' or writing 1 in
        configf's rescan file, or they can be triggered indirectly when calling
        the 'nvme list', 'nvme id-ns', or even using the 'nvme admin-passthru'
        command.

        Even after getting the new size with any of the NVMe commands above, we
        still need to wait until this is reflected on the host device, because
        we cannot return to the caller until the new size is in effect.

        If we don't see the new size taking effect on the system after 5
        seconds, or if we cannot get the new size with nvme, then we rescan in
        the latter and in both cases we blindly wait 5 seconds and return
        whatever size is present.

        For replicated volumes, the RAID needs to be extended.
        """
        # NOTE: Cannot use NVMeOFConnProps's decorator to create instance from
        # conn props because "connect_volume_undo_prepare_result" must be the
        # first decorator and it expects a dictionary.
        conn_props = NVMeOFConnProps(connection_properties)
        try:
            device_path = self.get_volume_paths(conn_props)[0]
        except IndexError:
            raise exception.VolumeDeviceNotFound()

        # Replicated needs to grow the raid, even if there's only 1 device
        if device_path.startswith(RAID_PATH):
            # NOTE: May not work without backend AER support and may have races
            self.run_mdadm(('mdadm', '--grow', '--size', 'max', device_path))

        else:
            dev_name = os.path.basename(device_path)
            ctrl_name = dev_name.rsplit('n', 1)[0]
            nsze: Optional[Union[str, int]] = None
            try:
                # With many devices, id-ns command generates less data
                out, err = self._execute('nvme', 'id-ns', '-ojson',
                                         device_path, run_as_root=True,
                                         root_helper=self._root_helper)
                ns_data = json.loads(out)
                nsze, new_size = self._get_sizes_from_lba(ns_data)
            except Exception as exc:
                LOG.warning('Failed to get id-ns %s', exc)
                # Assume that nvme command failed, so didn't scan
                self.rescan(ctrl_name)

            if nsze:  # Wait for the system to reflect the new size
                nsze = str(nsze)  # To compare with contents of sysfs
                for x in range(10):  # Wait 5 secs for size to appear in sysfs
                    current_nsze = blk_property('size', dev_name)
                    if current_nsze == nsze:
                        return new_size  # type: ignore

                    LOG.debug('Sysfs size is still %s', current_nsze)
                    time.sleep(0.5)
                LOG.warning('Timeout waiting for sysfs to reflect the right '
                            'volume size.')

            # Last resort when id-ns failed or system didn't reflect new size
            LOG.info('Wait 5 seconds and return whatever size is present')
            time.sleep(5)

        size = utils.get_device_size(self, device_path)
        if size is None:
            raise exception.BrickException(
                'get_device_size returned non-numeric size')
        return size

    # #######  RAID methods ########

    def run_mdadm(self,
                  cmd: Sequence[str],
                  raise_exception: bool = False) -> Optional[str]:
        cmd_output = None
        try:
            lines, err = self._execute(
                *cmd, run_as_root=True, root_helper=self._root_helper)
            for line in lines.split('\n'):
                cmd_output = line
                break
        except putils.ProcessExecutionError as ex:
            LOG.warning("[!] Could not run mdadm: %s", str(ex))
            if raise_exception:
                raise ex
        return cmd_output

    def _is_device_in_raid(self, device_path: str) -> bool:
        cmd = ['mdadm', '--examine', device_path]
        raid_expected = device_path + ':'
        try:
            lines, err = self._execute(
                *cmd, run_as_root=True, root_helper=self._root_helper)
            for line in lines.split('\n'):
                if line == raid_expected:
                    return True
                else:
                    return False
        except putils.ProcessExecutionError:
            pass
        return False

    @staticmethod
    def ks_readlink(dest: str) -> str:
        try:
            return os.readlink(dest)
        except Exception:
            return ''

    @staticmethod
    def get_md_name(device_name: str) -> Optional[str]:
        try:
            with open('/proc/mdstat', 'r') as f:
                lines = [line.split(' ')[0]
                         for line in f
                         if device_name in line]

                if lines:
                    return lines[0]
        except Exception as exc:
            LOG.debug("[!] Could not find md name for %s in mdstat: %s",
                      device_name, exc)

        return None

    def stop_and_assemble_raid(self,
                               drives: list[str],
                               md_path: str,
                               read_only: bool) -> None:
        md_name = None
        i = 0
        assembled = False
        link = ''
        while i < 5 and not assembled:
            for drive in drives:
                device_name = drive[5:]
                md_name = self.get_md_name(device_name)
                link = NVMeOFConnector.ks_readlink(md_path)
                if link != '':
                    link = os.path.basename(link)
                if md_name and md_name == link:
                    return
                LOG.debug(
                    "sleeping 1 sec -allow auto assemble link = %(link)s "
                    "md path = %(md_path)s",
                    {'link': link, 'md_path': md_path})
                time.sleep(1)

            if md_name and md_name != link:
                self.stop_raid(md_name)

            try:
                assembled = self.assemble_raid(drives, md_path, read_only)
            except Exception:
                i += 1

    def assemble_raid(self,
                      drives: list[str],
                      md_path: str,
                      read_only: bool) -> bool:
        cmd = ['mdadm', '--assemble', '--run', md_path]

        if read_only:
            cmd.append('-o')

        for i in range(len(drives)):
            cmd.append(drives[i])

        try:
            self.run_mdadm(cmd, True)
        except putils.ProcessExecutionError as ex:
            LOG.warning("[!] Could not _assemble_raid: %s", str(ex))
            raise ex

        return True

    def create_raid(self,
                    drives: list[str],
                    raid_type: str,
                    device_name: str,
                    name: str,
                    read_only: bool) -> None:
        cmd = ['mdadm']
        num_drives = len(drives)
        cmd.append('-C')

        if read_only:
            cmd.append('-o')

        cmd.append(device_name)
        cmd.append('-R')

        if name:
            cmd.append('-N')
            cmd.append(name)

        cmd.append('--level')
        cmd.append(raid_type)
        cmd.append('--raid-devices=' + str(num_drives))
        cmd.append('--bitmap=internal')
        cmd.append('--homehost=any')
        cmd.append('--failfast')
        cmd.append('--assume-clean')

        for i in range(len(drives)):
            cmd.append(drives[i])

        LOG.debug('[!] cmd = %s', cmd)
        self.run_mdadm(cmd)
        # sometimes under load, md is not created right away so we wait
        for i in range(60):
            try:
                is_exist = os.path.exists(RAID_PATH + name)
                LOG.debug("[!] md is_exist = %s", is_exist)
                if is_exist:
                    return
                time.sleep(1)
            except Exception:
                LOG.debug('[!] Exception_wait_raid!')
        msg = _("md: /dev/md/%s not found.") % name
        LOG.error(msg)
        raise exception.NotFound(message=msg)

    def end_raid(self, device_path: str) -> None:
        raid_exists = self.is_raid_exists(device_path)
        if raid_exists:
            for i in range(10):
                try:
                    cmd_out = self.stop_raid(device_path, True)
                    if not cmd_out:
                        break
                except Exception:
                    time.sleep(1)
            try:
                is_exist = os.path.exists(device_path)
                LOG.debug("[!] is_exist = %s", is_exist)
                if is_exist:
                    self.remove_raid(device_path)
                    os.remove(device_path)
            except Exception:
                LOG.debug('[!] Exception_stop_raid!')

    def stop_raid(self,
                  md_path: str,
                  raise_exception: bool = False) -> Optional[str]:
        cmd = ['mdadm', '--stop', md_path]
        LOG.debug("[!] cmd = %s", cmd)
        cmd_out = self.run_mdadm(cmd, raise_exception)
        return cmd_out

    def is_raid_exists(self, device_path: str) -> bool:
        cmd = ['mdadm', '--detail', device_path]
        LOG.debug("[!] cmd = %s", cmd)
        raid_expected = device_path + ':'
        try:
            lines, err = self._execute(
                *cmd, run_as_root=True, root_helper=self._root_helper)

            for line in lines.split('\n'):
                LOG.debug("[!] line = %s", line)
                if line == raid_expected:
                    return True
                else:
                    return False
        except putils.ProcessExecutionError:
            pass
        return False

    def remove_raid(self, device_path: str) -> None:
        cmd = ['mdadm', '--remove', device_path]
        LOG.debug("[!] cmd = %s", cmd)
        self.run_mdadm(cmd)

    def _is_raid_device(self, device: str) -> bool:
        return self._get_fs_type(device) == 'linux_raid_member'

    def _get_fs_type(self, device_path: str) -> Optional[str]:
        cmd = ['blkid', device_path, '-s', 'TYPE', '-o', 'value']
        LOG.debug("[!] cmd = %s", cmd)
        fs_type = None

        # We don't care about errors, on error lines will be '' so it's ok
        lines, err = self._execute(
            *cmd, run_as_root=True, root_helper=self._root_helper,
            check_exit_code=False)
        fs_type = lines.split('\n')[0]
        return fs_type or None

    # #######  NVMe methods ########

    def run_nvme_cli(self,
                     nvme_command: Sequence[str],
                     **kwargs) -> tuple[str, str]:
        """Run an nvme cli command and return stdout and stderr output."""
        (out, err) = self._execute('nvme', *nvme_command, run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=True)
        msg = ("nvme %(nvme_command)s: stdout=%(out)s stderr=%(err)s" %
               {'nvme_command': nvme_command, 'out': out, 'err': err})
        LOG.debug("[!] %s", msg)

        return out, err

    def rescan(self, controller_name: str) -> None:
        """Rescan an nvme controller."""
        nvme_command = ('ns-rescan', DEV_SEARCH_PATH + controller_name)
        try:
            self.run_nvme_cli(nvme_command)
        except Exception as e:
            raise exception.CommandExecutionFailed(e, cmd=nvme_command)

# CONNECTOR CLASS end
# #########################################################
