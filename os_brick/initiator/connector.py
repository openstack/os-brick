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
"""Brick Connector objects for each supported transport protocol.

.. module: connector

The connectors here are responsible for discovering and removing volumes for
each of the supported transport protocols.
"""

import platform
import socket
import sys

from oslo_concurrency import lockutils
from oslo_log import log as logging
from oslo_utils import importutils

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick import utils

LOG = logging.getLogger(__name__)

synchronized = lockutils.synchronized_with_prefix('os-brick-')

# List of connectors to call when getting
# the connector properties for a host
windows_connector_list = [
    'os_brick.initiator.windows.base.BaseWindowsConnector',
    'os_brick.initiator.windows.iscsi.WindowsISCSIConnector',
    'os_brick.initiator.windows.fibre_channel.WindowsFCConnector',
    'os_brick.initiator.windows.smbfs.WindowsSMBFSConnector'
]

unix_connector_list = [
    'os_brick.initiator.connectors.base.BaseLinuxConnector',
    'os_brick.initiator.connectors.iscsi.ISCSIConnector',
    'os_brick.initiator.connectors.fibre_channel.FibreChannelConnector',
    ('os_brick.initiator.connectors.fibre_channel_s390x.'
     'FibreChannelConnectorS390X'),
    ('os_brick.initiator.connectors.fibre_channel_ppc64.'
     'FibreChannelConnectorPPC64'),
    'os_brick.initiator.connectors.aoe.AoEConnector',
    'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    'os_brick.initiator.connectors.rbd.RBDConnector',
    'os_brick.initiator.connectors.local.LocalConnector',
    'os_brick.initiator.connectors.gpfs.GPFSConnector',
    'os_brick.initiator.connectors.drbd.DRBDConnector',
    'os_brick.initiator.connectors.huawei.HuaweiStorHyperConnector',
    'os_brick.initiator.connectors.hgst.HGSTConnector',
    'os_brick.initiator.connectors.scaleio.ScaleIOConnector',
    'os_brick.initiator.connectors.disco.DISCOConnector',
    'os_brick.initiator.connectors.vmware.VmdkConnector',
    'os_brick.initiator.connectors.vrtshyperscale.HyperScaleConnector',
    'os_brick.initiator.connectors.storpool.StorPoolConnector',
    'os_brick.initiator.connectors.nvmeof.NVMeOFConnector',
]


def _get_connector_list():
    if sys.platform != 'win32':
        return unix_connector_list
    else:
        return windows_connector_list


# Mappings used to determine who to construct in the factory
_connector_mapping_linux = {
    initiator.AOE:
        'os_brick.initiator.connectors.aoe.AoEConnector',
    initiator.DRBD:
        'os_brick.initiator.connectors.drbd.DRBDConnector',

    initiator.GLUSTERFS:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    initiator.NFS:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    initiator.SCALITY:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    initiator.QUOBYTE:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    initiator.VZSTORAGE:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',

    initiator.ISCSI:
        'os_brick.initiator.connectors.iscsi.ISCSIConnector',
    initiator.ISER:
        'os_brick.initiator.connectors.iscsi.ISCSIConnector',
    initiator.FIBRE_CHANNEL:
        'os_brick.initiator.connectors.fibre_channel.FibreChannelConnector',

    initiator.LOCAL:
        'os_brick.initiator.connectors.local.LocalConnector',
    initiator.HUAWEISDSHYPERVISOR:
        'os_brick.initiator.connectors.huawei.HuaweiStorHyperConnector',
    initiator.HGST:
        'os_brick.initiator.connectors.hgst.HGSTConnector',
    initiator.RBD:
        'os_brick.initiator.connectors.rbd.RBDConnector',
    initiator.SCALEIO:
        'os_brick.initiator.connectors.scaleio.ScaleIOConnector',
    initiator.DISCO:
        'os_brick.initiator.connectors.disco.DISCOConnector',
    initiator.VMDK:
        'os_brick.initiator.connectors.vmware.VmdkConnector',
    initiator.GPFS:
        'os_brick.initiator.connectors.gpfs.GPFSConnector',
    initiator.VERITAS_HYPERSCALE:
        'os_brick.initiator.connectors.vrtshyperscale.HyperScaleConnector',
    initiator.STORPOOL:
        'os_brick.initiator.connectors.storpool.StorPoolConnector',
    # Leave this in for backwards compatibility
    # This isn't an NVME connector, but NVME Over Fabrics
    initiator.NVME:
        'os_brick.initiator.connectors.nvmeof.NVMeOFConnector',
    initiator.NVMEOF:
        'os_brick.initiator.connectors.nvmeof.NVMeOFConnector',
}

# Mapping for the S390X platform
_connector_mapping_linux_s390x = {
    initiator.FIBRE_CHANNEL:
        'os_brick.initiator.connectors.fibre_channel_s390x.'
        'FibreChannelConnectorS390X',
    initiator.DRBD:
        'os_brick.initiator.connectors.drbd.DRBDConnector',
    initiator.NFS:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    initiator.ISCSI:
        'os_brick.initiator.connectors.iscsi.ISCSIConnector',
    initiator.LOCAL:
        'os_brick.initiator.connectors.local.LocalConnector',
    initiator.RBD:
        'os_brick.initiator.connectors.rbd.RBDConnector',
    initiator.GPFS:
        'os_brick.initiator.connectors.gpfs.GPFSConnector',
}

# Mapping for the PPC64 platform
_connector_mapping_linux_ppc64 = {
    initiator.FIBRE_CHANNEL:
        ('os_brick.initiator.connectors.fibre_channel_ppc64.'
         'FibreChannelConnectorPPC64'),
    initiator.DRBD:
        'os_brick.initiator.connectors.drbd.DRBDConnector',
    initiator.NFS:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    initiator.ISCSI:
        'os_brick.initiator.connectors.iscsi.ISCSIConnector',
    initiator.LOCAL:
        'os_brick.initiator.connectors.local.LocalConnector',
    initiator.RBD:
        'os_brick.initiator.connectors.rbd.RBDConnector',
    initiator.GPFS:
        'os_brick.initiator.connectors.gpfs.GPFSConnector',
    initiator.VZSTORAGE:
        'os_brick.initiator.connectors.remotefs.RemoteFsConnector',
    initiator.VERITAS_HYPERSCALE:
        'os_brick.initiator.connectors.vrtshyperscale.HyperScaleConnector',
    initiator.ISER:
        'os_brick.initiator.connectors.iscsi.ISCSIConnector',
}

# Mapping for the windows connectors
_connector_mapping_windows = {
    initiator.ISCSI:
        'os_brick.initiator.windows.iscsi.WindowsISCSIConnector',
    initiator.FIBRE_CHANNEL:
        'os_brick.initiator.windows.fibre_channel.WindowsFCConnector',
    initiator.SMBFS:
        'os_brick.initiator.windows.smbfs.WindowsSMBFSConnector',
}


# Create aliases to the old names until 2.0.0
# TODO(smcginnis) Remove this lookup once unit test code is updated to
# point to the correct location
def _set_aliases():
    conn_list = _get_connector_list()
    # TODO(lpetrut): Cinder is explicitly trying to use those two
    # connectors. We should drop this once we fix Cinder and
    # get passed the backwards compatibility period.
    if sys.platform == 'win32':
        conn_list += [
            'os_brick.initiator.connectors.iscsi.ISCSIConnector',
            ('os_brick.initiator.connectors.fibre_channel.'
             'FibreChannelConnector'),
        ]

    for item in conn_list:
        _name = item.split('.')[-1]
        globals()[_name] = importutils.import_class(item)


_set_aliases()


@utils.trace
def get_connector_properties(root_helper, my_ip, multipath, enforce_multipath,
                             host=None, execute=None):
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
    :param host: hostname.
    :param execute: execute helper.
    :returns: dict containing all of the collected initiator values.
    """
    props = {}
    props['platform'] = platform.machine()
    props['os_type'] = sys.platform
    props['ip'] = my_ip
    props['host'] = host if host else socket.gethostname()

    for item in _get_connector_list():
        connector = importutils.import_class(item)

        if (utils.platform_matches(props['platform'], connector.platform) and
           utils.os_matches(props['os_type'], connector.os_type)):
            props = utils.merge_dict(props,
                                     connector.get_connector_properties(
                                         root_helper,
                                         host=host,
                                         multipath=multipath,
                                         enforce_multipath=enforce_multipath,
                                         execute=execute))

    return props


def get_connector_mapping(arch=None):
    """Get connector mapping based on platform.

    This is used by Nova to get the right connector information.

    :param arch: The architecture being requested.
    """

    # We do this instead of assigning it in the definition
    # to help mocking for unit tests
    if arch is None:
        arch = platform.machine()

    # Set the correct mapping for imports
    if sys.platform == 'win32':
        return _connector_mapping_windows
    elif arch in (initiator.S390, initiator.S390X):
        return _connector_mapping_linux_s390x
    elif arch in (initiator.PPC64, initiator.PPC64LE):
        return _connector_mapping_linux_ppc64

    else:
        return _connector_mapping_linux


# TODO(walter-boring) We have to keep this class defined here
# so we don't break backwards compatibility
class InitiatorConnector(object):

    @staticmethod
    def factory(protocol, root_helper, driver=None,
                use_multipath=False,
                device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                arch=None,
                *args, **kwargs):
        """Build a Connector object based upon protocol and architecture."""

        _mapping = get_connector_mapping(arch)

        LOG.debug("Factory for %(protocol)s on %(arch)s",
                  {'protocol': protocol, 'arch': arch})
        protocol = protocol.upper()

        # set any special kwargs needed by connectors
        if protocol in (initiator.NFS, initiator.GLUSTERFS,
                        initiator.SCALITY, initiator.QUOBYTE,
                        initiator.VZSTORAGE):
            kwargs.update({'mount_type': protocol.lower()})
        elif protocol == initiator.ISER:
            kwargs.update({'transport': 'iser'})

        # now set all the default kwargs
        kwargs.update(
            {'root_helper': root_helper,
             'driver': driver,
             'use_multipath': use_multipath,
             'device_scan_attempts': device_scan_attempts,
             })

        connector = _mapping.get(protocol)
        if not connector:
            msg = (_("Invalid InitiatorConnector protocol "
                     "specified %(protocol)s") %
                   dict(protocol=protocol))
            raise exception.InvalidConnectorProtocol(msg)

        conn_cls = importutils.import_class(connector)
        return conn_cls(*args, **kwargs)
