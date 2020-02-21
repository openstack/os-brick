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

import glob
import os
import socket
import struct

from oslo_concurrency import lockutils
from oslo_log import log as logging
import six

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick import utils

LOG = logging.getLogger(__name__)
DEVICE_SCAN_ATTEMPTS_DEFAULT = 3
synchronized = lockutils.synchronized_with_prefix('os-brick-')


class DISCOConnector(base.BaseLinuxConnector):
    """Class implements the connector driver for DISCO."""

    DISCO_PREFIX = 'dms'

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        """Init DISCO connector."""
        super(DISCOConnector, self).__init__(
            root_helper,
            driver=driver,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs
        )
        LOG.debug("Init DISCO connector")

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

    @utils.trace
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

    @utils.trace
    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
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
            LOG.info("Volume already detached from host")

    def _mount_disco_volume(self, path, volume_id):
        """Send request to mount volume on physical host."""
        LOG.debug("Enter in mount disco volume %(port)s "
                  "and %(ip)s.",
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
            LOG.info("Volume already attached to host")

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
            LOG.error("Cannot connect TCP socket")
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
