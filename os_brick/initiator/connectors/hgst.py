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

import os
import socket

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick import utils

LOG = logging.getLogger(__name__)


class HGSTConnector(base.BaseLinuxConnector):
    """Connector class to attach/detach HGST volumes."""

    VGCCLUSTER = 'vgc-cluster'

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
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
        LOG.error("CLI fail: '%(cmd)s' = %(code)s\nout: %(stdout)s\n"
                  "err: %(stderr)s",
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
                for line in nets:
                    x = line.strip()
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

    @utils.trace
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

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
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
