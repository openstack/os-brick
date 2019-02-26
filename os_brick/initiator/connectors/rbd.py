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
import tempfile

from oslo_concurrency import processutils as putils
from oslo_log import log as logging
from oslo_utils import fileutils
from oslo_utils import netutils

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick.initiator import linuxrbd
from os_brick import utils

LOG = logging.getLogger(__name__)


class RBDConnector(base.BaseLinuxConnector):
    """"Connector class to attach/detach RBD volumes."""

    def __init__(self, root_helper, driver=None, use_multipath=False,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):

        super(RBDConnector, self).__init__(root_helper, driver=driver,
                                           device_scan_attempts=
                                           device_scan_attempts,
                                           *args, **kwargs)
        self.do_local_attach = kwargs.get('do_local_attach', False)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The RBD connector properties."""
        return {'do_local_attach': kwargs.get('do_local_attach', False)}

    def get_volume_paths(self, connection_properties):
        # TODO(e0ne): Implement this for local volume.
        return []

    def get_search_path(self):
        # TODO(walter-boring): don't know where the connector
        # looks for RBD volumes.
        return None

    def get_all_available_volumes(self, connection_properties=None):
        # TODO(e0ne): Implement this for local volume.
        return []

    def _sanitize_mon_hosts(self, hosts):
        def _sanitize_host(host):
            if netutils.is_valid_ipv6(host):
                host = '[%s]' % host
            return host
        return list(map(_sanitize_host, hosts))

    def _check_or_get_keyring_contents(self, keyring, cluster_name, user):
        try:
            if keyring is None:
                if user:
                    keyring_path = ("/etc/ceph/%s.client.%s.keyring" %
                                    (cluster_name, user))
                    with open(keyring_path, 'r') as keyring_file:
                        keyring = keyring_file.read()
                else:
                    keyring = ''
            return keyring
        except IOError:
            msg = (_("Keyring path %s is not readable.") % (keyring_path))
            raise exception.BrickException(msg=msg)

    def _create_ceph_conf(self, monitor_ips, monitor_ports,
                          cluster_name, user, keyring):
        monitors = ["%s:%s" % (ip, port) for ip, port in
                    zip(self._sanitize_mon_hosts(monitor_ips), monitor_ports)]
        mon_hosts = "mon_host = %s" % (','.join(monitors))

        keyring = self._check_or_get_keyring_contents(keyring, cluster_name,
                                                      user)

        try:
            fd, ceph_conf_path = tempfile.mkstemp(prefix="brickrbd_")
            with os.fdopen(fd, 'w') as conf_file:
                conf_file.writelines([mon_hosts, "\n", keyring, "\n"])
            return ceph_conf_path
        except IOError:
            msg = (_("Failed to write data to %s.") % (ceph_conf_path))
            raise exception.BrickException(msg=msg)

    def _get_rbd_handle(self, connection_properties):
        try:
            user = connection_properties['auth_username']
            pool, volume = connection_properties['name'].split('/')
            cluster_name = connection_properties['cluster_name']
            monitor_ips = connection_properties['hosts']
            monitor_ports = connection_properties['ports']
            keyring = connection_properties.get('keyring')
        except (KeyError, ValueError):
            msg = _("Connect volume failed, malformed connection properties.")
            raise exception.BrickException(msg=msg)

        conf = self._create_ceph_conf(monitor_ips, monitor_ports,
                                      str(cluster_name), user,
                                      keyring)
        try:
            rbd_client = linuxrbd.RBDClient(user, pool, conffile=conf,
                                            rbd_cluster_name=str(cluster_name))
            rbd_volume = linuxrbd.RBDVolume(rbd_client, volume)
            rbd_handle = linuxrbd.RBDVolumeIOWrapper(
                linuxrbd.RBDImageMetadata(rbd_volume, pool, user, conf))
        except Exception:
            fileutils.delete_if_exists(conf)
            raise

        return rbd_handle

    def _get_rbd_args(self, connection_properties):
        try:
            user = connection_properties['auth_username']
            monitor_ips = connection_properties.get('hosts')
            monitor_ports = connection_properties.get('ports')
        except KeyError:
            msg = _("Connect volume failed, malformed connection properties")
            raise exception.BrickException(msg=msg)

        args = ['--id', user]
        if monitor_ips and monitor_ports:
            monitors = ["%s:%s" % (ip, port) for ip, port in
                        zip(
                            self._sanitize_mon_hosts(monitor_ips),
                            monitor_ports)]
            for monitor in monitors:
                args += ['--mon_host', monitor]
        return args

    @staticmethod
    def get_rbd_device_name(pool, volume):
        """Return device name which will be generated by RBD kernel module.

        :param pool: RBD pool name.
        :type pool: string
        :param volume: RBD image name.
        :type volume: string
        """
        return '/dev/rbd/{pool}/{volume}'.format(pool=pool, volume=volume)

    @utils.trace
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """
        do_local_attach = connection_properties.get('do_local_attach',
                                                    self.do_local_attach)

        if do_local_attach:
            # NOTE(e0ne): sanity check if ceph-common is installed.
            cmd = ['which', 'rbd']
            try:
                self._execute(*cmd)
            except putils.ProcessExecutionError:
                msg = _("ceph-common package is not installed.")
                LOG.error(msg)
                raise exception.BrickException(message=msg)

            # NOTE(e0ne): map volume to a block device
            # via the rbd kernel module.
            pool, volume = connection_properties['name'].split('/')
            rbd_dev_path = RBDConnector.get_rbd_device_name(pool, volume)
            if (not os.path.islink(rbd_dev_path) or
                    not os.path.exists(os.path.realpath(rbd_dev_path))):
                cmd = ['rbd', 'map', volume, '--pool', pool]
                cmd += self._get_rbd_args(connection_properties)
                self._execute(*cmd, root_helper=self._root_helper,
                              run_as_root=True)
            else:
                LOG.debug('volume %(vol)s is already mapped to local'
                          ' device %(dev)s',
                          {'vol': volume,
                           'dev': os.path.realpath(rbd_dev_path)})

            return {'path': rbd_dev_path,
                    'type': 'block'}

        rbd_handle = self._get_rbd_handle(connection_properties)
        return {'path': rbd_handle}

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Disconnect a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        """
        do_local_attach = connection_properties.get('do_local_attach',
                                                    self.do_local_attach)
        if do_local_attach:
            pool, volume = connection_properties['name'].split('/')
            dev_name = RBDConnector.get_rbd_device_name(pool, volume)
            cmd = ['rbd', 'unmap', dev_name]
            cmd += self._get_rbd_args(connection_properties)
            self._execute(*cmd, root_helper=self._root_helper,
                          run_as_root=True)
        else:
            if device_info:
                rbd_handle = device_info.get('path', None)
                if rbd_handle is not None:
                    fileutils.delete_if_exists(rbd_handle.rbd_conf)
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
            LOG.error("Failed to access RBD device handle: %(error)s",
                      {"error": e})
            return False
        finally:
            rbd_handle.seek(original_offset, 0)

        return True

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError
