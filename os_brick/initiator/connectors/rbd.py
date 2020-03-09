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
from oslo_serialization import jsonutils
from oslo_utils import excutils
from oslo_utils import fileutils

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import base_rbd
from os_brick.initiator import linuxrbd
from os_brick.privileged import rbd as rbd_privsep
from os_brick import utils

LOG = logging.getLogger(__name__)


class RBDConnector(base_rbd.RBDConnectorMixin, base.BaseLinuxConnector):
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

    @staticmethod
    def _check_or_get_keyring_contents(keyring, cluster_name, user):
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

    @classmethod
    def _create_ceph_conf(cls, monitor_ips, monitor_ports,
                          cluster_name, user, keyring):
        monitors = ["%s:%s" % (ip, port) for ip, port in
                    zip(cls._sanitize_mon_hosts(monitor_ips), monitor_ports)]
        mon_hosts = "mon_host = %s" % (','.join(monitors))

        keyring = cls._check_or_get_keyring_contents(keyring, cluster_name,
                                                     user)

        try:
            fd, ceph_conf_path = tempfile.mkstemp(prefix="brickrbd_")
            with os.fdopen(fd, 'w') as conf_file:
                # Bug #1865754 - '[global]' has been the appropriate
                # place for this stuff since at least Hammer, but in
                # Octopus (15.2.0+), Ceph began enforcing this.
                conf_file.writelines(["[global]", "\n",
                                      mon_hosts, "\n",
                                      keyring, "\n"])
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
            # NOTE: cinder no longer passes keyring data in the connection
            # properties as of the victoria release.  See OSSN-0085.  But
            # cinderlib does, so we must keep the code related to the keyring.
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

    @staticmethod
    def get_rbd_device_name(pool, volume):
        """Return device name which will be generated by RBD kernel module.

        :param pool: RBD pool name.
        :type pool: string
        :param volume: RBD image name.
        :type volume: string
        """
        return '/dev/rbd/{pool}/{volume}'.format(pool=pool, volume=volume)

    @classmethod
    def create_non_openstack_config(cls, connection_properties):
        """Get root owned Ceph's .conf file for non OpenStack usage."""
        # If keyring info is missing then we are in OpenStack, nothing to do
        keyring = connection_properties.get('keyring')
        if not keyring:
            return None

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

        conf = rbd_privsep.root_create_ceph_conf(monitor_ips, monitor_ports,
                                                 str(cluster_name), user,
                                                 keyring)
        return conf

    def _local_attach_volume(self, connection_properties):
        # NOTE(e0ne): sanity check if ceph-common is installed.
        try:
            self._execute('which', 'rbd')
        except putils.ProcessExecutionError:
            msg = _("ceph-common package is not installed.")
            LOG.error(msg)
            raise exception.BrickException(message=msg)

        # NOTE(e0ne): map volume to a block device
        # via the rbd kernel module.
        pool, volume = connection_properties['name'].split('/')
        rbd_dev_path = self.get_rbd_device_name(pool, volume)
        # If we are not running on OpenStack, create config file
        conf = self.create_non_openstack_config(connection_properties)
        try:
            if (
                not os.path.islink(rbd_dev_path) or
                not os.path.exists(os.path.realpath(rbd_dev_path))
            ):
                # TODO(stephenfin): Update to the unified 'rbd device map'
                # command introduced in ceph 13.0 (commit 6a57358add1157629a6d)
                # when we drop support earlier versions
                cmd = ['rbd', 'map', volume, '--pool', pool]
                cmd += self._get_rbd_args(connection_properties, conf)
                self._execute(*cmd, root_helper=self._root_helper,
                              run_as_root=True)
            else:
                LOG.debug(
                    'Volume %(vol)s is already mapped to local device %(dev)s',
                    {'vol': volume, 'dev': os.path.realpath(rbd_dev_path)}
                )

            if (
                not os.path.islink(rbd_dev_path) or
                not os.path.exists(os.path.realpath(rbd_dev_path))
            ):
                LOG.warning(
                    'Volume %(vol)s has not been mapped to local device '
                    '%(dev)s; is the udev daemon running and are the '
                    'ceph-renamer udev rules configured? See bug #1884114 for '
                    'more information.',
                    {'vol': volume, 'dev': rbd_dev_path},
                )
        except Exception:
            # Cleanup conf file on failure
            with excutils.save_and_reraise_exception():
                if conf:
                    rbd_privsep.delete_if_exists(conf)

        res = {'path': rbd_dev_path,
               'type': 'block'}
        if conf:
            res['conf'] = conf
        return res

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
            return self._local_attach_volume(connection_properties)

        rbd_handle = self._get_rbd_handle(connection_properties)
        return {'path': rbd_handle}

    def _find_root_device(self, connection_properties, conf):
        """Find the underlying /dev/rbd* device for a mapping.

        Use the showmapped command to list all acive mappings and find the
        underlying /dev/rbd* device that corresponds to our pool and volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: '/dev/rbd*' or None if no active mapping is found.
        """
        __, volume = connection_properties['name'].split('/')
        # TODO(stephenfin): Update to the unified 'rbd device list'
        # command introduced in ceph 13.0 (commit 6a57358add1157629a6d)
        # when we drop support earlier versions
        cmd = ['rbd', 'showmapped', '--format=json']
        cmd += self._get_rbd_args(connection_properties, conf)
        (out, err) = self._execute(*cmd, root_helper=self._root_helper,
                                   run_as_root=True)

        # ceph v13.2.0 (Mimic) changed the output format of 'rbd showmapped'
        # from a dict of mappings keyed by ID to a simple list of mappings
        # https://docs.ceph.com/docs/master/releases/mimic/
        #
        # before:
        #
        #   {
        #     "0": {
        #       "pool":"volumes",
        #       "namespace":"",
        #       "name":"volume-6d54cb90-a5d1-40d8-9cb2-c6adf43a02af",
        #       "snap":"-",
        #       "device":"/dev/rbd0"
        #     }
        #   }
        #
        # after:
        #
        #   [
        #     {
        #       "id":"0",
        #       "pool":"volumes",
        #       "namespace":"",
        #       "name":"volume-6d54cb90-a5d1-40d8-9cb2-c6adf43a02af",
        #       "snap":"-",
        #       "device":"/dev/rbd0"
        #     }
        #   ]
        #
        # TODO(stephenfin): Drop when we drop support for ceph 13.2.0
        mappings = jsonutils.loads(out)
        if isinstance(mappings, dict):
            # yes, we're losing the ID field but we don't need it here
            mappings = mappings.values()

        for mapping in mappings:
            if mapping['name'] == volume:
                return mapping['device']
        return None

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
            conf = device_info.get('conf') if device_info else None
            root_device = self._find_root_device(connection_properties, conf)
            if root_device:
                # TODO(stephenfin): Update to the unified 'rbd device unmap'
                # command introduced in ceph 13.0 (commit 6a57358add1157629a6d)
                # when we drop support earlier versions
                cmd = ['rbd', 'unmap', root_device]
                cmd += self._get_rbd_args(connection_properties, conf)
                self._execute(*cmd, root_helper=self._root_helper,
                              run_as_root=True)
                if conf:
                    rbd_privsep.delete_if_exists(conf)
        else:
            if device_info:
                rbd_handle = device_info.get('path', None)
                if rbd_handle is not None:
                    fileutils.delete_if_exists(rbd_handle.rbd_conf)
                    rbd_handle.close()

    @staticmethod
    def _check_valid_device(rbd_handle):
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

    def check_valid_device(self, path, run_as_root=True):
        """Verify an existing RBD handle is connected and valid."""
        if not path:
            return False

        # We can receive a file handle or a path to a device
        if isinstance(path, str):
            if run_as_root:
                return rbd_privsep.check_valid_path(path)
            else:
                with open(path, 'rb') as rbd_handle:
                    return self._check_valid_device(rbd_handle)

        # For backward compatibility ignore run_as_root param with handles
        return self._check_valid_device(path)

    def extend_volume(self, connection_properties):
        """Refresh local volume view and return current size in bytes."""
        # Nothing to do, RBD attached volumes are automatically refreshed, but
        # we need to return the new size for compatibility
        do_local_attach = connection_properties.get('do_local_attach',
                                                    self.do_local_attach)

        if not do_local_attach:
            handle = self._get_rbd_handle(connection_properties)
            try:
                # Handles should return absolute position on seek, but the RBD
                # wrapper doesn't, so we need to call tell afterwards
                handle.seek(0, 2)
                return handle.tell()
            finally:
                fileutils.delete_if_exists(handle.rbd_conf)
                handle.close()

        # Create config file when we do the attach on the host and not the VM
        conf = self.create_non_openstack_config(connection_properties)

        try:
            device_path = self._find_root_device(connection_properties, conf)
        finally:
            # If we have generated the config file we need to remove it
            if conf:
                try:
                    rbd_privsep.delete_if_exists(conf)
                except Exception as exc:
                    LOG.warning(_('Could not remove config file %(filename)s: '
                                  '%(exc)s'), {'filename': conf, 'exc': exc})

        if not device_path:
            msg = _('Cannot extend non mapped device.')
            raise exception.BrickException(msg=msg)

        device_name = os.path.basename(device_path)  # ie: rbd0
        device_number = device_name[3:]  # ie: 0
        # Get size from /sys/devices/rbd/0/size instead of
        # /sys/class/block/rbd0/size because the latter isn't updated
        with open('/sys/devices/rbd/' + device_number + '/size') as f:
            size_bytes = f.read().strip()
        return int(size_bytes)
