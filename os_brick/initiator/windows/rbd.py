# Copyright 2020 Cloudbase Solutions Srl
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

import ctypes
import errno
import json

from oslo_concurrency import processutils
from oslo_log import log as logging
from oslo_service import loopingcall

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator.connectors import base_rbd
from os_brick.initiator.windows import base as win_conn_base
from os_brick import utils

LOG = logging.getLogger(__name__)


class WindowsRBDConnector(base_rbd.RBDConnectorMixin,
                          win_conn_base.BaseWindowsConnector):
    """Connector class to attach/detach RBD volumes.

    The Windows RBD connector is very similar to the Linux one.
    There are a few main differences though:
      * the Ceph python bindings are not available on Windows yet, so we'll
        always do a local mount. Besides, Hyper-V cannot use librbd, so
        we'll need to do a local mount anyway.
      * The device names aren't handled in the same way. On Windows,
        disk names such as "\\\\.\\PhysicalDrive1" are provided by the OS and
        cannot be explicitly requsted.
    """

    def __init__(self, *args, **kwargs):
        super(WindowsRBDConnector, self).__init__(*args, **kwargs)

        self._ensure_rbd_available()

    def _check_rbd(self):
        cmd = ['where.exe', 'rbd']
        try:
            self._execute(*cmd)
            return True
        except processutils.ProcessExecutionError:
            LOG.warning("rbd.exe is not available.")

        return False

    def _ensure_rbd_available(self):
        if not self._check_rbd():
            msg = _("rbd.exe is not available.")
            LOG.error(msg)
            raise exception.BrickException(msg)

    def get_volume_paths(self, connection_properties):
        return [self.get_device_name(connection_properties)]

    def _show_rbd_mapping(self, connection_properties):
        # TODO(lpetrut): consider using "rbd device show" if/when
        # it becomes available.
        cmd = ['rbd-wnbd', 'show', connection_properties['name'],
               '--format', 'json']
        try:
            out, err = self._execute(*cmd)
            return json.loads(out)
        except processutils.ProcessExecutionError as ex:
            if abs(ctypes.c_int32(ex.exit_code).value) == errno.ENOENT:
                LOG.debug("Couldn't find RBD mapping: %s",
                          connection_properties['name'])
                return
            raise
        except json.decoder.JSONDecodeError:
            msg = _("Could not get rbd mappping.")
            LOG.exception(msg)
            raise exception.BrickException(msg)

    def get_device_name(self, connection_properties, expect=True):
        mapping = self._show_rbd_mapping(connection_properties)
        if mapping:
            dev_num = mapping['disk_number']
            LOG.debug(
                "Located RBD mapping: %(image)s. "
                "Disk number: %(disk_number)s.",
                dict(image=connection_properties['name'],
                     disk_number=dev_num))
            return self._diskutils.get_device_name_by_device_number(dev_num)
        elif expect:
            msg = _("The specified RBD image is not mounted: %s")
            raise exception.VolumeDeviceNotFound(
                msg % connection_properties['name'])

    def _wait_for_volume(self, connection_properties):
        """Wait for the specified volume to become accessible."""
        attempt = 0
        dev_path = None

        def _check_rbd_device():
            rbd_dev_path = self.get_device_name(
                connection_properties, expect=False)
            if rbd_dev_path:
                try:
                    # Under high load, it can take a second before the disk
                    # becomes accessible.
                    with open(rbd_dev_path, 'rb'):
                        pass

                    nonlocal dev_path
                    dev_path = rbd_dev_path
                    raise loopingcall.LoopingCallDone()
                except FileNotFoundError:
                    LOG.debug("The RBD image %(image)s mapped to local device "
                              "%(dev)s isn't available yet.",
                              {'image': connection_properties['name'],
                               'dev': rbd_dev_path})
            nonlocal attempt
            attempt += 1
            if attempt >= self.device_scan_attempts:
                msg = _("The mounted RBD image isn't available: %s")
                raise exception.VolumeDeviceNotFound(
                    msg % connection_properties['name'])

        timer = loopingcall.FixedIntervalLoopingCall(_check_rbd_device)
        timer.start(interval=self.device_scan_interval).wait()
        return dev_path

    @utils.trace
    def connect_volume(self, connection_properties):
        rbd_dev_path = self.get_device_name(connection_properties,
                                            expect=False)
        if not rbd_dev_path:
            cmd = ['rbd', 'device', 'map', connection_properties['name']]
            cmd += self._get_rbd_args(connection_properties)
            self._execute(*cmd)

            rbd_dev_path = self._wait_for_volume(connection_properties)
        else:
            LOG.debug('The RBD image %(image)s is already mapped to local '
                      'device %(dev)s',
                      {'image': connection_properties['name'],
                       'dev': rbd_dev_path})

        dev_num = self._diskutils.get_device_number_from_device_name(
            rbd_dev_path)
        # TODO(lpetrut): remove this once wnbd honors the SAN policy setting.
        self._diskutils.set_disk_offline(dev_num)
        return {'path': rbd_dev_path,
                'type': 'block'}

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info=None,
                          force=False, ignore_errors=False):
        cmd = ['rbd', 'device', 'unmap', connection_properties['name']]
        cmd += self._get_rbd_args(connection_properties)
        if force:
            cmd += ["-o", "hard-disconnect"]
        self._execute(*cmd)
