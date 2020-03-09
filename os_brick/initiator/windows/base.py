# Copyright 2016 Cloudbase Solutions Srl
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

from os_win import utilsfactory
from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator import initiator_connector
from os_brick import utils

LOG = logging.getLogger(__name__)


class BaseWindowsConnector(initiator_connector.InitiatorConnector):
    platform = initiator.PLATFORM_ALL
    os_type = initiator.OS_TYPE_WINDOWS

    DEFAULT_DEVICE_SCAN_INTERVAL = 2

    def __init__(self, root_helper=None, *args, **kwargs):
        kwargs['executor'] = kwargs.get('executor') or putils.execute
        super(BaseWindowsConnector, self).__init__(root_helper,
                                                   *args, **kwargs)
        self.device_scan_interval = kwargs.pop(
            'device_scan_interval', self.DEFAULT_DEVICE_SCAN_INTERVAL)

        self._diskutils = utilsfactory.get_diskutils()

    @staticmethod
    def check_multipath_support(enforce_multipath):
        hostutils = utilsfactory.get_hostutils()
        mpio_enabled = hostutils.check_server_feature(
            hostutils.FEATURE_MPIO)
        if not mpio_enabled:
            err_msg = _("Using multipath connections for iSCSI and FC disks "
                        "requires the Multipath IO Windows feature to be "
                        "enabled. MPIO must be configured to claim such "
                        "devices.")
            LOG.error(err_msg)
            if enforce_multipath:
                raise exception.BrickException(err_msg)
            return False
        return True

    @staticmethod
    def get_connector_properties(*args, **kwargs):
        multipath = kwargs['multipath']
        enforce_multipath = kwargs['enforce_multipath']

        props = {}
        props['multipath'] = (
            multipath and
            BaseWindowsConnector.check_multipath_support(enforce_multipath))
        return props

    def _get_scsi_wwn(self, device_number):
        # NOTE(lpetrut): The Linux connectors use scsi_id to retrieve the
        # disk unique id, which prepends the identifier type to the unique id
        # retrieved from the page 83 SCSI inquiry data. We'll do the same
        # to remain consistent.
        disk_uid, uid_type = self._diskutils.get_disk_uid_and_uid_type(
            device_number)
        scsi_wwn = '%s%s' % (uid_type, disk_uid)
        return scsi_wwn

    def check_valid_device(self, path, *args, **kwargs):
        try:
            with open(path, 'r') as dev:
                dev.read(1)
        except IOError:
            LOG.exception(
                "Failed to access the device on the path "
                "%(path)s", {"path": path})
            return False
        return True

    def get_all_available_volumes(self):
        # TODO(lpetrut): query for disks based on the protocol used.
        return []

    def _check_device_paths(self, device_paths):
        if len(device_paths) > 1:
            err_msg = _("Multiple volume paths were found: %s. This can "
                        "occur if multipath is used and MPIO is not "
                        "properly configured, thus not claiming the device "
                        "paths. This issue must be addressed urgently as "
                        "it can lead to data corruption.")
            raise exception.BrickException(err_msg % device_paths)

    @utils.trace
    def extend_volume(self, connection_properties):
        volume_paths = self.get_volume_paths(connection_properties)
        if not volume_paths:
            err_msg = _("Could not find the disk. Extend failed.")
            raise exception.NotFound(err_msg)

        device_path = volume_paths[0]
        device_number = self._diskutils.get_device_number_from_device_name(
            device_path)
        self._diskutils.refresh_disk(device_number)

    def get_search_path(self):
        return None
