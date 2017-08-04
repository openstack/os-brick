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

from os_win import exceptions as os_win_exc
from os_win import utilsfactory
from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator.connectors import base_iscsi
from os_brick.initiator.windows import base as win_conn_base
from os_brick import utils

LOG = logging.getLogger(__name__)


class WindowsISCSIConnector(win_conn_base.BaseWindowsConnector,
                            base_iscsi.BaseISCSIConnector):
    def __init__(self, *args, **kwargs):
        super(WindowsISCSIConnector, self).__init__(*args, **kwargs)
        self.use_multipath = kwargs.pop('use_multipath', False)
        self.initiator_list = kwargs.pop('initiator_list', [])

        self._iscsi_utils = utilsfactory.get_iscsi_initiator_utils()

        self.validate_initiators()

    def validate_initiators(self):
        """Validates the list of requested initiator HBAs

        Validates the list of requested initiator HBAs to be used
        when establishing iSCSI sessions.
        """
        valid_initiator_list = True
        if not self.initiator_list:
            LOG.info("No iSCSI initiator was explicitly requested. "
                     "The Microsoft iSCSI initiator will choose the "
                     "initiator when establishing sessions.")
        else:
            available_initiators = self._iscsi_utils.get_iscsi_initiators()
            for initiator in self.initiator_list:
                if initiator not in available_initiators:
                    LOG.warning("The requested initiator %(req_initiator)s "
                                "is not in the list of available initiators: "
                                "%(avail_initiators)s.",
                                dict(req_initiator=initiator,
                                     avail_initiators=available_initiators))
                    valid_initiator_list = False
        return valid_initiator_list

    def get_initiator(self):
        """Returns the iSCSI initiator node name."""
        return self._iscsi_utils.get_iscsi_initiator()

    @staticmethod
    def get_connector_properties(*args, **kwargs):
        iscsi_utils = utilsfactory.get_iscsi_initiator_utils()
        initiator = iscsi_utils.get_iscsi_initiator()
        return dict(initiator=initiator)

    def _get_all_paths(self, connection_properties):
        initiator_list = self.initiator_list or [None]
        all_targets = self._get_all_targets(connection_properties)
        paths = [(initiator_name, target_portal, target_iqn, target_lun)
                 for target_portal, target_iqn, target_lun in all_targets
                 for initiator_name in initiator_list]
        return paths

    @utils.trace
    def connect_volume(self, connection_properties):
        connected_target_mappings = set()
        volume_connected = False

        for (initiator_name,
             target_portal,
             target_iqn,
             target_lun) in self._get_all_paths(connection_properties):
            try:
                LOG.info("Attempting to establish an iSCSI session to "
                         "target %(target_iqn)s on portal %(target_portal)s "
                         "accessing LUN %(target_lun)s using initiator "
                         "%(initiator_name)s.",
                         dict(target_portal=target_portal,
                              target_iqn=target_iqn,
                              target_lun=target_lun,
                              initiator_name=initiator_name))
                self._iscsi_utils.login_storage_target(
                    target_lun=target_lun,
                    target_iqn=target_iqn,
                    target_portal=target_portal,
                    auth_username=connection_properties.get('auth_username'),
                    auth_password=connection_properties.get('auth_password'),
                    mpio_enabled=self.use_multipath,
                    initiator_name=initiator_name,
                    ensure_lun_available=False)

                connected_target_mappings.add((target_iqn, target_lun))

                if not self.use_multipath:
                    break
            except os_win_exc.OSWinException:
                LOG.exception("Could not establish the iSCSI session.")

        for target_iqn, target_lun in connected_target_mappings:
            try:
                (device_number,
                 device_path) = self._iscsi_utils.get_device_number_and_path(
                    target_iqn, target_lun,
                    retry_attempts=self.device_scan_attempts,
                    retry_interval=self.device_scan_interval,
                    rescan_disks=True,
                    ensure_mpio_claimed=self.use_multipath)
                volume_connected = True
            except os_win_exc.OSWinException:
                LOG.exception("Could not retrieve device path for target "
                              "%(target_iqn)s and lun %(target_lun)s.",
                              dict(target_iqn=target_iqn,
                                   target_lun=target_lun))

        if not volume_connected:
            raise exception.BrickException(
                _("Could not connect volume %s.") % connection_properties)

        scsi_wwn = self._get_scsi_wwn(device_number)

        device_info = {'type': 'block',
                       'path': device_path,
                       'number': device_number,
                       'scsi_wwn': scsi_wwn}
        return device_info

    @utils.trace
    def disconnect_volume(self, connection_properties, device_info=None,
                          force=False, ignore_errors=False):
        # We want to refresh the cached information first.
        self._diskutils.rescan_disks()
        for (target_portal,
             target_iqn,
             target_lun) in self._get_all_targets(connection_properties):

            luns = self._iscsi_utils.get_target_luns(target_iqn)
            # We disconnect the target only if it does not expose other
            # luns which may be in use.
            if not luns or luns == [target_lun]:
                self._iscsi_utils.logout_storage_target(target_iqn)

    @utils.trace
    def get_volume_paths(self, connection_properties):
        device_paths = set()

        for (target_portal,
             target_iqn,
             target_lun) in self._get_all_targets(connection_properties):

            (device_number,
             device_path) = self._iscsi_utils.get_device_number_and_path(
                target_iqn, target_lun,
                ensure_mpio_claimed=self.use_multipath)
            if device_path:
                device_paths.add(device_path)

        self._check_device_paths(device_paths)
        return list(device_paths)
