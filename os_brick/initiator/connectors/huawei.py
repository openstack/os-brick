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

from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator.connectors import base
from os_brick import utils

LOG = logging.getLogger(__name__)


class HuaweiStorHyperConnector(base.BaseLinuxConnector):
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
            LOG.error('SDS CLI file not found, '
                      'HuaweiStorHyperConnector init failed.')
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

    @utils.trace
    @base.synchronized('connect_volume', external=True)
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

    @utils.trace
    @base.synchronized('connect_volume', external=True)
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
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
            LOG.error("SDS CLI output some log: %s.", clilog)
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
