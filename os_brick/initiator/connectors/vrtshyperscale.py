# Copyright (c) 2017 Veritas Technologies LLC.
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

import json

from oslo_concurrency import lockutils
from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator.connectors import base
from os_brick import utils

LOG = logging.getLogger(__name__)
synchronized = lockutils.synchronized_with_prefix('os-brick-vrts-hyperscale-')


class HyperScaleConnector(base.BaseLinuxConnector):
    """Class implements the os-brick connector for HyperScale volumes."""

    def __init__(self, root_helper, driver=None,
                 execute=None,
                 *args, **kwargs):

        super(HyperScaleConnector, self).__init__(
            root_helper, driver=driver,
            execute=execute,
            *args, **kwargs)

    def get_volume_paths(self, connection_properties):
        return []

    def get_search_path(self):
        return None

    def extend_volume(self, connection_properties):
        raise NotImplementedError

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The HyperScale connector properties."""
        return {}

    @utils.trace
    @synchronized('connect_volume')
    def connect_volume(self, connection_properties):
        """Connect a volume to an instance."""

        out = None
        err = None
        device_info = {}
        volume_name = None

        if 'name' in connection_properties.keys():
            volume_name = connection_properties['name']

        if volume_name is None:
            msg = _("Failed to connect volume: invalid volume name.")
            raise exception.BrickException(message=msg)

        cmd_arg = {'operation': 'connect_volume'}
        cmd_arg['volume_guid'] = volume_name
        cmdarg_json = json.dumps(cmd_arg)

        LOG.debug("HyperScale command hscli: %(cmd_arg)s",
                  {'cmd_arg': cmdarg_json})
        try:
            (out, err) = self._execute('hscli', cmdarg_json,
                                       run_as_root=True,
                                       root_helper=self._root_helper)

        except putils.ProcessExecutionError as e:
            msg = (_("Error executing hscli: %(err)s") % {'err': e.stderr})
            raise exception.BrickException(message=msg)

        LOG.debug("Result of hscli: stdout=%(out)s "
                  "stderr=%(err)s",
                  {'out': out, 'err': err})

        if err or out is None or len(out) == 0:
            msg = (_("Failed to connect volume with stdout=%(out)s "
                     "stderr=%(err)s") % {'out': out, 'err': err})
            raise exception.BrickException(message=msg)

        output = json.loads(out)
        payload = output.get('payload')
        if payload is None:
            msg = _("Failed to connect volume: "
                    "hscli returned invalid payload")
            raise exception.BrickException(message=msg)

        if ('vsa_ip' not in payload.keys() or
                'refl_factor' not in payload.keys()):
            msg = _("Failed to connect volume: "
                    "hscli returned invalid results")
            raise exception.BrickException(message=msg)

        device_info['vsa_ip'] = payload.get('vsa_ip')
        device_info['path'] = (
            '/dev/' + connection_properties['name'][1:32])
        refl_factor = int(payload.get('refl_factor'))
        device_info['refl_factor'] = str(refl_factor)

        if refl_factor > 0:
            if 'refl_targets' not in payload.keys():
                msg = _("Failed to connect volume: "
                        "hscli returned inconsistent results")
                raise exception.BrickException(message=msg)

            device_info['refl_targets'] = (
                payload.get('refl_targets'))

        return device_info

    @utils.trace
    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Disconnect a volume from an instance."""
        volume_name = None

        if 'name' in connection_properties.keys():
            volume_name = connection_properties['name']

        if volume_name is None:
            msg = _("Failed to disconnect volume: invalid volume name")
            raise exception.BrickException(message=msg)

        cmd_arg = {'operation': 'disconnect_volume'}
        cmd_arg['volume_guid'] = volume_name
        cmdarg_json = json.dumps(cmd_arg)

        LOG.debug("HyperScale command hscli: %(cmd_arg)s",
                  {'cmd_arg': cmdarg_json})
        try:
            (out, err) = self._execute('hscli', cmdarg_json,
                                       run_as_root=True,
                                       root_helper=self._root_helper)

        except putils.ProcessExecutionError as e:
            msg = (_("Error executing hscli: %(err)s") % {'err': e.stderr})
            raise exception.BrickException(message=msg)

        if err:
            msg = (_("Failed to connect volume: stdout=%(out)s "
                     "stderr=%(err)s") % {'out': out, 'err': err})
            raise exception.BrickException(message=msg)
