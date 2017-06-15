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

from oslo_concurrency import lockutils
from oslo_log import log as logging
from oslo_service import loopingcall

from os_brick import exception
from os_brick import initiator

from os_brick.initiator.connectors import base
from os_brick import utils

DEVICE_SCAN_ATTEMPTS_DEFAULT = 3
LOG = logging.getLogger(__name__)


class AoEConnector(base.BaseLinuxConnector):
    """Connector class to attach/detach AoE volumes."""

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(AoEConnector, self).__init__(
            root_helper,
            driver=driver,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The AoE connector properties."""
        return {}

    def get_search_path(self):
        return '/dev/etherd'

    def get_volume_paths(self, connection_properties):
        aoe_device, aoe_path = self._get_aoe_info(connection_properties)
        volume_paths = []
        if os.path.exists(aoe_path):
            volume_paths.append(aoe_path)

        return volume_paths

    def _get_aoe_info(self, connection_properties):
        shelf = connection_properties['target_shelf']
        lun = connection_properties['target_lun']
        aoe_device = 'e%(shelf)s.%(lun)s' % {'shelf': shelf,
                                             'lun': lun}
        path = self.get_search_path()
        aoe_path = '%(path)s/%(device)s' % {'path': path,
                                            'device': aoe_device}
        return aoe_device, aoe_path

    @utils.trace
    @lockutils.synchronized('aoe_control', 'aoe-')
    def connect_volume(self, connection_properties):
        """Discover and attach the volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict

        connection_properties for AoE must include:
        target_shelf - shelf id of volume
        target_lun - lun id of volume
        """
        aoe_device, aoe_path = self._get_aoe_info(connection_properties)

        device_info = {
            'type': 'block',
            'device': aoe_device,
            'path': aoe_path,
        }

        if os.path.exists(aoe_path):
            self._aoe_revalidate(aoe_device)
        else:
            self._aoe_discover()

        waiting_status = {'tries': 0}

        # NOTE(jbr_): Device path is not always present immediately
        def _wait_for_discovery(aoe_path):
            if os.path.exists(aoe_path):
                raise loopingcall.LoopingCallDone

            if waiting_status['tries'] >= self.device_scan_attempts:
                raise exception.VolumeDeviceNotFound(device=aoe_path)

            LOG.info("AoE volume not yet found at: %(path)s. "
                     "Try number: %(tries)s",
                     {'path': aoe_device, 'tries': waiting_status['tries']})

            self._aoe_discover()
            waiting_status['tries'] += 1

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_discovery,
                                                     aoe_path)
        timer.start(interval=2).wait()

        if waiting_status['tries']:
            LOG.debug("Found AoE device %(path)s "
                      "(after %(tries)s rediscover)",
                      {'path': aoe_path,
                       'tries': waiting_status['tries']})

        return device_info

    @utils.trace
    @lockutils.synchronized('aoe_control', 'aoe-')
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Detach and flush the volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict

        connection_properties for AoE must include:
        target_shelf - shelf id of volume
        target_lun - lun id of volume
        """
        aoe_device, aoe_path = self._get_aoe_info(connection_properties)

        if os.path.exists(aoe_path):
            self._aoe_flush(aoe_device)

    def _aoe_discover(self):
        (out, err) = self._execute('aoe-discover',
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=0)

        LOG.debug('aoe-discover: stdout=%(out)s stderr%(err)s',
                  {'out': out, 'err': err})

    def _aoe_revalidate(self, aoe_device):
        (out, err) = self._execute('aoe-revalidate',
                                   aoe_device,
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=0)

        LOG.debug('aoe-revalidate %(dev)s: stdout=%(out)s stderr%(err)s',
                  {'dev': aoe_device, 'out': out, 'err': err})

    def _aoe_flush(self, aoe_device):
        (out, err) = self._execute('aoe-flush',
                                   aoe_device,
                                   run_as_root=True,
                                   root_helper=self._root_helper,
                                   check_exit_code=0)
        LOG.debug('aoe-flush %(dev)s: stdout=%(out)s stderr%(err)s',
                  {'dev': aoe_device, 'out': out, 'err': err})

    def extend_volume(self, connection_properties):
        # TODO(walter-boring): is this possible?
        raise NotImplementedError
