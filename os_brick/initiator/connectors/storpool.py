#    Copyright (c) 2015 - 2017 StorPool
#    All Rights Reserved.
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
import pathlib
import time

from oslo_log import log as logging
from oslo_utils import importutils

from os_brick import exception
from os_brick.initiator.connectors import base
from os_brick import utils

LOG = logging.getLogger(__name__)

spopenstack = importutils.try_import('storpool.spopenstack')
spapi = importutils.try_import('storpool.spapi')


DEV_STORPOOL = pathlib.Path('/dev/storpool')
DEV_STORPOOL_BYID = pathlib.Path('/dev/storpool-byid')


def path_to_volname(path: pathlib.Path) -> str:
    """Determine a volume name to pass to the StorPool API."""
    if path.parent == DEV_STORPOOL_BYID:
        return f"~{path.name}"

    if path.parent == DEV_STORPOOL:
        return path.name

    raise exception.BrickException('Unexpected device path %(path)s' %
                                   {'path': path})


class StorPoolConnector(base.BaseLinuxConnector):
    """"Connector class to attach/detach StorPool volumes."""

    def __init__(self, root_helper, driver=None,
                 *args, **kwargs):

        super(StorPoolConnector, self).__init__(root_helper, driver=driver,
                                                *args, **kwargs)

        if spapi is None:
            raise exception.BrickException(
                'Could not import the StorPool API bindings')

        if spopenstack is None:
            raise exception.BrickException(
                'Could not import the required module "storpool.spopenstack"')

        try:
            self._attach = spopenstack.AttachDB(log=LOG)
        except Exception as e:
            raise exception.BrickException(
                'Could not initialize the StorPool API bindings: %s' % (e))

        if "SP_OURID" not in self._attach.config():
            raise exception.BrickException(
                'Could not read "SP_OURID" from the StorPool configuration"')

    def _detach_retry(self, sp_ourid, volume):
        """Retry detaching.

        Retries attempt to handle LUKS tests-related failures:
          busy: volume ... open at ...
        """

        count = 10
        while True:
            try:
                force = count == 0
                self._attach.api().volumesReassignWait(
                    {
                        "reassign": [{
                            "volume": volume,
                            "detach": [sp_ourid],
                            "force": force,
                        }]
                    }
                )
                break
            except spapi.ApiError as exc:
                if (
                    exc.name in ("busy", "invalidParam")
                    and "is open at" in exc.desc
                ):
                    assert count > 0
                    time.sleep(0.2)
                    count -= 1
                else:
                    raise

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The StorPool connector properties."""
        return {}

    @utils.connect_volume_prepare_result
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes;
                                      it needs to contain the StorPool
                                      'client_id' and the common 'volume' and
                                      'access_mode' values.
        :type connection_properties: dict
        :returns: dict
        """
        client_id = connection_properties.get('client_id', None)
        if client_id is None:
            raise exception.BrickException(
                'Invalid StorPool connection data, no client ID specified.')
        volume_id = connection_properties.get('volume', None)
        if volume_id is None:
            raise exception.BrickException(
                'Invalid StorPool connection data, no volume ID specified.')
        volume = self._attach.volumeName(volume_id)
        mode = connection_properties.get('access_mode', None)
        if mode is None or mode not in ('rw', 'ro'):
            raise exception.BrickException(
                'Invalid access_mode specified in the connection data.')
        try:
            sp_ourid = self._attach.config()["SP_OURID"]
        except KeyError:
            raise exception.BrickException(
                'SP_OURID missing, cannot connect volume %s' % volume_id)

        try:
            self._attach.api().volumesReassignWait(
                {"reassign": [{"volume": volume, mode: [sp_ourid]}]})
        except Exception as exc:
            raise exception.BrickException(
                'Communication with the StorPool API '
                'failed: %s' % (exc)) from exc

        try:
            volume_info = self._attach.api().volumeInfo(volume)
        except Exception as exc:
            raise exception.BrickException(
                'Communication with the StorPool API '
                'failed: %s' % (exc)) from exc

        sp_global_id = volume_info.globalId
        return {'type': 'block',
                'path': str(DEV_STORPOOL_BYID) + '/' + sp_global_id}

    @utils.connect_volume_undo_prepare_result(unlink_after=True)
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Disconnect a volume from the local host.

        The connection_properties are the same as from connect_volume.
        The device_info is returned from connect_volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes;
                                      it needs to contain the StorPool
                                      'client_id' and the common 'volume'
                                      values.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        :param force: Whether to forcefully disconnect even if flush fails.
                      For StorPool, this parameter is ignored, the volume is
                      always detached.
        :type force: bool
        :param ignore_errors: When force is True, this will decide whether to
                              ignore errors or raise an exception once finished
                              the operation.  Default is False.
                              For StorPool, this parameter is ignored,
                              no exception is raised except on
                              unexpected errors.
        :type ignore_errors: bool
        """
        client_id = connection_properties.get('client_id', None)
        if client_id is None:
            raise exception.BrickException(
                'Invalid StorPool connection data, no client ID specified.')
        device_path = connection_properties.get('device_path', None)
        if device_path is None:
            LOG.debug('connection_properties is missing "device_path",'
                      ' looking for "path" inside device_info')
            if device_info:
                device_path = device_info.get('path', None)
        if device_path is None:
            raise exception.BrickException(
                'Invalid StorPool connection data, no device_path specified.')
        volume_name = path_to_volname(pathlib.Path(device_path))
        try:
            sp_ourid = self._attach.config()["SP_OURID"]
        except KeyError:
            raise exception.BrickException(
                'SP_OURID missing, cannot disconnect volume %s' % volume_name)
        try:
            self._detach_retry(sp_ourid, volume_name)
        except Exception as exc:
            raise exception.BrickException(
                'Communication with the StorPool API '
                'failed: %s' % (exc)) from exc

    def get_search_path(self):
        return '/dev/storpool'

    def get_volume_paths(self, connection_properties):
        """Return the list of existing paths for a volume.

        The job of this method is to find out what paths in
        the system are associated with a volume as described
        by the connection_properties.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes;
                                      it needs to contain 'volume' and
                                      'device_path' values.
        :type connection_properties: dict
        """
        volume_id = connection_properties.get('volume', None)
        if volume_id is None:
            raise exception.BrickException(
                'Invalid StorPool connection data, no volume ID specified.')
        volume = self._attach.volumeName(volume_id)
        path = '/dev/storpool/' + volume
        dpath = connection_properties.get('device_path', None)
        if dpath is not None and dpath != path:
            raise exception.BrickException(
                'Internal error: StorPool volume path %(path)s does not '
                'match device path %(dpath)s' %
                {'path': path, 'dpath': dpath})
        return [path]

    def get_all_available_volumes(self, connection_properties=None):
        """Return all volumes that exist in the search directory.

        At connect_volume time, a Connector looks in a specific
        directory to discover a volume's paths showing up.
        This method's job is to return all paths in the directory
        that connect_volume uses to find a volume.

        This method is used in coordination with get_volume_paths()
        to verify that volumes have gone away after disconnect_volume
        has been called.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
                                      Unused for the StorPool connector.
        :type connection_properties: dict
        """
        names = []
        prefix = self._attach.volumeName('')
        prefixlen = len(prefix)
        if os.path.isdir('/dev/storpool'):
            files = os.listdir('/dev/storpool')
            for entry in files:
                full = '/dev/storpool/' + entry
                if entry.startswith(prefix) and os.path.islink(full) and \
                   not os.path.isdir(full):
                    names.append(entry[prefixlen:])
        return names

    def _get_device_size(self, device):
        """Get the size in bytes of a volume."""
        (out, _err) = self._execute('blockdev', '--getsize64',
                                    device, run_as_root=True,
                                    root_helper=self._root_helper)
        var = str(out).strip()
        if var.isnumeric():
            return int(var)
        else:
            return None

    @utils.connect_volume_undo_prepare_result
    def extend_volume(self, connection_properties):
        """Update the attached volume's size.

        This method will attempt to update the local hosts's
        volume after the volume has been extended on the remote
        system.  The new volume size in bytes will be returned.
        If there is a failure to update, then None will be returned.

        :param connection_properties: The volume connection properties.
        :returns: new size of the volume.
        """
        # The StorPool client (storpool_block service) running on this host
        # should have picked up the change already, so it is enough to query
        # the actual disk device to see if its size is correct.
        #
        volume_id = connection_properties.get('volume', None)
        if volume_id is None:
            raise exception.BrickException(
                'Invalid StorPool connection data, no volume ID specified.')

        # Get the expected (new) size from the StorPool API
        volume = self._attach.volumeName(volume_id)
        LOG.debug('Querying the StorPool API for the size of %(vol)s',
                  {'vol': volume})
        vdata = self._attach.api().volumeList(volume)[0]
        LOG.debug('Got size %(size)d', {'size': vdata.size})

        # Wait for the StorPool client to update the size of the local device
        path = '/dev/storpool/' + volume
        for _ in range(10):
            size = utils.get_device_size(self, path)
            LOG.debug('Got local size %(size)d', {'size': size})
            if size == vdata.size:
                return size
            time.sleep(0.1)
        else:
            size = utils.get_device_size(self, path)
            LOG.debug('Last attempt: local size %(size)d', {'size': size})
            return size
