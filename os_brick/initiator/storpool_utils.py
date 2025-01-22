#    Copyright (c) 2015 - 2024 StorPool
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

import configparser
import errno
import http.client
import json
import os
import pathlib
import platform
import socket
import time

from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _

LOG = logging.getLogger(__name__)

DEV_STORPOOL = pathlib.Path('/dev/storpool')
DEV_STORPOOL_BYID = pathlib.Path('/dev/storpool-byid')


STORPOOL_CONF_DEFAULTS = {
    "SP_API_HTTP_HOST": "127.0.0.1",
    "SP_API_HTTP_PORT": "81",
}


ENV_OVERRIDE = ["SP_AUTH_TOKEN", "SP_API_HTTP_HOST", "SP_API_HTTP_PORT"]


def get_conf(section=None, use_env=True):
    """Load the StorPool configuration from files and the environment."""
    config_path = pathlib.Path('/etc/storpool.conf')
    config_dir_path = pathlib.Path('/etc/storpool.conf.d')

    def _read_with_unnamed(a_parser, file):
        with open(file) as stream:
            a_parser.read_string('[UNNAMED_SECTION]\n' + stream.read())

    def _get_env_overrides():
        overrides = {}
        for override in ENV_OVERRIDE:
            if (value := os.environ.get(override)) is not None:
                overrides[override] = value
        return overrides

    parser = configparser.ConfigParser(strict=False, allow_no_value=True)
    parser.optionxform = str

    if not config_path.is_file():
        message = "File %(file)s does not exist or not a file"
        raise exception.BrickException(message, file=config_path)

    _read_with_unnamed(parser, config_path)

    if config_dir_path.is_dir():
        for path in sorted(config_dir_path.iterdir()):
            path_str = str(path)
            if path.is_file() \
                and path_str.endswith(".conf") \
                    and not path_str.startswith("."):
                _read_with_unnamed(parser, path)

    if section is None:
        section = platform.node()

    conf = dict(STORPOOL_CONF_DEFAULTS)
    for sect in ['UNNAMED_SECTION', section]:
        if parser.has_section(sect):
            conf.update(dict(parser[sect]))

    if use_env:
        conf.update(_get_env_overrides())

    return conf


def os_to_sp_volume_name(prefix, volume_id):
    return "{pfx}--volume-{id}".format(pfx=prefix, id=volume_id)


def os_to_sp_snapshot_name(prefix, type, snapshot_id, more=None):
    return "{pfx}--{t}--{m}--snapshot-{id}".format(
        pfx=prefix,
        t=type,
        m="none" if more is None else more,
        id=snapshot_id,
    )


class StorPoolAPIError(exception.BrickException):
    """Borrowed from `storpool.spapi`"""
    message = _("HTTP: %(status)s, %(name)s: %(desc)s")

    def __init__(self, status, json):
        self.status = status
        self.json = json
        self.name = json['error'].get('name', "<Missing error name>")
        self.desc = json['error'].get('descr', "<Missing error description>")
        self.transient = json['error'].get('transient', False)

        super(StorPoolAPIError, self).__init__(
            status=status, name=self.name, desc=self.desc)


class StorPoolAPI:
    """A subset of the Python package `storpool` for a StorPool API client."""

    def __init__(self, host, port, auth, timeout = 300, transient_retries = 5):
        self.url = f"{host}:{port}"
        self.auth_header = {'Authorization': f'Storpool v1:{auth}'}
        self.timeout = timeout
        self.transient_retries = transient_retries

    def _api_call(self, method, path, body = None):
        retry = 0
        last_error = None
        while True:
            connection = None
            try:
                connection = http.client.HTTPConnection(
                    self.url, timeout=self.timeout)
                if body:
                    body = json.dumps(body)
                connection.request(method, path, body, self.auth_header)
                response = connection.getresponse()
                status, jres = response.status, json.load(response)

                if status == http.client.OK and 'error' not in jres:
                    return jres['data']

                last_error = StorPoolAPIError(status, jres)
                if not jres['error'].get('transient', False):
                    raise last_error
            except (socket.error, http.client.HTTPException) as err:
                if not (isinstance(err, http.client.HTTPException) or
                        err.errno in (errno.ECONNREFUSED, errno.ECONNRESET)):
                    raise
                last_error = err
            finally:
                if connection:
                    connection.close()

            if retry >= self.transient_retries:
                raise last_error

            time.sleep(2**retry)
            retry += 1

    def disks_list(self):
        return self._api_call('GET', '/ctrl/1.0/DisksList')

    def volume_templates_list(self):
        return self._api_call('GET', '/ctrl/1.0/VolumeTemplatesList')

    def volumes_reassign(self, data):
        self._api_call('POST', '/ctrl/1.0/MultiCluster/VolumesReassign', data)

    def volumes_reassign_wait(self, data):
        self._api_call(
            'POST', '/ctrl/1.0/MultiCluster/VolumesReassignWait', data)

    def volume(self, volume):
        return self._api_call(
            'GET', f'/ctrl/1.0/MultiCluster/Volume/{volume}')

    def volume_create(self, data):
        self._api_call('POST', '/ctrl/1.0/MultiCluster/VolumeCreate', data)

    def volume_get_info(self, volume):
        return self._api_call(
            'GET', f'/ctrl/1.0/MultiCluster/VolumeGetInfo/{volume}')

    def volume_update(self, volume, data):
        self._api_call(
            'POST', f'/ctrl/1.0/MultiCluster/VolumeUpdate/{volume}', data)

    def volume_revert(self, volume, data):
        self._api_call(
            'POST', f'/ctrl/1.0/MultiCluster/VolumeRevert/{volume}', data)

    def volume_delete(self, volume):
        self._api_call('POST', f'/ctrl/1.0/MultiCluster/VolumeDelete/{volume}')

    def volumes_list(self):
        return self._api_call('GET', '/ctrl/1.0/MultiCluster/VolumesList')

    def snapshot_create(self, volume, data):
        self._api_call(
            'POST', f'/ctrl/1.0/MultiCluster/VolumeSnapshot/{volume}', data)

    def snapshot_update(self, snapshot, data):
        self._api_call(
            'POST', f'/ctrl/1.0/SnapshotUpdate/{snapshot}', data)

    def snapshot_delete(self, snapshot):
        self._api_call(
            'POST', f'/ctrl/1.0/MultiCluster/SnapshotDelete/{snapshot}')

    def get_iscsi_config(self):
        return self._api_call('GET', '/ctrl/1.0/iSCSIConfig')

    def post_iscsi_config(self, data):
        return self._api_call('POST', '/ctrl/1.0/iSCSIConfig', data)
