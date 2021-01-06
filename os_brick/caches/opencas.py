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

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import caches
from os_brick import exception
from os_brick import executor


LOG = logging.getLogger(__name__)


class OpenCASEngine(executor.Executor, caches.CacheEngineBase):
    def __init__(self, **kwargs):
        super(OpenCASEngine, self).__init__(**kwargs)

        self.cache_id = kwargs.get('opencas_cache_id')

    def os_execute(self, *cmd, **kwargs):
        LOG.debug('os_execute: cmd: %s, args: %s', cmd, kwargs)
        try:
            out, err = self._execute(*cmd, **kwargs)
        except putils.ProcessExecutionError as err:
            LOG.exception('os_execute error')
            LOG.error('Cmd     :%s', err.cmd)
            LOG.error('StdOut  :%s', err.stdout)
            LOG.error('StdErr  :%s', err.stderr)
            raise
        return out, err

    def is_engine_ready(self, **kwargs):
        """'casadm -L' will print like:

        type    id   disk           status    write policy   device
        cache   1    /dev/nvme0n1   Running   wt             -
        """
        cmd = ['casadm', '-L']
        kwargs = dict(run_as_root=True,
                      root_helper=self._root_helper)
        out, err = self.os_execute(*cmd, **kwargs)

        for line in out.splitlines():
            fields = line.split()
            if str(self.cache_id) == fields[1] and 'Running' == fields[3]:
                return True

        return False

    def attach_volume(self, **kwargs):
        core = kwargs.get('dev_path')
        if core is None:
            LOG.error('dev_path is not specified')
            raise exception.VolumePathsNotFound()
        core = os.path.realpath(core)
        return self._map_casdisk(core)

    def detach_volume(self, **kwargs):
        casdev = kwargs.get('dev_path')
        if casdev is None:
            LOG.error('dev_path is not specified')
            raise exception.VolumePathsNotFound()
        coreid, coredev = self._get_mapped_coredev(casdev)
        LOG.info("opencas: coreid=%s,coredev=%s", coreid, coredev)
        self._unmap_casdisk(coreid)
        return coredev

    def _get_mapped_casdev(self, core):
        cmd = ['casadm', '-L']
        kwargs = dict(run_as_root=True,
                      root_helper=self._root_helper)
        out, err = self.os_execute(*cmd, **kwargs)

        for line in out.splitlines():
            if line.find(core) < 0:
                continue
            fields = line.split()
            return fields[5]

        raise exception.BrickException('Cannot find emulated device.')

    def _get_mapped_coredev(self, casdev):
        cmd = ['casadm', '-L']
        kwargs = dict(run_as_root=True,
                      root_helper=self._root_helper)
        out, err = self.os_execute(*cmd, **kwargs)

        for line in out.splitlines():
            if line.find(casdev) < 0:
                continue
            fields = line.split()
            return (fields[1], fields[2])

        raise exception.BrickException('Cannot find core device.')

    def _map_casdisk(self, core):
        cmd = ['casadm', '-A', '-i', self.cache_id, '-d', core]
        kwargs = dict(run_as_root=True,
                      root_helper=self._root_helper)
        out, err = self.os_execute(*cmd, **kwargs)

        return self._get_mapped_casdev(core)

    def _unmap_casdisk(self, coreid):
        cmd = ['casadm', '-R', '-f', '-i', self.cache_id, '-j', coreid]
        kwargs = dict(run_as_root=True,
                      root_helper=self._root_helper)
        out, err = self.os_execute(*cmd, **kwargs)
