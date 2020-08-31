# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import abc

from oslo_log import log as logging
from oslo_utils import importutils

from os_brick import exception
from os_brick.i18n import _


LOG = logging.getLogger(__name__)

CACHE_ENGINE_TO_CACHE_CLASS_MAP = {
    "opencas": 'os_brick.caches.opencas.OpenCASEngine',
}


class CacheEngineBase(object, metaclass=abc.ABCMeta):
    def __init__(self, **kwargs):
        self._root_helper = kwargs.get('root_helper')

    @abc.abstractmethod
    def is_engine_ready(self, **kwargs):
        return

    @abc.abstractmethod
    def attach_volume(self, **kwargs):
        return

    @abc.abstractmethod
    def detach_volume(self, **kwargs):
        return


class CacheManager():
    """Cache manager for volumes.

    This CacheManager uses cache engines to do volume cache.
    """
    def __init__(self, root_helper, connection_info,
                 *args, **kwargs):

        data = connection_info['data']
        if not data.get('device_path'):
            volume_id = data.get('volume_id') or connection_info.get('serial')
            raise exception.VolumeLocalCacheNotSupported(
                volume_id=volume_id,
                volume_type=connection_info.get('driver_volume_type'))

        self.ori_device_path = data.get('device_path')
        if not data.get('cacheable'):
            self.cacheable = False
            return

        self.cacheable = True
        self.root_helper = root_helper
        self.engine_name = kwargs.get('cache_name')
        self.args = args
        self.kwargs = kwargs
        self.kwargs["root_helper"] = root_helper
        self.kwargs["dev_path"] = data.get('device_path')
        self.engine = self._get_engine(self.engine_name, **self.kwargs)

    def _get_engine(self, engine_name, **kwargs):
        eng_cls_path = CACHE_ENGINE_TO_CACHE_CLASS_MAP.get(engine_name)
        if eng_cls_path:
            engine_cls = importutils.import_class(eng_cls_path)
            eng = engine_cls(**kwargs)
            if eng.is_engine_ready():
                return eng

        raise exception.Invalid(_("No valid cache engine"))

    def attach_volume(self):
        """setup the cache when attaching volume."""
        if not self.cacheable:
            return self.ori_device_path

        LOG.debug("volume before cached: %s", self.kwargs.get('dev_path'))
        emulated_disk = self.engine.attach_volume(**self.kwargs)
        LOG.debug("volume after cached: %s", emulated_disk)
        return emulated_disk

    def detach_volume(self):
        """Release the cache on detaching volume."""
        if not self.cacheable:
            return self.ori_device_path

        LOG.debug("volume before detach: %s", self.kwargs.get('dev_path'))
        ori_disk = self.engine.detach_volume(**self.kwargs)
        LOG.debug("volume after detach: %s", ori_disk)
        return ori_disk
