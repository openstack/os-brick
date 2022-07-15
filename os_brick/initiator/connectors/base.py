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


import functools
import glob
import os

from oslo_concurrency import lockutils
from oslo_concurrency import processutils as putils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import reflection
from oslo_utils import timeutils

from os_brick import exception
from os_brick import initiator
from os_brick.initiator import host_driver
from os_brick.initiator import initiator_connector
from os_brick.initiator import linuxscsi

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def synchronized(name, lock_file_prefix='os-brick-', external=False,
                 lock_path=None, semaphores=None, delay=0.01, fair=False,
                 blocking=True):
    """os-brick synchronization decorator

    Like the one in lock_utils but defaulting the prefix to os-brick- and using
    our own lock_path.

    Cannot use lock_utils one because when using the default we don't know the
    value until setup has been called, which can be after the code using the
    decorator has been loaded.
    """
    def wrap(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            t1 = timeutils.now()
            t2 = None
            gotten = True
            lpath = lock_path or CONF.os_brick.lock_path
            # TODO: (AA Release) Remove this failsafe
            if not lpath and CONF.oslo_concurrency.lock_path:
                LOG.warning("Service needs to call os_brick.setup() before "
                            "connecting volumes, if it doesn't it will break "
                            "on the next release")
                lpath = CONF.oslo_concurrency.lock_path
            f_name = reflection.get_callable_name(f)
            try:
                LOG.debug('Acquiring lock "%s" by "%s"', name, f_name)
                with lockutils.lock(name, lock_file_prefix, external, lpath,
                                    do_log=False, semaphores=semaphores,
                                    delay=delay, fair=fair, blocking=blocking):
                    t2 = timeutils.now()
                    LOG.debug('Lock "%(name)s" acquired by "%(function)s" :: '
                              'waited %(wait_secs)0.3fs',
                              {'name': name,
                               'function': f_name,
                               'wait_secs': (t2 - t1)})
                    return f(*args, **kwargs)
            except lockutils.AcquireLockFailedException:
                gotten = False
            finally:
                t3 = timeutils.now()
                if t2 is None:
                    held_secs = "N/A"
                else:
                    held_secs = "%0.3fs" % (t3 - t2)
                LOG.debug('Lock "%(name)s" "%(gotten)s" by "%(function)s" ::'
                          ' held %(held_secs)s',
                          {'name': name,
                           'gotten': 'released' if gotten else 'unacquired',
                           'function': f_name,
                           'held_secs': held_secs})
        return inner

    return wrap


class BaseLinuxConnector(initiator_connector.InitiatorConnector):
    os_type = initiator.OS_TYPE_LINUX

    def __init__(self, root_helper: str, driver=None, execute=None,
                 *args, **kwargs):
        self._linuxscsi = linuxscsi.LinuxSCSI(root_helper, execute=execute)

        if not driver:
            driver = host_driver.HostDriver()
        self.set_driver(driver)

        super(BaseLinuxConnector, self).__init__(root_helper, execute=execute,
                                                 *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper: str, *args, **kwargs) -> dict:
        """The generic connector properties."""
        multipath = kwargs['multipath']
        enforce_multipath = kwargs['enforce_multipath']
        props = {}

        props['multipath'] = (multipath and
                              linuxscsi.LinuxSCSI.is_multipath_running(
                                  enforce_multipath, root_helper,
                                  execute=kwargs.get('execute')))

        return props

    def check_valid_device(self, path: str, run_as_root: bool = True) -> bool:
        cmd = ('dd', 'if=%(path)s' % {"path": path},
               'of=/dev/null', 'count=1')
        out, info = None, None
        try:
            out, info = self._execute(*cmd, run_as_root=run_as_root,
                                      root_helper=self._root_helper)
        except putils.ProcessExecutionError as e:
            LOG.error("Failed to access the device on the path "
                      "%(path)s: %(error)s.",
                      {"path": path, "error": e.stderr})
            return False
        # If the info is none, the path does not exist.
        if info is None:
            return False
        return True

    def get_all_available_volumes(self, connection_properties=None):
        volumes = []
        path = self.get_search_path()
        if path:
            # now find all entries in the search path
            if os.path.isdir(path):
                path_items = [path, '/*']
                file_filter = ''.join(path_items)
                volumes = glob.glob(file_filter)

        return volumes

    def _discover_mpath_device(self,
                               device_wwn: str,
                               connection_properties: dict,
                               device_name: str) -> tuple:
        """This method discovers a multipath device.

        Discover a multipath device based on a defined connection_property
        and a device_wwn and return the multipath_id and path of the multipath
        enabled device if there is one.
        """

        path = self._linuxscsi.find_multipath_device_path(device_wwn)
        device_path = None
        multipath_id = None

        if path is None:
            # find_multipath_device only accept realpath not symbolic path
            device_realpath = os.path.realpath(device_name)
            mpath_info = self._linuxscsi.find_multipath_device(
                device_realpath)
            if mpath_info:
                device_path = mpath_info['device']
                multipath_id = device_wwn
            else:
                # we didn't find a multipath device.
                # so we assume the kernel only sees 1 device
                device_path = device_name
                LOG.debug("Unable to find multipath device name for "
                          "volume. Using path %(device)s for volume.",
                          {'device': device_path})
        else:
            device_path = path
            multipath_id = device_wwn
        if connection_properties.get('access_mode', '') != 'ro':
            try:
                # Sometimes the multipath devices will show up as read only
                # initially and need additional time/rescans to get to RW.
                self._linuxscsi.wait_for_rw(device_wwn, device_path)
            except exception.BlockDeviceReadOnly:
                LOG.warning('Block device %s is still read-only. '
                            'Continuing anyway.', device_path)
        return device_path, multipath_id
