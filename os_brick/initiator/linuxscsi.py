# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

"""Generic linux scsi subsystem and Multipath utilities.

   Note, this is not iSCSI.
"""
import glob
import os
import re
import time
from typing import Dict, List, Optional  # noqa: H301

from oslo_concurrency import processutils as putils
from oslo_log import log as logging
from oslo_utils import excutils

from os_brick import exception
from os_brick import executor
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick import utils

LOG = logging.getLogger(__name__)

MULTIPATH_ERROR_REGEX = re.compile(r"\w{3} \d+ \d\d:\d\d:\d\d \|.*$")
MULTIPATH_WWID_REGEX = re.compile(r"\((?P<wwid>.+)\)")
MULTIPATH_DEVICE_ACTIONS = ['unchanged:', 'reject:', 'reload:',
                            'switchpg:', 'rename:', 'create:',
                            'resize:']
MULTIPATHD_RESIZE_TIMEOUT = 120


class LinuxSCSI(executor.Executor):
    # As found in drivers/scsi/scsi_lib.c
    WWN_TYPES = {'t10.': '1', 'eui.': '2', 'naa.': '3'}

    def echo_scsi_command(self, path, content) -> None:
        """Used to echo strings to scsi subsystem."""

        args = ["-a", path]
        kwargs = dict(process_input=content,
                      run_as_root=True,
                      root_helper=self._root_helper)
        self._execute('tee', *args, **kwargs)

    def get_name_from_path(self, path) -> Optional[str]:
        """Translates /dev/disk/by-path/ entry to /dev/sdX."""

        name = os.path.realpath(path)
        if name.startswith("/dev/"):
            return name
        else:
            return None

    def remove_scsi_device(self,
                           device: str,
                           force: bool = False,
                           exc=None,
                           flush: bool = True) -> None:
        """Removes a scsi device based upon /dev/sdX name."""
        path = "/sys/block/%s/device/delete" % device.replace("/dev/", "")
        if os.path.exists(path):
            exc = exception.ExceptionChainer() if exc is None else exc
            if flush:
                # flush any outstanding IO first
                with exc.context(force, 'Flushing %s failed', device):
                    self.flush_device_io(device)

            LOG.debug("Remove SCSI device %(device)s with %(path)s",
                      {'device': device, 'path': path})
            with exc.context(force, 'Removing %s failed', device):
                self.echo_scsi_command(path, "1")

    def wait_for_volumes_removal(self, volumes_names: List[str]) -> None:
        """Wait for device paths to be removed from the system."""
        str_names = ', '.join(volumes_names)
        LOG.debug('Checking to see if SCSI volumes %s have been removed.',
                  str_names)
        exist = ['/dev/' + volume_name for volume_name in volumes_names]

        # It can take up to 30 seconds to remove a SCSI device if the path
        # failed right before we start detaching, which is unlikely, but we
        # still shouldn't fail in that case.
        for i in range(61):
            exist = [path for path in exist if os.path.exists(path)]
            if not exist:
                LOG.debug("SCSI volumes %s have been removed.", str_names)
                return
            # Don't sleep on the last try since we are quitting
            if i < 60:
                time.sleep(0.5)
                # Log every 5 seconds
                if i % 10 == 0:
                    LOG.debug('%s still exist.', ', '.join(exist))
        raise exception.VolumePathNotRemoved(volume_path=exist)

    def get_device_info(self, device: str) -> Dict[str, Optional[str]]:
        dev_info = {'device': device, 'host': None,
                    'channel': None, 'id': None, 'lun': None}
        # The input argument 'device' can be of 2 types:
        # (a) /dev/disk/by-path/XXX which is a symlink to /dev/sdX device
        # (b) /dev/sdX
        # If it's a symlink, get the /dev/sdX name first
        if os.path.islink(device):
            device = '/dev/' + os.readlink(device).split('/')[-1]
        # Else it's already a /dev/sdX device.
        # Then get it from lsscsi output
        (out, _err) = self._execute('lsscsi')
        if out:
            for line in out.strip().split('\n'):
                # The last column of lsscsi is device name
                if line.split()[-1] == device:
                    # The first column of lsscsi is [H:C:T:L]
                    hctl_info = line.split()[0].strip('[]').split(':')
                    dev_info['host'] = hctl_info[0]
                    dev_info['channel'] = hctl_info[1]
                    dev_info['id'] = hctl_info[2]
                    dev_info['lun'] = hctl_info[3]
                    break

        LOG.debug('dev_info=%s', str(dev_info))
        return dev_info

    def get_sysfs_wwn(self, device_names, mpath=None) -> str:
        """Return the wwid from sysfs in any of devices in udev format."""
        # If we have a multipath DM we know that it has found the WWN
        if mpath:
            # We have the WWN in /uuid even with friendly names, unline /name
            try:
                with open('/sys/block/%s/dm/uuid' % mpath) as f:
                    # Contents are matph-WWN, so get the part we want
                    wwid = f.read().strip()[6:]
                    if wwid:  # Check should not be needed, but just in case
                        return wwid
            except Exception as exc:
                LOG.warning('Failed to read the DM uuid: %s', exc)

        wwid = self.get_sysfs_wwid(device_names)
        glob_str = '/dev/disk/by-id/scsi-'
        wwn_paths = glob.glob(glob_str + '*')
        # If we don't have multiple designators on page 0x83
        if wwid and glob_str + wwid in wwn_paths:
            return wwid

        # If we have multiple designators use symlinks to find out the wwn
        device_names = set(device_names)
        for wwn_path in wwn_paths:
            try:
                if os.path.islink(wwn_path) and os.stat(wwn_path):
                    path = os.path.realpath(wwn_path)
                    if path.startswith('/dev/'):
                        name = path[5:]
                        # Symlink may point to the multipath dm if the attach
                        # was too fast or we took long to check it. Check
                        # devices belonging to the multipath DM.
                        if name.startswith('dm-'):
                            # Get the devices that belong to the DM
                            slaves_path = '/sys/class/block/%s/slaves' % name
                            dm_devs = os.listdir(slaves_path)
                            # This is the right wwn_path if the devices we have
                            # attached belong to the dm we followed
                            if device_names.intersection(dm_devs):
                                break

                        # This is the right wwn_path if  devices we have
                        elif name in device_names:
                            break
            except OSError:
                continue
        else:
            return ''
        return wwn_path[len(glob_str):]

    def get_sysfs_wwid(self, device_names):
        """Return the wwid from sysfs in any of devices in udev format."""
        for device_name in device_names:
            try:
                with open('/sys/block/%s/device/wwid' % device_name) as f:
                    wwid = f.read().strip()
            except IOError:
                continue
            # The sysfs wwid has the wwn type in string format as a prefix,
            # but udev uses its numerical representation as returned by
            # scsi_id's page 0x83, so we need to map it
            udev_wwid = self.WWN_TYPES.get(wwid[:4], '8') + wwid[4:]
            return udev_wwid
        return ''

    def get_scsi_wwn(self, path):
        """Read the WWN from page 0x83 value for a SCSI device."""

        (out, _err) = self._execute('/lib/udev/scsi_id', '--page', '0x83',
                                    '--whitelisted', path,
                                    run_as_root=True,
                                    root_helper=self._root_helper)
        return out.strip()

    @staticmethod
    def is_multipath_running(enforce_multipath,
                             root_helper,
                             execute=None) -> bool:
        try:
            if execute is None:
                execute = priv_rootwrap.execute
            cmd = ('multipathd', 'show', 'status')
            out, _err = execute(*cmd, run_as_root=True,
                                root_helper=root_helper)
            # There was a bug in multipathd where it didn't return an error
            # code and just printed the error message in stdout.
            if out and out.startswith('error receiving packet'):
                raise putils.ProcessExecutionError('', out, 1, cmd, None)

        except putils.ProcessExecutionError as err:
            if enforce_multipath:
                LOG.error('multipathd is not running: exit code %(err)s',
                          {'err': err.exit_code})
                raise
            return False
        return True

    def get_dm_name(self, dm):
        """Get the Device map name given the device name of the dm on sysfs.

        :param dm: Device map name as seen in sysfs. ie: 'dm-0'
        :returns: String with the name, or empty string if not available.
                  ie: '36e843b658476b7ed5bc1d4d10d9b1fde'
        """
        try:
            with open('/sys/block/' + dm + '/dm/name') as f:
                return f.read().strip()
        except IOError:
            return ''

    def find_sysfs_multipath_dm(self, device_names):
        """Find the dm device name given a list of device names

        :param device_names: Iterable with device names, not paths. ie: ['sda']
        :returns: String with the dm name or None if not found. ie: 'dm-0'
        """
        glob_str = '/sys/block/%s/holders/dm-*'
        for dev_name in device_names:
            dms = glob.glob(glob_str % dev_name)
            if dms:
                __, device_name, __, dm = dms[0].rsplit('/', 3)
                return dm
        return None

    @staticmethod
    def requires_flush(path, path_used, was_multipath):
        """Check if a device needs to be flushed when detaching.

        A device representing a single path connection to a volume must only be
        flushed if it has been used directly by Nova or Cinder to write data.

        If the path has been used via a multipath DM or if the device was part
        of a multipath but a different single path was used for I/O (instead of
        the multipath) then we don't need to flush.
        """
        # No used path happens on failed attachs, when we don't care about
        # individual flushes.
        if not path_used:
            return False

        path = os.path.realpath(path)
        path_used = os.path.realpath(path_used)

        # Need to flush this device if we used this specific path.  We check
        # this before checking if it's multipath in case we don't detect it
        # being multipath correctly (as in bug #1897787).
        if path_used == path:
            return True

        # We flush individual path if Nova didn't use a multipath and we
        # replaced the symlink to a real device with a link to the decrypted
        # DM.  We know we replaced it because it doesn't link to /dev/XYZ,
        # instead it maps to /dev/mapped/crypt-XYZ
        return not was_multipath and '/dev' != os.path.split(path_used)[0]

    def remove_connection(self, devices_names, force=False, exc=None,
                          path_used=None, was_multipath=False):
        """Remove LUNs and multipath associated with devices names.

        :param devices_names: Iterable with real device names ('sda', 'sdb')
        :param force: Whether to forcefully disconnect even if flush fails.
        :param exc: ExceptionChainer where to add exceptions if forcing
        :param path_used: What path was used by Nova/Cinder for I/O
        :param was_multipath: If the path used for I/O was a multipath
        :returns: Multipath device map name if found and not flushed
        """
        if not devices_names:
            return
        exc = exception.ExceptionChainer() if exc is None else exc

        multipath_dm = self.find_sysfs_multipath_dm(devices_names)
        LOG.debug('Removing %(type)s devices %(devices)s',
                  {'type': 'multipathed' if multipath_dm else 'single pathed',
                   'devices': ', '.join(devices_names)})
        multipath_name = multipath_dm and self.get_dm_name(multipath_dm)
        if multipath_name:
            with exc.context(force, 'Flushing %s failed', multipath_name):
                self.flush_multipath_device(multipath_name)
                multipath_name = None
            multipath_running = True
        else:
            multipath_running = self.is_multipath_running(
                enforce_multipath=False, root_helper=self._root_helper)

        for device_name in devices_names:
            dev_path = '/dev/' + device_name
            if multipath_running:
                # Recent multipathd doesn't remove path devices in time when
                # it receives mutiple udev events in a short span, so here we
                # tell multipathd to remove the path device immediately.
                # Even if this step fails, later removing an iscsi device
                # triggers a udev event and multipathd can remove the path
                # device based on the udev event
                self.multipath_del_path(dev_path)
            flush = self.requires_flush(dev_path, path_used, was_multipath)
            self.remove_scsi_device(dev_path, force, exc, flush)

        # Wait until the symlinks are removed
        with exc.context(force, 'Some devices remain from %s', devices_names):
            try:
                self.wait_for_volumes_removal(devices_names)
            finally:
                # Since we use /dev/disk/by-id/scsi- links to get the wwn we
                # must ensure they are always removed.
                self._remove_scsi_symlinks(devices_names)
        return multipath_name

    def _remove_scsi_symlinks(self, devices_names):
        devices = ['/dev/' + dev for dev in devices_names]
        links = glob.glob('/dev/disk/by-id/scsi-*')
        unlink = []
        for link in links:
            try:
                if os.path.realpath(link) in devices:
                    unlink.append(link)
            except OSError:
                # A race condition in Python's posixpath:realpath just occurred
                # so we can ignore it because the file was just removed between
                # a check if file exists and a call to os.readlink
                continue

        if unlink:
            priv_rootwrap.unlink_root(no_errors=True, *unlink)

    def flush_device_io(self, device):
        """This is used to flush any remaining IO in the buffers."""
        if os.path.exists(device):
            try:
                # NOTE(geguileo): With 30% connection error rates flush can get
                # stuck, set timeout to prevent it from hanging here forever.
                # Retry twice after 20 and 40 seconds.
                LOG.debug("Flushing IO for device %s", device)
                self._execute('blockdev', '--flushbufs', device,
                              run_as_root=True, attempts=3, timeout=300,
                              interval=10, root_helper=self._root_helper)
            except putils.ProcessExecutionError as exc:
                LOG.warning("Failed to flush IO buffers prior to removing "
                            "device: %(code)s", {'code': exc.exit_code})
                raise

    def flush_multipath_device(self, device_map_name):
        LOG.debug("Flush multipath device %s", device_map_name)
        # NOTE(geguileo): With 30% connection error rates flush can get stuck,
        # set timeout to prevent it from hanging here forever.  Retry twice
        # after 20 and 40 seconds.
        self._execute('multipath', '-f', device_map_name, run_as_root=True,
                      attempts=3, timeout=300, interval=10,
                      root_helper=self._root_helper)

    @utils.retry(exception.VolumeDeviceNotFound)
    def wait_for_path(self, volume_path):
        """Wait for a path to show up."""
        LOG.debug("Checking to see if %s exists yet.",
                  volume_path)
        if not os.path.exists(volume_path):
            LOG.debug("%(path)s doesn't exists yet.", {'path': volume_path})
            raise exception.VolumeDeviceNotFound(
                device=volume_path)
        else:
            LOG.debug("%s has shown up.", volume_path)

    @utils.retry(exception.BlockDeviceReadOnly, retries=5)
    def wait_for_rw(self, wwn, device_path):
        """Wait for block device to be Read-Write."""
        LOG.debug("Checking to see if %s is read-only.",
                  device_path)
        out, info = self._execute('lsblk', '-o', 'NAME,RO', '-l', '-n')
        LOG.debug("lsblk output: %s", out)
        blkdevs = out.splitlines()
        for blkdev in blkdevs:
            # Entries might look like:
            #
            #   "3624a93709a738ed78583fd120013902b (dm-1)  1"
            #
            # or
            #
            #   "sdd                                       0"
            #
            # We are looking for the first and last part of them. For FC
            # multipath devices the name is in the format of '<WWN> (dm-<ID>)'
            blkdev_parts = blkdev.split(' ')
            ro = blkdev_parts[-1]
            name = blkdev_parts[0]

            # We must validate that all pieces of the dm-# device are rw,
            # if some are still ro it can cause problems.
            if wwn in name and int(ro) == 1:
                LOG.debug("Block device %s is read-only", device_path)
                self._execute('multipath', '-r', check_exit_code=[0, 1, 21],
                              run_as_root=True, root_helper=self._root_helper)
                raise exception.BlockDeviceReadOnly(
                    device=device_path)
        else:
            LOG.debug("Block device %s is not read-only.", device_path)

    def find_multipath_device_path(self, wwn):
        """Look for the multipath device file for a volume WWN.

        Multipath devices can show up in several places on
        a linux system.

        1) When multipath friendly names are ON:
            a device file will show up in
            /dev/disk/by-id/dm-uuid-mpath-<WWN>
            /dev/disk/by-id/dm-name-mpath<N>
            /dev/disk/by-id/scsi-mpath<N>
            /dev/mapper/mpath<N>

        2) When multipath friendly names are OFF:
            /dev/disk/by-id/dm-uuid-mpath-<WWN>
            /dev/disk/by-id/scsi-<WWN>
            /dev/mapper/<WWN>

        """
        LOG.info("Find Multipath device file for volume WWN %(wwn)s",
                 {'wwn': wwn})
        # First look for the common path
        wwn_dict = {'wwn': wwn}
        path = "/dev/disk/by-id/dm-uuid-mpath-%(wwn)s" % wwn_dict
        try:
            self.wait_for_path(path)
            return path
        except exception.VolumeDeviceNotFound:
            pass

        # for some reason the common path wasn't found
        # lets try the dev mapper path
        path = "/dev/mapper/%(wwn)s" % wwn_dict
        try:
            self.wait_for_path(path)
            return path
        except exception.VolumeDeviceNotFound:
            pass

        # couldn't find a path
        LOG.warning("couldn't find a valid multipath device path for "
                    "%(wwn)s", wwn_dict)
        return None

    def find_multipath_device(self, device):
        """Discover multipath devices for a mpath device.

           This uses the slow multipath -l command to find a
           multipath device description, then screen scrapes
           the output to discover the multipath device name
           and it's devices.

        """

        mdev = None
        devices = []
        out = None
        try:
            (out, _err) = self._execute('multipath', '-l', device,
                                        run_as_root=True,
                                        root_helper=self._root_helper)
        except putils.ProcessExecutionError as exc:
            LOG.warning("multipath call failed exit %(code)s",
                        {'code': exc.exit_code})
            raise exception.CommandExecutionFailed(
                cmd='multipath -l %s' % device)

        if out:
            lines_str = out.strip()
            lines = lines_str.split("\n")
            lines = [line for line in lines
                     if not re.match(MULTIPATH_ERROR_REGEX, line) and
                     len(line)]
            if lines:

                mdev_name = lines[0].split(" ")[0]

                if mdev_name in MULTIPATH_DEVICE_ACTIONS:
                    mdev_name = lines[0].split(" ")[1]

                mdev = '/dev/mapper/%s' % mdev_name

                # Confirm that the device is present.
                try:
                    os.stat(mdev)
                except OSError:
                    LOG.warning("Couldn't find multipath device %s",
                                mdev)
                    return None

                wwid_search = MULTIPATH_WWID_REGEX.search(lines[0])
                if wwid_search is not None:
                    mdev_id = wwid_search.group('wwid')
                else:
                    mdev_id = mdev_name

                LOG.debug("Found multipath device = %(mdev)s",
                          {'mdev': mdev})
                device_lines = lines[3:]
                for dev_line in device_lines:
                    if dev_line.find("policy") != -1:
                        continue

                    dev_line = dev_line.lstrip(' |-`')
                    dev_info = dev_line.split()
                    address = dev_info[0].split(":")

                    dev = {'device': '/dev/%s' % dev_info[1],
                           'host': address[0], 'channel': address[1],
                           'id': address[2], 'lun': address[3]
                           }

                    devices.append(dev)

        if mdev is not None:
            info = {"device": mdev,
                    "id": mdev_id,
                    "name": mdev_name,
                    "devices": devices}
            return info
        return None

    def get_device_size(self, device):
        """Get the size in bytes of a volume."""
        (out, _err) = self._execute('blockdev', '--getsize64',
                                    device, run_as_root=True,
                                    root_helper=self._root_helper)
        var = str(out.strip())
        if var.isnumeric():
            return int(var)
        else:
            return None

    def multipath_reconfigure(self):
        """Issue a multipathd reconfigure.

        When attachments come and go, the multipathd seems
        to get lost and not see the maps.  This causes
        resize map to fail 100%.  To overcome this we have
        to issue a reconfigure prior to resize map.
        """
        (out, _err) = self._execute('multipathd', 'reconfigure',
                                    run_as_root=True,
                                    root_helper=self._root_helper)
        return out

    def _multipath_resize_map(self, mpath_id):
        cmd = ('multipathd', 'resize', 'map', mpath_id)
        (out, _err) = self._execute(*cmd,
                                    run_as_root=True,
                                    root_helper=self._root_helper)
        if 'fail' in out or 'timeout' in out:
            raise putils.ProcessExecutionError(
                stdout=out, stderr=_err,
                exit_code=1, cmd=cmd)

        return out

    def multipath_resize_map(self, mpath_id):
        """Issue a multipath resize map on device.

        This forces the multipath daemon to update it's
        size information a particular multipath device.
        """

        # "multipathd reconfigure" is async since 0.6.1. While the
        # operation is in progress, "multipathd resize map" returns
        # "timeout".
        tstart = time.time()
        while True:
            try:
                self._multipath_resize_map(mpath_id)
                break
            except putils.ProcessExecutionError as err:
                with excutils.save_and_reraise_exception(reraise=True) as ctx:
                    elapsed = time.time() - tstart
                    if 'timeout' in err.stdout and (
                            elapsed < MULTIPATHD_RESIZE_TIMEOUT):
                        LOG.debug(
                            "multipathd resize map timed out. "
                            "Elapsed: %s, timeout: %s. Retrying...",
                            elapsed, MULTIPATHD_RESIZE_TIMEOUT)
                        ctx.reraise = False
                        time.sleep(1)

    def extend_volume(self, volume_paths, use_multipath=False):
        """Signal the SCSI subsystem to test for volume resize.

        This function tries to signal the local system's kernel
        that an already attached volume might have been resized.
        """
        LOG.debug("extend volume %s", volume_paths)

        for volume_path in volume_paths:
            device = self.get_device_info(volume_path)
            LOG.debug("Volume device info = %s", device)
            device_id = ("%(host)s:%(channel)s:%(id)s:%(lun)s" %
                         {'host': device['host'],
                          'channel': device['channel'],
                          'id': device['id'],
                          'lun': device['lun']})

            scsi_path = ("/sys/bus/scsi/drivers/sd/%(device_id)s" %
                         {'device_id': device_id})

            size = self.get_device_size(volume_path)
            LOG.debug("Starting size: %s", size)

            # now issue the device rescan
            rescan_path = "%(scsi_path)s/rescan" % {'scsi_path': scsi_path}
            self.echo_scsi_command(rescan_path, "1")
            new_size = self.get_device_size(volume_path)
            LOG.debug("volume size after scsi device rescan %s", new_size)

        scsi_wwn = self.get_scsi_wwn(volume_paths[0])
        if use_multipath:
            mpath_device = self.find_multipath_device_path(scsi_wwn)
            if mpath_device:
                # Force a reconfigure so that resize works
                self.multipath_reconfigure()

                size = self.get_device_size(mpath_device)
                LOG.info("mpath(%(device)s) current size %(size)s",
                         {'device': mpath_device, 'size': size})

                self.multipath_resize_map(scsi_wwn)

                new_size = self.get_device_size(mpath_device)
                LOG.info("mpath(%(device)s) new size %(size)s",
                         {'device': mpath_device, 'size': new_size})

        return new_size

    def process_lun_id(self, lun_ids):
        if isinstance(lun_ids, list):
            processed = []
            for x in lun_ids:
                x = self._format_lun_id(x)
                processed.append(x)
        else:
            processed = self._format_lun_id(lun_ids)
        return processed

    def _format_lun_id(self, lun_id):
        # make sure lun_id is an int
        lun_id = int(lun_id)
        if lun_id < 256:
            return lun_id
        else:
            return ("0x%04x%04x00000000" %
                    (lun_id & 0xffff, lun_id >> 16 & 0xffff))

    def get_hctl(self, session, lun):
        """Given an iSCSI session return the host, channel, target, and lun."""
        glob_str = '/sys/class/iscsi_host/host*/device/session' + session
        paths = glob.glob(glob_str + '/target*')
        if paths:
            __, channel, target = os.path.split(paths[0])[1].split(':')
        # Check if we can get the host
        else:
            target = channel = '-'
            paths = glob.glob(glob_str)

        if not paths:
            LOG.debug('No hctl found on session %s with lun %s', session, lun)
            return None

        # Extract the host number from the path
        host = paths[0][26:paths[0].index('/', 26)]
        res = (host, channel, target, lun)
        LOG.debug('HCTL %s found on session %s with lun %s', res, session, lun)
        return res

    def device_name_by_hctl(self, session, hctl):
        """Find the device name given a session and the hctl.

        :param session: A string with the session number
        :param hctl: An iterable with the host, channel, target, and lun as
                     passed to scan.  ie: ('5', '-', '-', '0')
        """
        if '-' in hctl:
            hctl = ['*' if x == '-' else x for x in hctl]
        path = ('/sys/class/scsi_host/host%(h)s/device/session%(s)s/target'
                '%(h)s:%(c)s:%(t)s/%(h)s:%(c)s:%(t)s:%(l)s/block/*' %
                {'h': hctl[0], 'c': hctl[1], 't': hctl[2], 'l': hctl[3],
                 's': session})
        # Sort devices and return the first so we don't return a partition
        devices = sorted(glob.glob(path))
        device = os.path.split(devices[0])[1] if devices else None
        LOG.debug('Searching for a device in session %s and hctl %s yield: %s',
                  session, hctl, device)
        return device

    def scan_iscsi(self, host, channel='-', target='-', lun='-'):
        """Send an iSCSI scan request given the host and optionally the ctl."""
        LOG.debug('Scanning host %(host)s c: %(channel)s, '
                  't: %(target)s, l: %(lun)s)',
                  {'host': host, 'channel': channel,
                   'target': target, 'lun': lun})
        self.echo_scsi_command('/sys/class/scsi_host/host%s/scan' % host,
                               '%(c)s %(t)s %(l)s' % {'c': channel,
                                                      't': target,
                                                      'l': lun})

    def multipath_add_wwid(self, wwid):
        """Add a wwid to the list of know multipath wwids.

        This has the effect of multipathd being willing to create a dm for a
        multipath even when there's only 1 device.
        """
        out, err = self._execute('multipath', '-a', wwid,
                                 run_as_root=True,
                                 check_exit_code=False,
                                 root_helper=self._root_helper)
        return out.strip() == "wwid '" + wwid + "' added"

    def multipath_add_path(self, realpath):
        """Add a path to multipathd for monitoring.

        This has the effect of multipathd checking an already checked device
        for multipath.

        Together with `multipath_add_wwid` we can create a multipath when
        there's only 1 path.
        """
        stdout, stderr = self._execute('multipathd', 'add', 'path', realpath,
                                       run_as_root=True, timeout=5,
                                       check_exit_code=False,
                                       root_helper=self._root_helper)
        return stdout.strip() == 'ok'

    def multipath_del_path(self, realpath):
        """Remove a path from multipathd for monitoring."""
        stdout, stderr = self._execute('multipathd', 'del', 'path', realpath,
                                       run_as_root=True, timeout=5,
                                       check_exit_code=False,
                                       root_helper=self._root_helper)
        return stdout.strip() == 'ok'
