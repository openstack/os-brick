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
import os
import re
import six

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick import executor
from os_brick.i18n import _LE
from os_brick.i18n import _LI
from os_brick.i18n import _LW
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick import utils

LOG = logging.getLogger(__name__)

MULTIPATH_ERROR_REGEX = re.compile("\w{3} \d+ \d\d:\d\d:\d\d \|.*$")
MULTIPATH_WWID_REGEX = re.compile("\((?P<wwid>.+)\)")
MULTIPATH_DEVICE_ACTIONS = ['unchanged:', 'reject:', 'reload:',
                            'switchpg:', 'rename:', 'create:',
                            'resize:']


class LinuxSCSI(executor.Executor):
    def echo_scsi_command(self, path, content):
        """Used to echo strings to scsi subsystem."""

        args = ["-a", path]
        kwargs = dict(process_input=content,
                      run_as_root=True,
                      root_helper=self._root_helper)
        self._execute('tee', *args, **kwargs)

    def get_name_from_path(self, path):
        """Translates /dev/disk/by-path/ entry to /dev/sdX."""

        name = os.path.realpath(path)
        if name.startswith("/dev/"):
            return name
        else:
            return None

    def remove_scsi_device(self, device):
        """Removes a scsi device based upon /dev/sdX name."""

        path = "/sys/block/%s/device/delete" % device.replace("/dev/", "")
        if os.path.exists(path):
            # flush any outstanding IO first
            self.flush_device_io(device)

            LOG.debug("Remove SCSI device %(device)s with %(path)s",
                      {'device': device, 'path': path})
            self.echo_scsi_command(path, "1")

    @utils.retry(exceptions=exception.VolumePathNotRemoved, retries=3,
                 backoff_rate=2)
    def wait_for_volume_removal(self, volume_path):
        """This is used to ensure that volumes are gone."""
        LOG.debug("Checking to see if SCSI volume %s has been removed.",
                  volume_path)
        if os.path.exists(volume_path):
            LOG.debug("%(path)s still exists.", {'path': volume_path})
            raise exception.VolumePathNotRemoved(
                volume_path=volume_path)
        else:
            LOG.debug("SCSI volume %s has been removed.", volume_path)

    def get_device_info(self, device):
        (out, _err) = self._execute('sg_scan', device, run_as_root=True,
                                    root_helper=self._root_helper)
        dev_info = {'device': device, 'host': None,
                    'channel': None, 'id': None, 'lun': None}
        if out:
            line = out.strip()
            line = line.replace(device + ": ", "")
            info = line.split(" ")

            for item in info:
                if '=' in item:
                    pair = item.split('=')
                    dev_info[pair[0]] = pair[1]
                elif 'scsi' in item:
                    dev_info['host'] = item.replace('scsi', '')

        return dev_info

    def get_scsi_wwn(self, path):
        """Read the WWN from page 0x83 value for a SCSI device."""

        (out, _err) = self._execute('/lib/udev/scsi_id', '--page', '0x83',
                                    '--whitelisted', path,
                                    run_as_root=True,
                                    root_helper=self._root_helper)
        return out.strip()

    @staticmethod
    def is_multipath_running(enforce_multipath, root_helper):
        try:
            priv_rootwrap.execute('multipathd', 'show', 'status',
                                  run_as_root=True,
                                  root_helper=root_helper)
        except putils.ProcessExecutionError as err:
            LOG.error(_LE('multipathd is not running: exit code %(err)s'),
                      {'err': err.exit_code})
            if enforce_multipath:
                raise
            return False

        return True

    def remove_multipath_device(self, device):
        """This removes LUNs associated with a multipath device
        and the multipath device itself.
        """

        LOG.debug("remove multipath device %s", device)
        mpath_dev = self.find_multipath_device(device)
        if mpath_dev:
            devices = mpath_dev['devices']
            LOG.debug("multipath LUNs to remove %s", devices)
            for device in devices:
                self.remove_scsi_device(device['device'])
            self.flush_multipath_device(mpath_dev['id'])

    def flush_device_io(self, device):
        """This is used to flush any remaining IO in the buffers."""
        try:
            LOG.debug("Flushing IO for device %s", device)
            self._execute('blockdev', '--flushbufs', device, run_as_root=True,
                          root_helper=self._root_helper)
        except putils.ProcessExecutionError as exc:
            LOG.warning(_LW("Failed to flush IO buffers prior to removing "
                            "device: %(code)s"), {'code': exc.exit_code})

    def flush_multipath_device(self, device):
        try:
            LOG.debug("Flush multipath device %s", device)
            self._execute('multipath', '-f', device, run_as_root=True,
                          root_helper=self._root_helper)
        except putils.ProcessExecutionError as exc:
            LOG.warning(_LW("multipath call failed exit %(code)s"),
                        {'code': exc.exit_code})

    def flush_multipath_devices(self):
        try:
            self._execute('multipath', '-F', run_as_root=True,
                          root_helper=self._root_helper)
        except putils.ProcessExecutionError as exc:
            LOG.warning(_LW("multipath call failed exit %(code)s"),
                        {'code': exc.exit_code})

    @utils.retry(exceptions=exception.VolumeDeviceNotFound)
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

    @utils.retry(exceptions=exception.BlockDeviceReadOnly, retries=5)
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
        LOG.info(_LI("Find Multipath device file for volume WWN %(wwn)s"),
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
        LOG.warning(_LW("couldn't find a valid multipath device path for "
                        "%(wwn)s"), wwn_dict)
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
            LOG.warning(_LW("multipath call failed exit %(code)s"),
                        {'code': exc.exit_code})
            raise exception.CommandExecutionFailed(
                cmd='multipath -l %s' % device)

        if out:
            lines = out.strip()
            lines = lines.split("\n")
            lines = [line for line in lines
                     if not re.match(MULTIPATH_ERROR_REGEX, line)]
            if lines:

                mdev_name = lines[0].split(" ")[0]

                if mdev_name in MULTIPATH_DEVICE_ACTIONS:
                    mdev_name = lines[0].split(" ")[1]

                mdev = '/dev/mapper/%s' % mdev_name

                # Confirm that the device is present.
                try:
                    os.stat(mdev)
                except OSError:
                    LOG.warning(_LW("Couldn't find multipath device %s"),
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
        var = six.text_type(out.strip())
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

    def multipath_resize_map(self, mpath_id):
        """Issue a multipath resize map on device.

        This forces the multipath daemon to update it's
        size information a particular multipath device.
        """
        (out, _err) = self._execute('multipathd', 'resize', 'map', mpath_id,
                                    run_as_root=True,
                                    root_helper=self._root_helper)
        return out

    def extend_volume(self, volume_path):
        """Signal the SCSI subsystem to test for volume resize.

        This function tries to signal the local system's kernel
        that an already attached volume might have been resized.
        """
        LOG.debug("extend volume %s", volume_path)

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

        scsi_wwn = self.get_scsi_wwn(volume_path)
        mpath_device = self.find_multipath_device_path(scsi_wwn)
        if mpath_device:
            # Force a reconfigure so that resize works
            self.multipath_reconfigure()

            size = self.get_device_size(mpath_device)
            LOG.info(_LI("mpath(%(device)s) current size %(size)s"),
                     {'device': mpath_device, 'size': size})
            result = self.multipath_resize_map(scsi_wwn)
            if 'fail' in result:
                msg = (_LI("Multipathd failed to update the size mapping of "
                           "multipath device %(scsi_wwn)s volume %(volume)s") %
                       {'scsi_wwn': scsi_wwn, 'volume': volume_path})
                LOG.error(msg)
                return None

            new_size = self.get_device_size(mpath_device)
            LOG.info(_LI("mpath(%(device)s) new size %(size)s"),
                     {'device': mpath_device, 'size': new_size})
            return new_size
        else:
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
        if lun_id < 256:
                return lun_id
        else:
            return ("0x%04x%04x00000000" %
                    (lun_id & 0xffff, lun_id >> 16 & 0xffff))
