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

import os
import os.path
import textwrap
from unittest import mock

import ddt
from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick.initiator import linuxscsi
from os_brick.tests import base

LOG = logging.getLogger(__name__)


@ddt.ddt
class LinuxSCSITestCase(base.TestCase):
    def setUp(self):
        super(LinuxSCSITestCase, self).setUp()
        self.cmds = []
        self.realpath = os.path.realpath
        self.mock_object(os.path, 'realpath', return_value='/dev/sdc')
        self.mock_object(os, 'stat', returns=os.stat(__file__))
        self.linuxscsi = linuxscsi.LinuxSCSI(None, execute=self.fake_execute)

    def fake_execute(self, *cmd, **kwargs):
        self.cmds.append(" ".join(cmd))
        return "", None

    def test_echo_scsi_command(self):
        self.linuxscsi.echo_scsi_command("/some/path", "1")
        expected_commands = ['tee -a /some/path']
        self.assertEqual(expected_commands, self.cmds)

    @mock.patch.object(os.path, 'realpath')
    def test_get_name_from_path(self, realpath_mock):
        device_name = "/dev/sdc"
        realpath_mock.return_value = device_name
        disk_path = ("/dev/disk/by-path/ip-10.10.220.253:3260-"
                     "iscsi-iqn.2000-05.com.3pardata:21810002ac00383d-lun-0")
        name = self.linuxscsi.get_name_from_path(disk_path)
        self.assertEqual(device_name, name)
        disk_path = ("/dev/disk/by-path/pci-0000:00:00.0-ip-10.9.8.7:3260-"
                     "iscsi-iqn.2000-05.com.openstack:2180002ac00383d-lun-0")
        name = self.linuxscsi.get_name_from_path(disk_path)
        self.assertEqual(device_name, name)
        realpath_mock.return_value = "bogus"
        name = self.linuxscsi.get_name_from_path(disk_path)
        self.assertIsNone(name)

    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_remove_scsi_device(self, exists_mock):
        self.linuxscsi.remove_scsi_device("/dev/sdc")
        expected_commands = []
        self.assertEqual(expected_commands, self.cmds)
        exists_mock.return_value = True
        self.linuxscsi.remove_scsi_device("/dev/sdc")
        expected_commands = [
            ('blockdev --flushbufs /dev/sdc'),
            ('tee -a /sys/block/sdc/device/delete')]
        self.assertEqual(expected_commands, self.cmds)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'echo_scsi_command')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_device_io')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_remove_scsi_device_force(self, exists_mock, flush_mock,
                                      echo_mock):
        """With force we'll always call delete even if flush fails."""
        exc = exception.ExceptionChainer()
        flush_mock.side_effect = Exception()
        echo_mock.side_effect = Exception()
        device = '/dev/sdc'

        self.linuxscsi.remove_scsi_device(device, force=True, exc=exc)
        # The context manager has caught the exceptions
        self.assertTrue(exc)
        flush_mock.assert_called_once_with(device)
        echo_mock.assert_called_once_with('/sys/block/sdc/device/delete', '1')

    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_remove_scsi_device_no_flush(self, exists_mock):
        self.linuxscsi.remove_scsi_device("/dev/sdc")
        expected_commands = []
        self.assertEqual(expected_commands, self.cmds)
        exists_mock.return_value = True
        self.linuxscsi.remove_scsi_device("/dev/sdc", flush=False)
        expected_commands = [('tee -a /sys/block/sdc/device/delete')]
        self.assertEqual(expected_commands, self.cmds)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch('os.path.exists', return_value=True)
    def test_wait_for_volumes_removal_failure(self, exists_mock, sleep_mock):
        retries = 61
        names = ('sda', 'sdb')
        self.assertRaises(exception.VolumePathNotRemoved,
                          self.linuxscsi.wait_for_volumes_removal, names)
        exists_mock.assert_has_calls([mock.call('/dev/' + name)
                                      for name in names] * retries)
        self.assertEqual(retries - 1, sleep_mock.call_count)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch('os.path.exists', side_effect=(True, True, False, False))
    def test_wait_for_volumes_removal_retry(self, exists_mock, sleep_mock):
        names = ('sda', 'sdb')
        self.linuxscsi.wait_for_volumes_removal(names)
        exists_mock.assert_has_calls([mock.call('/dev/' + name)
                                      for name in names] * 2)
        self.assertEqual(1, sleep_mock.call_count)

    def test_flush_multipath_device(self):
        dm_map_name = '3600d0230000000000e13955cc3757800'
        with mock.patch.object(self.linuxscsi, '_execute') as exec_mock:
            self.linuxscsi.flush_multipath_device(dm_map_name)

        exec_mock.assert_called_once_with(
            'multipath', '-f', dm_map_name, run_as_root=True, attempts=3,
            timeout=300, interval=10, root_helper=self.linuxscsi._root_helper)

    def test_get_scsi_wwn(self):
        fake_path = '/dev/disk/by-id/somepath'
        fake_wwn = '1234567890'

        def fake_execute(*cmd, **kwargs):
            return fake_wwn, None

        self.linuxscsi._execute = fake_execute
        wwn = self.linuxscsi.get_scsi_wwn(fake_path)
        self.assertEqual(fake_wwn, wwn)

    @mock.patch('builtins.open')
    def test_get_dm_name(self, open_mock):
        dm_map_name = '3600d0230000000000e13955cc3757800'
        cm_open = open_mock.return_value.__enter__.return_value
        cm_open.read.return_value = dm_map_name
        res = self.linuxscsi.get_dm_name('dm-0')
        self.assertEqual(dm_map_name, res)
        open_mock.assert_called_once_with('/sys/block/dm-0/dm/name')

    @mock.patch('builtins.open', side_effect=IOError)
    def test_get_dm_name_failure(self, open_mock):
        self.assertEqual('', self.linuxscsi.get_dm_name('dm-0'))

    @mock.patch('glob.glob', side_effect=[[], ['/sys/block/sda/holders/dm-9']])
    def test_find_sysfs_multipath_dm(self, glob_mock):
        device_names = ('sda', 'sdb')
        res = self.linuxscsi.find_sysfs_multipath_dm(device_names)
        self.assertEqual('dm-9', res)
        glob_mock.assert_has_calls([mock.call('/sys/block/sda/holders/dm-*'),
                                    mock.call('/sys/block/sdb/holders/dm-*')])

    @mock.patch('glob.glob', return_value=[])
    def test_find_sysfs_multipath_dm_not_found(self, glob_mock):
        device_names = ('sda', 'sdb')
        res = self.linuxscsi.find_sysfs_multipath_dm(device_names)
        self.assertIsNone(res)
        glob_mock.assert_has_calls([mock.call('/sys/block/sda/holders/dm-*'),
                                    mock.call('/sys/block/sdb/holders/dm-*')])

    @mock.patch.object(linuxscsi.LinuxSCSI, '_execute')
    @mock.patch('os.path.exists', return_value=True)
    def test_flush_device_io(self, exists_mock, exec_mock):
        device = '/dev/sda'
        self.linuxscsi.flush_device_io(device)
        exists_mock.assert_called_once_with(device)
        exec_mock.assert_called_once_with(
            'blockdev', '--flushbufs', device, run_as_root=True, attempts=3,
            timeout=300, interval=10, root_helper=self.linuxscsi._root_helper)

    @mock.patch('os.path.exists', return_value=False)
    def test_flush_device_io_non_existent(self, exists_mock):
        device = '/dev/sda'
        self.linuxscsi.flush_device_io(device)
        exists_mock.assert_called_once_with(device)

    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_find_multipath_device_path(self, exists_mock):
        fake_wwn = '1234567890'
        found_path = self.linuxscsi.find_multipath_device_path(fake_wwn)
        expected_path = '/dev/disk/by-id/dm-uuid-mpath-%s' % fake_wwn
        self.assertEqual(expected_path, found_path)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch.object(os.path, 'exists')
    def test_find_multipath_device_path_mapper(self, exists_mock, sleep_mock):
        # the wait loop tries 3 times before it gives up
        # we want to test failing to find the
        # /dev/disk/by-id/dm-uuid-mpath-<WWN> path
        # but finding the
        # /dev/mapper/<WWN> path
        exists_mock.side_effect = [False, False, False, True]
        fake_wwn = '1234567890'
        found_path = self.linuxscsi.find_multipath_device_path(fake_wwn)
        expected_path = '/dev/mapper/%s' % fake_wwn
        self.assertEqual(expected_path, found_path)
        self.assertTrue(sleep_mock.called)

    @mock.patch.object(os.path, 'exists', return_value=False)
    @mock.patch('os_brick.utils._time_sleep')
    def test_find_multipath_device_path_fail(self, exists_mock, sleep_mock):
        fake_wwn = '1234567890'
        found_path = self.linuxscsi.find_multipath_device_path(fake_wwn)
        self.assertIsNone(found_path)

    @mock.patch.object(os.path, 'exists', return_value=False)
    @mock.patch('os_brick.utils._time_sleep')
    def test_wait_for_path_not_found(self, exists_mock, sleep_mock):
        path = "/dev/disk/by-id/dm-uuid-mpath-%s" % '1234567890'
        self.assertRaisesRegex(exception.VolumeDeviceNotFound,
                               r'Volume device not found at %s' % path,
                               self.linuxscsi.wait_for_path,
                               path)

    @ddt.data({'do_raise': False, 'force': False},
              {'do_raise': True, 'force': True})
    @ddt.unpack
    @mock.patch.object(linuxscsi.LinuxSCSI, '_remove_scsi_symlinks')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_del_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'is_multipath_running',
                       return_value=True)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_dm_name')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_volumes_removal')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    def test_remove_connection_multipath_complete(self, remove_mock, wait_mock,
                                                  find_dm_mock,
                                                  get_dm_name_mock,
                                                  flush_mp_mock,
                                                  is_mp_running_mock,
                                                  mp_del_path_mock,
                                                  remove_link_mock,
                                                  do_raise, force):
        if do_raise:
            flush_mp_mock.side_effect = Exception
        devices_names = ('sda', 'sdb')
        exc = exception.ExceptionChainer()
        mp_name = self.linuxscsi.remove_connection(devices_names,
                                                   force=mock.sentinel.Force,
                                                   exc=exc)
        find_dm_mock.assert_called_once_with(devices_names)
        get_dm_name_mock.assert_called_once_with(find_dm_mock.return_value)
        flush_mp_mock.assert_called_once_with(get_dm_name_mock.return_value)
        self.assertEqual(get_dm_name_mock.return_value if do_raise else None,
                         mp_name)
        is_mp_running_mock.assert_not_called()
        mp_del_path_mock.assert_has_calls([
            mock.call('/dev/sda'), mock.call('/dev/sdb')])
        remove_mock.assert_has_calls([
            mock.call('/dev/sda', mock.sentinel.Force, exc, False),
            mock.call('/dev/sdb', mock.sentinel.Force, exc, False)])
        wait_mock.assert_called_once_with(devices_names)
        self.assertEqual(do_raise, bool(exc))
        remove_link_mock.assert_called_once_with(devices_names)

    @mock.patch.object(linuxscsi.LinuxSCSI, '_remove_scsi_symlinks')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_del_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'is_multipath_running',
                       return_value=True)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_dm_name')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm',
                       return_value=None)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_volumes_removal')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    def test_remove_connection_multipath_complete_no_dm(self, remove_mock,
                                                        wait_mock,
                                                        find_dm_mock,
                                                        get_dm_name_mock,
                                                        flush_mp_mock,
                                                        is_mp_running_mock,
                                                        mp_del_path_mock,
                                                        remove_link_mock):
        devices_names = ('sda', 'sdb')
        exc = exception.ExceptionChainer()
        mp_name = self.linuxscsi.remove_connection(devices_names,
                                                   force=mock.sentinel.Force,
                                                   exc=exc)
        find_dm_mock.assert_called_once_with(devices_names)
        get_dm_name_mock.assert_not_called()
        flush_mp_mock.assert_not_called()
        self.assertIsNone(mp_name)
        is_mp_running_mock.assert_called_once()
        mp_del_path_mock.assert_has_calls([
            mock.call('/dev/sda'), mock.call('/dev/sdb')])
        remove_mock.assert_has_calls([
            mock.call('/dev/sda', mock.sentinel.Force, exc, False),
            mock.call('/dev/sdb', mock.sentinel.Force, exc, False)])
        wait_mock.assert_called_once_with(devices_names)
        self.assertFalse(bool(exc))
        remove_link_mock.assert_called_once_with(devices_names)

    @mock.patch.object(linuxscsi.LinuxSCSI, '_remove_scsi_symlinks')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_del_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'is_multipath_running',
                       return_value=True)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_multipath_device',
                       side_effect=Exception)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_dm_name')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_volumes_removal')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    def test_remove_connection_multipath_fail(self, remove_mock, wait_mock,
                                              find_dm_mock, get_dm_name_mock,
                                              flush_mp_mock,
                                              is_mp_running_mock,
                                              mp_del_path_mock,
                                              remove_link_mock):
        flush_mp_mock.side_effect = exception.ExceptionChainer
        devices_names = ('sda', 'sdb')
        exc = exception.ExceptionChainer()
        self.assertRaises(exception.ExceptionChainer,
                          self.linuxscsi.remove_connection,
                          devices_names, force=False, exc=exc)
        find_dm_mock.assert_called_once_with(devices_names)
        get_dm_name_mock.assert_called_once_with(find_dm_mock.return_value)
        flush_mp_mock.assert_called_once_with(get_dm_name_mock.return_value)
        is_mp_running_mock.assert_not_called()
        mp_del_path_mock.assert_not_called()
        remove_mock.assert_not_called()
        wait_mock.assert_not_called()
        remove_link_mock.assert_not_called()
        self.assertTrue(bool(exc))

    @mock.patch.object(linuxscsi.LinuxSCSI, '_remove_scsi_symlinks')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_del_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'is_multipath_running',
                       return_value=True)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_volumes_removal')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    def test_remove_connection_singlepath_no_path(self, remove_mock, wait_mock,
                                                  find_dm_mock,
                                                  is_mp_running_mock,
                                                  mp_del_path_mock,
                                                  remove_link_mock):
        # Test remove connection when we didn't form a multipath and didn't
        # even use any of the devices that were found.  This means that we
        # don't flush any of the single paths when removing them.
        find_dm_mock.return_value = None
        devices_names = ('sda', 'sdb')
        exc = exception.ExceptionChainer()
        self.linuxscsi.remove_connection(devices_names,
                                         force=mock.sentinel.Force,
                                         exc=exc)
        find_dm_mock.assert_called_once_with(devices_names)
        is_mp_running_mock.assert_called_once()
        mp_del_path_mock.assert_has_calls([
            mock.call('/dev/sda'), mock.call('/dev/sdb')])
        remove_mock.assert_has_calls(
            [mock.call('/dev/sda', mock.sentinel.Force, exc, False),
             mock.call('/dev/sdb', mock.sentinel.Force, exc, False)])
        wait_mock.assert_called_once_with(devices_names)
        remove_link_mock.assert_called_once_with(devices_names)

    @mock.patch.object(linuxscsi.LinuxSCSI, '_remove_scsi_symlinks')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_del_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'is_multipath_running',
                       return_value=False)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_volumes_removal')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    def test_remove_connection_singlepath_used(self, remove_mock, wait_mock,
                                               find_dm_mock,
                                               is_mp_running_mock,
                                               mp_del_path_mock,
                                               remove_link_mock):
        # Test remove connection when we didn't form a multipath and just used
        # one of the single paths that were found.  This means that we don't
        # flush any of the single paths when removing them.
        find_dm_mock.return_value = None
        devices_names = ('sda', 'sdb')
        exc = exception.ExceptionChainer()

        # realpath was mocked on test setup
        with mock.patch('os.path.realpath', side_effect=self.realpath):
            self.linuxscsi.remove_connection(devices_names,
                                             force=mock.sentinel.Force,
                                             exc=exc, path_used='/dev/sdb',
                                             was_multipath=False)
        find_dm_mock.assert_called_once_with(devices_names)
        is_mp_running_mock.assert_called_once()
        mp_del_path_mock.assert_not_called()
        remove_mock.assert_has_calls(
            [mock.call('/dev/sda', mock.sentinel.Force, exc, False),
             mock.call('/dev/sdb', mock.sentinel.Force, exc, True)])
        wait_mock.assert_called_once_with(devices_names)
        remove_link_mock.assert_called_once_with(devices_names)

    def test_find_multipath_device_3par_ufn(self):
        def fake_execute(*cmd, **kwargs):
            out = ("mpath6 (350002ac20398383d) dm-3 3PARdata,VV\n"
                   "size=2.0G features='0' hwhandler='0' wp=rw\n"
                   "`-+- policy='round-robin 0' prio=-1 status=active\n"
                   "  |- 0:0:0:1 sde 8:64 active undef running\n"
                   "  `- 2:0:0:1 sdf 8:80 active undef running\n"
                   )
            return out, None

        self.linuxscsi._execute = fake_execute

        info = self.linuxscsi.find_multipath_device('/dev/sde')

        self.assertEqual("350002ac20398383d", info["id"])
        self.assertEqual("mpath6", info["name"])
        self.assertEqual("/dev/mapper/mpath6", info["device"])

        self.assertEqual("/dev/sde", info['devices'][0]['device'])
        self.assertEqual("0", info['devices'][0]['host'])
        self.assertEqual("0", info['devices'][0]['id'])
        self.assertEqual("0", info['devices'][0]['channel'])
        self.assertEqual("1", info['devices'][0]['lun'])

        self.assertEqual("/dev/sdf", info['devices'][1]['device'])
        self.assertEqual("2", info['devices'][1]['host'])
        self.assertEqual("0", info['devices'][1]['id'])
        self.assertEqual("0", info['devices'][1]['channel'])
        self.assertEqual("1", info['devices'][1]['lun'])

    def test_find_multipath_device_svc(self):
        def fake_execute(*cmd, **kwargs):
            out = ("36005076da00638089c000000000004d5 dm-2 IBM,2145\n"
                   "size=954M features='1 queue_if_no_path' hwhandler='0'"
                   " wp=rw\n"
                   "|-+- policy='round-robin 0' prio=-1 status=active\n"
                   "| |- 6:0:2:0 sde 8:64  active undef  running\n"
                   "| `- 6:0:4:0 sdg 8:96  active undef  running\n"
                   "`-+- policy='round-robin 0' prio=-1 status=enabled\n"
                   "  |- 6:0:3:0 sdf 8:80  active undef  running\n"
                   "  `- 6:0:5:0 sdh 8:112 active undef  running\n"
                   )
            return out, None

        self.linuxscsi._execute = fake_execute

        info = self.linuxscsi.find_multipath_device('/dev/sde')

        self.assertEqual("36005076da00638089c000000000004d5", info["id"])
        self.assertEqual("36005076da00638089c000000000004d5", info["name"])
        self.assertEqual("/dev/mapper/36005076da00638089c000000000004d5",
                         info["device"])

        self.assertEqual("/dev/sde", info['devices'][0]['device'])
        self.assertEqual("6", info['devices'][0]['host'])
        self.assertEqual("0", info['devices'][0]['channel'])
        self.assertEqual("2", info['devices'][0]['id'])
        self.assertEqual("0", info['devices'][0]['lun'])

        self.assertEqual("/dev/sdf", info['devices'][2]['device'])
        self.assertEqual("6", info['devices'][2]['host'])
        self.assertEqual("0", info['devices'][2]['channel'])
        self.assertEqual("3", info['devices'][2]['id'])
        self.assertEqual("0", info['devices'][2]['lun'])

    def test_find_multipath_device_ds8000(self):
        def fake_execute(*cmd, **kwargs):
            out = ("36005076303ffc48e0000000000000101 dm-2 IBM,2107900\n"
                   "size=1.0G features='1 queue_if_no_path' hwhandler='0'"
                   " wp=rw\n"
                   "`-+- policy='round-robin 0' prio=-1 status=active\n"
                   "  |- 6:0:2:0  sdd 8:64  active undef  running\n"
                   "  `- 6:1:0:3  sdc 8:32  active undef  running\n"
                   )
            return out, None

        self.linuxscsi._execute = fake_execute

        info = self.linuxscsi.find_multipath_device('/dev/sdd')

        self.assertEqual("36005076303ffc48e0000000000000101", info["id"])
        self.assertEqual("36005076303ffc48e0000000000000101", info["name"])
        self.assertEqual("/dev/mapper/36005076303ffc48e0000000000000101",
                         info["device"])

        self.assertEqual("/dev/sdd", info['devices'][0]['device'])
        self.assertEqual("6", info['devices'][0]['host'])
        self.assertEqual("0", info['devices'][0]['channel'])
        self.assertEqual("2", info['devices'][0]['id'])
        self.assertEqual("0", info['devices'][0]['lun'])

        self.assertEqual("/dev/sdc", info['devices'][1]['device'])
        self.assertEqual("6", info['devices'][1]['host'])
        self.assertEqual("1", info['devices'][1]['channel'])
        self.assertEqual("0", info['devices'][1]['id'])
        self.assertEqual("3", info['devices'][1]['lun'])

    def test_find_multipath_device_with_error(self):
        def fake_execute(*cmd, **kwargs):
            out = ("Oct 13 10:24:01 | /lib/udev/scsi_id exited with 1\n"
                   "36005076303ffc48e0000000000000101 dm-2 IBM,2107900\n"
                   "size=1.0G features='1 queue_if_no_path' hwhandler='0'"
                   " wp=rw\n"
                   "`-+- policy='round-robin 0' prio=-1 status=active\n"
                   "  |- 6:0:2:0  sdd 8:64  active undef  running\n"
                   "  `- 6:1:0:3  sdc 8:32  active undef  running\n"
                   )
            return out, None

        self.linuxscsi._execute = fake_execute

        info = self.linuxscsi.find_multipath_device('/dev/sdd')

        self.assertEqual("36005076303ffc48e0000000000000101", info["id"])
        self.assertEqual("36005076303ffc48e0000000000000101", info["name"])
        self.assertEqual("/dev/mapper/36005076303ffc48e0000000000000101",
                         info["device"])

        self.assertEqual("/dev/sdd", info['devices'][0]['device'])
        self.assertEqual("6", info['devices'][0]['host'])
        self.assertEqual("0", info['devices'][0]['channel'])
        self.assertEqual("2", info['devices'][0]['id'])
        self.assertEqual("0", info['devices'][0]['lun'])

        self.assertEqual("/dev/sdc", info['devices'][1]['device'])
        self.assertEqual("6", info['devices'][1]['host'])
        self.assertEqual("1", info['devices'][1]['channel'])
        self.assertEqual("0", info['devices'][1]['id'])
        self.assertEqual("3", info['devices'][1]['lun'])

    def test_find_multipath_device_with_multiple_errors(self):
        def fake_execute(*cmd, **kwargs):
            out = ("Jun 21 04:39:26 | 8:160: path wwid appears to have "
                   "changed. Using old wwid.\n\n"
                   "Jun 21 04:39:26 | 65:208: path wwid appears to have "
                   "changed. Using old wwid.\n\n"
                   "Jun 21 04:39:26 | 65:208: path wwid appears to have "
                   "changed. Using old wwid.\n"
                   "3624a93707edcfde1127040370004ee62 dm-84 PURE    ,"
                   "FlashArray\n"
                   "size=100G features='0' hwhandler='0' wp=rw\n"
                   "`-+- policy='queue-length 0' prio=1 status=active\n"
                   "  |- 8:0:0:9  sdaa 65:160 active ready running\n"
                   "  `- 8:0:1:9  sdac 65:192 active ready running\n"
                   )
            return out, None

        self.linuxscsi._execute = fake_execute

        info = self.linuxscsi.find_multipath_device('/dev/sdaa')

        self.assertEqual("3624a93707edcfde1127040370004ee62", info["id"])
        self.assertEqual("3624a93707edcfde1127040370004ee62", info["name"])
        self.assertEqual("/dev/mapper/3624a93707edcfde1127040370004ee62",
                         info["device"])

        self.assertEqual("/dev/sdaa", info['devices'][0]['device'])
        self.assertEqual("8", info['devices'][0]['host'])
        self.assertEqual("0", info['devices'][0]['channel'])
        self.assertEqual("0", info['devices'][0]['id'])
        self.assertEqual("9", info['devices'][0]['lun'])

        self.assertEqual("/dev/sdac", info['devices'][1]['device'])
        self.assertEqual("8", info['devices'][1]['host'])
        self.assertEqual("0", info['devices'][1]['channel'])
        self.assertEqual("1", info['devices'][1]['id'])
        self.assertEqual("9", info['devices'][1]['lun'])

    @mock.patch('os_brick.utils._time_sleep')
    def test_wait_for_rw(self, mock_sleep):
        lsblk_output = """3624a93709a738ed78583fd1200143029 (dm-2)  0
sdb                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdc                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdd                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sde                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdf                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdg                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sdh                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdi                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdj                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sdk                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdl                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdm                                       0
vda1                                      0
vdb                                       0
vdb1                                      0
loop0                                     0"""

        mock_execute = mock.Mock()
        mock_execute.return_value = (lsblk_output, None)
        self.linuxscsi._execute = mock_execute

        wwn = '3624a93709a738ed78583fd120014a2bb'
        path = '/dev/disk/by-id/dm-uuid-mpath-' + wwn

        # Ensure no exception is raised and no sleep is called
        self.linuxscsi.wait_for_rw(wwn, path)
        self.assertFalse(mock_sleep.called)

    @mock.patch('os_brick.utils._time_sleep')
    def test_wait_for_rw_needs_retry(self, mock_sleep):
        lsblk_ro_output = """3624a93709a738ed78583fd1200143029 (dm-2)  0
sdb                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdc                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdd                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  1
sde                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdf                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdg                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  1
sdh                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdi                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdj                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  1
sdk                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdl                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdm                                       0
vda1                                      0
vdb                                       0
vdb1                                      0
loop0                                     0"""
        lsblk_rw_output = """3624a93709a738ed78583fd1200143029 (dm-2)  0
sdb                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdc                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdd                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sde                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdf                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdg                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sdh                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdi                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdj                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sdk                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdl                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  0
sdm                                       0
vda1                                      0
vdb                                       0
vdb1                                      0
loop0                                     0"""
        mock_execute = mock.Mock()
        mock_execute.side_effect = [(lsblk_ro_output, None),
                                    ('', None),  # multipath -r output
                                    (lsblk_rw_output, None)]
        self.linuxscsi._execute = mock_execute

        wwn = '3624a93709a738ed78583fd1200143029'
        path = '/dev/disk/by-id/dm-uuid-mpath-' + wwn

        self.linuxscsi.wait_for_rw(wwn, path)
        self.assertEqual(1, mock_sleep.call_count)

    @mock.patch('os_brick.utils._time_sleep')
    def test_wait_for_rw_always_readonly(self, mock_sleep):
        lsblk_output = """3624a93709a738ed78583fd1200143029 (dm-2)  0
sdb                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdc                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  1
sdd                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sde                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdf                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  1
sdg                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sdh                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdi                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  1
sdj                                       0
3624a93709a738ed78583fd1200143029 (dm-2)  0
sdk                                       0
3624a93709a738ed78583fd120014724e (dm-1)  0
sdl                                       0
3624a93709a738ed78583fd120014a2bb (dm-0)  1
sdm                                       0
vda1                                      0
vdb                                       0
vdb1                                      0
loop0                                     0"""

        mock_execute = mock.Mock()
        mock_execute.return_value = (lsblk_output, None)
        self.linuxscsi._execute = mock_execute

        wwn = '3624a93709a738ed78583fd120014a2bb'
        path = '/dev/disk/by-id/dm-uuid-mpath-' + wwn

        self.assertRaises(exception.BlockDeviceReadOnly,
                          self.linuxscsi.wait_for_rw,
                          wwn,
                          path)

        self.assertEqual(4, mock_sleep.call_count)

    def test_find_multipath_device_with_action(self):
        def fake_execute(*cmd, **kwargs):
            out = textwrap.dedent("""
                create: 36005076303ffc48e0000000000000101 dm-2 IBM,2107900
                size=1.0G features='1 queue_if_no_path' hwhandler='0'
                 wp=rw
                `-+- policy='round-robin 0' prio=-1 status=active
                  |- 6:0:2:0 sdd 8:64  active undef  running
                  `- 6:1:0:3 sdc 8:32  active undef  running
                """)
            return out, None

        self.linuxscsi._execute = fake_execute
        info = self.linuxscsi.find_multipath_device('/dev/sdd')
        LOG.error("Device info: %s", info)

        self.assertEqual('36005076303ffc48e0000000000000101', info['id'])
        self.assertEqual('36005076303ffc48e0000000000000101', info['name'])
        self.assertEqual('/dev/mapper/36005076303ffc48e0000000000000101',
                         info['device'])

        self.assertEqual("/dev/sdd", info['devices'][0]['device'])
        self.assertEqual("6", info['devices'][0]['host'])
        self.assertEqual("0", info['devices'][0]['channel'])
        self.assertEqual("2", info['devices'][0]['id'])
        self.assertEqual("0", info['devices'][0]['lun'])

        self.assertEqual("/dev/sdc", info['devices'][1]['device'])
        self.assertEqual("6", info['devices'][1]['host'])
        self.assertEqual("1", info['devices'][1]['channel'])
        self.assertEqual("0", info['devices'][1]['id'])
        self.assertEqual("3", info['devices'][1]['lun'])

    def test_get_device_size(self):
        mock_execute = mock.Mock()
        self.linuxscsi._execute = mock_execute
        size = '1024'
        mock_execute.return_value = (size, None)

        ret_size = self.linuxscsi.get_device_size('/dev/fake')
        self.assertEqual(int(size), ret_size)

        size = 'junk'
        mock_execute.return_value = (size, None)
        ret_size = self.linuxscsi.get_device_size('/dev/fake')
        self.assertIsNone(ret_size)

        size_bad = '1024\n'
        size_good = 1024
        mock_execute.return_value = (size_bad, None)
        ret_size = self.linuxscsi.get_device_size('/dev/fake')
        self.assertEqual(size_good, ret_size)

    def test_multipath_reconfigure(self):
        self.linuxscsi.multipath_reconfigure()
        expected_commands = ['multipathd reconfigure']
        self.assertEqual(expected_commands, self.cmds)

    def test_multipath_resize_map(self):
        wwn = '1234567890123456'
        self.linuxscsi.multipath_resize_map(wwn)
        expected_commands = ['multipathd resize map %s' % wwn]
        self.assertEqual(expected_commands, self.cmds)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    def test_extend_volume_no_mpath(self, mock_device_info,
                                    mock_device_size,
                                    mock_scsi_wwn,
                                    mock_find_mpath_path):
        """Test extending a volume where there is no multipath device."""
        fake_device = {'host': '0',
                       'channel': '0',
                       'id': '0',
                       'lun': '1'}
        mock_device_info.return_value = fake_device

        first_size = 1024
        second_size = 2048

        mock_device_size.side_effect = [first_size, second_size]
        wwn = '1234567890123456'
        mock_scsi_wwn.return_value = wwn
        mock_find_mpath_path.return_value = None

        ret_size = self.linuxscsi.extend_volume(['/dev/fake'])
        self.assertEqual(second_size, ret_size)

        # because we don't mock out the echo_scsi_command
        expected_cmds = ['tee -a /sys/bus/scsi/drivers/sd/0:0:0:1/rescan']
        self.assertEqual(expected_cmds, self.cmds)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    def test_extend_volume_with_mpath(self, mock_device_info,
                                      mock_device_size,
                                      mock_scsi_wwn,
                                      mock_find_mpath_path):
        """Test extending a volume where there is a multipath device."""
        mock_device_info.side_effect = [{'host': host,
                                         'channel': '0',
                                         'id': '0',
                                         'lun': '1'} for host in ['0', '1']]

        mock_device_size.side_effect = [1024, 2048, 1024, 2048, 1024, 2048]
        wwn = '1234567890123456'
        mock_scsi_wwn.return_value = wwn
        mock_find_mpath_path.return_value = ('/dev/mapper/dm-uuid-mpath-%s' %
                                             wwn)

        ret_size = self.linuxscsi.extend_volume(['/dev/fake1', '/dev/fake2'],
                                                use_multipath=True)
        self.assertEqual(2048, ret_size)

        # because we don't mock out the echo_scsi_command
        expected_cmds = ['tee -a /sys/bus/scsi/drivers/sd/0:0:0:1/rescan',
                         'tee -a /sys/bus/scsi/drivers/sd/1:0:0:1/rescan',
                         'multipathd reconfigure',
                         'multipathd resize map %s' % wwn]
        self.assertEqual(expected_cmds, self.cmds)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_resize_map')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_size')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    def test_extend_volume_with_mpath_fail(self, mock_device_info,
                                           mock_device_size,
                                           mock_scsi_wwn,
                                           mock_find_mpath_path,
                                           mock_mpath_resize_map):
        """Test extending a volume where there is a multipath device fail."""
        mock_device_info.side_effect = [{'host': host,
                                         'channel': '0',
                                         'id': '0',
                                         'lun': '1'} for host in ['0', '1']]

        mock_device_size.side_effect = [1024, 2048, 1024, 2048, 1024, 2048]
        wwn = '1234567890123456'
        mock_scsi_wwn.return_value = wwn
        mock_find_mpath_path.return_value = ('/dev/mapper/dm-uuid-mpath-%s' %
                                             wwn)

        mock_mpath_resize_map.return_value = 'fail'

        ret_size = self.linuxscsi.extend_volume(['/dev/fake1', '/dev/fake2'],
                                                use_multipath=True)
        self.assertIsNone(ret_size)

        # because we don't mock out the echo_scsi_command
        expected_cmds = ['tee -a /sys/bus/scsi/drivers/sd/0:0:0:1/rescan',
                         'tee -a /sys/bus/scsi/drivers/sd/1:0:0:1/rescan',
                         'multipathd reconfigure']
        self.assertEqual(expected_cmds, self.cmds)

    def test_process_lun_id_list(self):
        lun_list = [2, 255, 88, 370, 5, 256]
        result = self.linuxscsi.process_lun_id(lun_list)
        expected = [2, 255, 88, '0x0172000000000000',
                    5, '0x0100000000000000']

        self.assertEqual(expected, result)

    def test_process_lun_id_single_val_make_hex(self):
        lun_id = 499
        result = self.linuxscsi.process_lun_id(lun_id)
        expected = '0x01f3000000000000'
        self.assertEqual(expected, result)

    def test_process_lun_id_single_val_make_hex_border_case(self):
        lun_id = 256
        result = self.linuxscsi.process_lun_id(lun_id)
        expected = '0x0100000000000000'
        self.assertEqual(expected, result)

    def test_process_lun_id_single_var_return(self):
        lun_id = 13
        result = self.linuxscsi.process_lun_id(lun_id)
        expected = 13
        self.assertEqual(expected, result)

    @mock.patch('os_brick.privileged.rootwrap.execute', return_value=('', ''))
    def test_is_multipath_running(self, mock_exec):
        res = linuxscsi.LinuxSCSI.is_multipath_running(False, None, mock_exec)
        self.assertTrue(res)
        mock_exec.assert_called_once_with(
            'multipathd', 'show', 'status', run_as_root=True, root_helper=None)

    @mock.patch.object(linuxscsi, 'LOG')
    @mock.patch('os_brick.privileged.rootwrap.execute')
    def test_is_multipath_running_failure(
        self, mock_exec, mock_log
    ):
        mock_exec.side_effect = putils.ProcessExecutionError()
        self.assertRaises(putils.ProcessExecutionError,
                          linuxscsi.LinuxSCSI.is_multipath_running,
                          True, None, mock_exec)
        mock_log.error.assert_called_once()

    @mock.patch.object(linuxscsi, 'LOG')
    @mock.patch('os_brick.privileged.rootwrap.execute')
    def test_is_multipath_running_failure_exit_code_0(
        self, mock_exec, mock_log
    ):
        mock_exec.return_value = ('error receiving packet', '')
        self.assertRaises(putils.ProcessExecutionError,
                          linuxscsi.LinuxSCSI.is_multipath_running,
                          True, None, mock_exec)
        mock_exec.assert_called_once_with(
            'multipathd', 'show', 'status', run_as_root=True, root_helper=None)
        mock_log.error.assert_called_once()

    @mock.patch.object(linuxscsi, 'LOG')
    @mock.patch('os_brick.privileged.rootwrap.execute')
    def test_is_multipath_running_failure_not_enforcing_multipath(
        self, mock_exec, mock_log
    ):
        mock_exec.side_effect = putils.ProcessExecutionError()
        res = linuxscsi.LinuxSCSI.is_multipath_running(False, None, mock_exec)
        mock_exec.assert_called_once_with(
            'multipathd', 'show', 'status', run_as_root=True, root_helper=None)
        self.assertFalse(res)
        mock_log.error.assert_not_called()

    @mock.patch.object(linuxscsi, 'LOG')
    @mock.patch('os_brick.privileged.rootwrap.execute')
    def test_is_multipath_running_failure_not_enforcing_exit_code_0(
        self, mock_exec, mock_log
    ):
        mock_exec.return_value = ('error receiving packet', '')
        res = linuxscsi.LinuxSCSI.is_multipath_running(False, None, mock_exec)
        mock_exec.assert_called_once_with(
            'multipathd', 'show', 'status', run_as_root=True, root_helper=None)
        self.assertFalse(res)
        mock_log.error.assert_not_called()

    def test_get_device_info(self):
        ret = "[1:1:0:0] disk Vendor Array 0100 /dev/adevice\n"
        with mock.patch.object(self.linuxscsi, '_execute') as exec_mock:
            exec_mock.return_value = (ret, "")
            info = self.linuxscsi.get_device_info('/dev/adevice')

            exec_mock.assert_called_once_with('lsscsi')
            self.assertEqual(info, {'channel': '1',
                                    'device': '/dev/adevice',
                                    'host': '1',
                                    'id': '0',
                                    'lun': '0'})

    @mock.patch('builtins.open')
    def test_get_sysfs_wwn_mpath(self, open_mock):
        wwn = '3600d0230000000000e13955cc3757800'
        cm_open = open_mock.return_value.__enter__.return_value
        cm_open.read.return_value = 'mpath-' + wwn

        res = self.linuxscsi.get_sysfs_wwn(mock.sentinel.device_names, 'dm-1')
        open_mock.assert_called_once_with('/sys/block/dm-1/dm/uuid')
        self.assertEqual(wwn, res)

    @mock.patch('glob.glob')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwid')
    def test_get_sysfs_wwn_single_designator(self, get_wwid_mock, glob_mock):
        glob_mock.return_value = ['/dev/disk/by-id/scsi-wwid1',
                                  '/dev/disk/by-id/scsi-wwid2']
        get_wwid_mock.return_value = 'wwid1'
        res = self.linuxscsi.get_sysfs_wwn(mock.sentinel.device_names)
        self.assertEqual('wwid1', res)
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        get_wwid_mock.assert_called_once_with(mock.sentinel.device_names)

    @mock.patch('builtins.open', side_effect=Exception)
    @mock.patch('glob.glob')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwid')
    def test_get_sysfs_wwn_mpath_exc(self, get_wwid_mock, glob_mock,
                                     open_mock):
        glob_mock.return_value = ['/dev/disk/by-id/scsi-wwid1',
                                  '/dev/disk/by-id/scsi-wwid2']
        get_wwid_mock.return_value = 'wwid1'
        res = self.linuxscsi.get_sysfs_wwn(mock.sentinel.device_names, 'dm-1')
        open_mock.assert_called_once_with('/sys/block/dm-1/dm/uuid')
        self.assertEqual('wwid1', res)
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        get_wwid_mock.assert_called_once_with(mock.sentinel.device_names)

    @mock.patch('os.listdir', return_value=['sda', 'sdd'])
    @mock.patch('os.path.realpath', side_effect=('/other/path',
                                                 '/dev/dm-5',
                                                 '/dev/sda', '/dev/sdb'))
    @mock.patch('os.path.islink', side_effect=(False,) + (True,) * 5)
    @mock.patch('os.stat', side_effect=(False,) + (True,) * 4)
    @mock.patch('glob.glob')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwid')
    def test_get_sysfs_wwn_multiple_designators(self, get_wwid_mock, glob_mock,
                                                stat_mock, islink_mock,
                                                realpath_mock, listdir_mock):
        glob_mock.return_value = ['/dev/disk/by-id/scsi-fail-link',
                                  '/dev/disk/by-id/scsi-fail-stat',
                                  '/dev/disk/by-id/scsi-non-dev',
                                  '/dev/disk/by-id/scsi-another-dm',
                                  '/dev/disk/by-id/scsi-wwid1',
                                  '/dev/disk/by-id/scsi-wwid2']

        get_wwid_mock.return_value = 'pre-wwid'
        devices = ['sdb', 'sdc']
        res = self.linuxscsi.get_sysfs_wwn(devices)
        self.assertEqual('wwid2', res)
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        listdir_mock.assert_called_once_with('/sys/class/block/dm-5/slaves')
        get_wwid_mock.assert_called_once_with(devices)

    @mock.patch('os.listdir', side_effect=[['sda', 'sdb'], ['sdc', 'sdd']])
    @mock.patch('os.path.realpath', side_effect=('/dev/sde',
                                                 '/dev/dm-5',
                                                 '/dev/dm-6'))
    @mock.patch('os.path.islink', mock.Mock())
    @mock.patch('os.stat', mock.Mock())
    @mock.patch('glob.glob')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwid', return_value='')
    def test_get_sysfs_wwn_dm_link(self, get_wwid_mock, glob_mock,
                                   realpath_mock, listdir_mock):
        glob_mock.return_value = ['/dev/disk/by-id/scsi-wwid1',
                                  '/dev/disk/by-id/scsi-another-dm',
                                  '/dev/disk/by-id/scsi-our-dm']

        devices = ['sdc', 'sdd']
        res = self.linuxscsi.get_sysfs_wwn(devices)
        self.assertEqual('our-dm', res)
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        listdir_mock.assert_has_calls(
            [mock.call('/sys/class/block/dm-5/slaves'),
             mock.call('/sys/class/block/dm-6/slaves')])
        get_wwid_mock.assert_called_once_with(devices)

    @mock.patch('os.path.realpath', side_effect=('/dev/sda', '/dev/sdb'))
    @mock.patch('os.path.islink', return_value=True)
    @mock.patch('os.stat', return_value=True)
    @mock.patch('glob.glob')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwid')
    def test_get_sysfs_wwn_not_found(self, get_wwid_mock, glob_mock, stat_mock,
                                     islink_mock, realpath_mock):
        glob_mock.return_value = ['/dev/disk/by-id/scsi-wwid1',
                                  '/dev/disk/by-id/scsi-wwid2']
        get_wwid_mock.return_value = 'pre-wwid'
        devices = ['sdc']
        res = self.linuxscsi.get_sysfs_wwn(devices)
        self.assertEqual('', res)
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        get_wwid_mock.assert_called_once_with(devices)

    @mock.patch('glob.glob', return_value=[])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwid')
    def test_get_sysfs_wwn_no_links(self, get_wwid_mock, glob_mock):
        get_wwid_mock.return_value = ''
        devices = ['sdc']
        res = self.linuxscsi.get_sysfs_wwn(devices)
        self.assertEqual('', res)
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        get_wwid_mock.assert_called_once_with(devices)

    @ddt.data({'wwn_type': 't10.', 'num_val': '1'},
              {'wwn_type': 'eui.', 'num_val': '2'},
              {'wwn_type': 'naa.', 'num_val': '3'})
    @ddt.unpack
    @mock.patch('builtins.open')
    def test_get_sysfs_wwid(self, open_mock, wwn_type, num_val):
        read_fail = mock.MagicMock()
        read_fail.__enter__.return_value.read.side_effect = IOError
        read_data = mock.MagicMock()
        read_data.__enter__.return_value.read.return_value = (wwn_type +
                                                              'wwid1\n')
        open_mock.side_effect = (IOError, read_fail, read_data)

        res = self.linuxscsi.get_sysfs_wwid(['sda', 'sdb', 'sdc'])
        self.assertEqual(num_val + 'wwid1', res)
        open_mock.assert_has_calls([mock.call('/sys/block/sda/device/wwid'),
                                    mock.call('/sys/block/sdb/device/wwid'),
                                    mock.call('/sys/block/sdc/device/wwid')])

    @mock.patch('builtins.open', side_effect=IOError)
    def test_get_sysfs_wwid_not_found(self, open_mock):
        res = self.linuxscsi.get_sysfs_wwid(['sda', 'sdb'])
        self.assertEqual('', res)
        open_mock.assert_has_calls([mock.call('/sys/block/sda/device/wwid'),
                                    mock.call('/sys/block/sdb/device/wwid')])

    @mock.patch.object(linuxscsi.priv_rootwrap, 'unlink_root')
    @mock.patch('glob.glob')
    @mock.patch('os.path.realpath', side_effect=['/dev/sda', '/dev/sdb',
                                                 '/dev/sdc'])
    def test_remove_scsi_symlinks(self, realpath_mock, glob_mock, unlink_mock):
        paths = ['/dev/disk/by-id/scsi-wwid1', '/dev/disk/by-id/scsi-wwid2',
                 '/dev/disk/by-id/scsi-wwid3']
        glob_mock.return_value = paths
        self.linuxscsi._remove_scsi_symlinks(['sdb', 'sdc', 'sdd'])
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        realpath_mock.assert_has_calls([mock.call(g) for g in paths])
        unlink_mock.assert_called_once_with(no_errors=True, *paths[1:])

    @mock.patch.object(linuxscsi.priv_rootwrap, 'unlink_root')
    @mock.patch('glob.glob')
    @mock.patch('os.path.realpath', side_effect=['/dev/sda', '/dev/sdb'])
    def test_remove_scsi_symlinks_no_links(self, realpath_mock, glob_mock,
                                           unlink_mock):
        paths = ['/dev/disk/by-id/scsi-wwid1', '/dev/disk/by-id/scsi-wwid2']
        glob_mock.return_value = paths
        self.linuxscsi._remove_scsi_symlinks(['sdd', 'sde'])
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        realpath_mock.assert_has_calls([mock.call(g) for g in paths])
        unlink_mock.assert_not_called()

    @mock.patch.object(linuxscsi.priv_rootwrap, 'unlink_root')
    @mock.patch('glob.glob')
    @mock.patch('os.path.realpath', side_effect=[OSError, '/dev/sda'])
    def test_remove_scsi_symlinks_race_condition(self, realpath_mock,
                                                 glob_mock, unlink_mock):
        paths = ['/dev/disk/by-id/scsi-wwid1', '/dev/disk/by-id/scsi-wwid2']
        glob_mock.return_value = paths
        self.linuxscsi._remove_scsi_symlinks(['sda'])
        glob_mock.assert_called_once_with('/dev/disk/by-id/scsi-*')
        realpath_mock.assert_has_calls([mock.call(g) for g in paths])
        unlink_mock.assert_called_once_with(paths[1], no_errors=True)

    @mock.patch('glob.glob')
    def test_get_hctl_with_target(self, glob_mock):
        glob_mock.return_value = [
            '/sys/class/iscsi_host/host3/device/session1/target3:4:5',
            '/sys/class/iscsi_host/host3/device/session1/target3:4:6']
        res = self.linuxscsi.get_hctl('1', '2')
        self.assertEqual(('3', '4', '5', '2'), res)
        glob_mock.assert_called_once_with(
            '/sys/class/iscsi_host/host*/device/session1/target*')

    @mock.patch('glob.glob')
    def test_get_hctl_no_target(self, glob_mock):
        glob_mock.side_effect = [
            [],
            ['/sys/class/iscsi_host/host3/device/session1',
             '/sys/class/iscsi_host/host3/device/session1']]
        res = self.linuxscsi.get_hctl('1', '2')
        self.assertEqual(('3', '-', '-', '2'), res)
        glob_mock.assert_has_calls(
            [mock.call('/sys/class/iscsi_host/host*/device/session1/target*'),
             mock.call('/sys/class/iscsi_host/host*/device/session1')])

    @mock.patch('glob.glob', return_value=[])
    def test_get_hctl_no_paths(self, glob_mock):
        res = self.linuxscsi.get_hctl('1', '2')
        self.assertIsNone(res)
        glob_mock.assert_has_calls(
            [mock.call('/sys/class/iscsi_host/host*/device/session1/target*'),
             mock.call('/sys/class/iscsi_host/host*/device/session1')])

    @mock.patch('glob.glob')
    def test_device_name_by_hctl(self, glob_mock):
        glob_mock.return_value = [
            '/sys/class/scsi_host/host3/device/session1/target3:4:5/3:4:5:2/'
            'block/sda2',
            '/sys/class/scsi_host/host3/device/session1/target3:4:5/3:4:5:2/'
            'block/sda']
        res = self.linuxscsi.device_name_by_hctl('1', ('3', '4', '5', '2'))
        self.assertEqual('sda', res)
        glob_mock.assert_called_once_with(
            '/sys/class/scsi_host/host3/device/session1/target3:4:5/3:4:5:2/'
            'block/*')

    @mock.patch('glob.glob')
    def test_device_name_by_hctl_wildcards(self, glob_mock):
        glob_mock.return_value = [
            '/sys/class/scsi_host/host3/device/session1/target3:4:5/3:4:5:2/'
            'block/sda2',
            '/sys/class/scsi_host/host3/device/session1/target3:4:5/3:4:5:2/'
            'block/sda']
        res = self.linuxscsi.device_name_by_hctl('1', ('3', '-', '-', '2'))
        self.assertEqual('sda', res)
        glob_mock.assert_called_once_with(
            '/sys/class/scsi_host/host3/device/session1/target3:*:*/3:*:*:2/'
            'block/*')

    @mock.patch('glob.glob', mock.Mock(return_value=[]))
    def test_device_name_by_hctl_no_devices(self):
        res = self.linuxscsi.device_name_by_hctl('1', ('4', '5', '6', '2'))
        self.assertIsNone(res)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'echo_scsi_command')
    def test_scsi_iscsi(self, echo_mock):
        self.linuxscsi.scan_iscsi('host', 'channel', 'target', 'lun')
        echo_mock.assert_called_once_with('/sys/class/scsi_host/hosthost/scan',
                                          'channel target lun')

    def test_multipath_add_wwid(self):
        self.linuxscsi.multipath_add_wwid('wwid1')
        self.assertEqual(['multipath -a wwid1'], self.cmds)

    def test_multipath_add_path(self):
        self.linuxscsi.multipath_add_path('/dev/sda')
        self.assertEqual(['multipathd add path /dev/sda'], self.cmds)

    def test_multipath_del_path(self):
        self.linuxscsi.multipath_del_path('/dev/sda')
        self.assertEqual(['multipathd del path /dev/sda'], self.cmds)

    @ddt.data(('/dev/sda', '/dev/sda', False, True, None),
              # This checks that we ignore the was_multipath parameter if it
              # doesn't make sense (because the used path is the one we are
              # asking about)
              ('/dev/sda', '/dev/sda', True, True, None),
              ('/dev/sda', '', True, False, None),
              # Check for encrypted volume
              ('/dev/link_sda', '/dev/disk/by-path/pci-XYZ', False, True,
               ('/dev/sda', '/dev/mapper/crypt-pci-XYZ')),
              ('/dev/link_sda', '/dev/link_sdb', False, False, ('/dev/sda',
                                                                '/dev/sdb')),
              ('/dev/link_sda', '/dev/link2_sda', False, True, ('/dev/sda',
                                                                '/dev/sda')))
    @ddt.unpack
    def test_requires_flush(self, path, path_used, was_multipath, expected,
                            real_paths):
        with mock.patch('os.path.realpath', side_effect=real_paths) as mocked:
            self.assertEqual(
                expected,
                self.linuxscsi.requires_flush(path, path_used, was_multipath))
            if real_paths:
                mocked.assert_has_calls([mock.call(path),
                                         mock.call(path_used)])
