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
import time

import mock
from oslo_log import log as logging

from os_brick import exception
from os_brick.initiator import linuxscsi
from os_brick.tests import base

LOG = logging.getLogger(__name__)


class LinuxSCSITestCase(base.TestCase):
    def setUp(self):
        super(LinuxSCSITestCase, self).setUp()
        self.cmds = []
        mock.patch.object(os.path, 'realpath', return_value='/dev/sdc').start()
        mock.patch.object(os, 'stat', returns=os.stat(__file__)).start()
        self.addCleanup(mock.patch.stopall)
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

    @mock.patch('time.sleep')
    def test_wait_for_volume_removal(self, sleep_mock):
        fake_path = '/dev/disk/by-path/fake-iscsi-iqn-lun-0'
        exists_mock = mock.Mock()
        exists_mock.return_value = True
        os.path.exists = exists_mock
        self.assertRaises(exception.VolumePathNotRemoved,
                          self.linuxscsi.wait_for_volume_removal,
                          fake_path)

        exists_mock = mock.Mock()
        exists_mock.return_value = False
        os.path.exists = exists_mock
        self.linuxscsi.wait_for_volume_removal(fake_path)
        expected_commands = []
        self.assertEqual(expected_commands, self.cmds)
        self.assertTrue(sleep_mock.called)

    def test_flush_multipath_device(self):
        self.linuxscsi.flush_multipath_device('/dev/dm-9')
        expected_commands = [('multipath -f /dev/dm-9')]
        self.assertEqual(expected_commands, self.cmds)

    def test_flush_multipath_devices(self):
        self.linuxscsi.flush_multipath_devices()
        expected_commands = [('multipath -F')]
        self.assertEqual(expected_commands, self.cmds)

    def test_get_scsi_wwn(self):
        fake_path = '/dev/disk/by-id/somepath'
        fake_wwn = '1234567890'

        def fake_execute(*cmd, **kwargs):
            return fake_wwn, None

        self.linuxscsi._execute = fake_execute
        wwn = self.linuxscsi.get_scsi_wwn(fake_path)
        self.assertEqual(fake_wwn, wwn)

    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_find_multipath_device_path(self, exists_mock):
        fake_wwn = '1234567890'
        found_path = self.linuxscsi.find_multipath_device_path(fake_wwn)
        expected_path = '/dev/disk/by-id/dm-uuid-mpath-%s' % fake_wwn
        self.assertEqual(expected_path, found_path)

    @mock.patch('time.sleep')
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
    @mock.patch.object(time, 'sleep')
    def test_find_multipath_device_path_fail(self, exists_mock, sleep_mock):
        fake_wwn = '1234567890'
        found_path = self.linuxscsi.find_multipath_device_path(fake_wwn)
        expected_path = None
        self.assertEqual(expected_path, found_path)

    @mock.patch.object(os.path, 'exists', return_value=False)
    @mock.patch.object(time, 'sleep')
    def test_wait_for_path_not_found(self, exists_mock, sleep_mock):
        path = "/dev/disk/by-id/dm-uuid-mpath-%s" % '1234567890'
        self.assertRaisesRegexp(exception.VolumeDeviceNotFound,
                                r'Volume device not found at %s' % path,
                                self.linuxscsi.wait_for_path,
                                path)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_remove_multipath_device(self, exists_mock, mock_multipath):
        def fake_find_multipath_device(device):
            devices = [{'device': '/dev/sde', 'host': 0,
                        'channel': 0, 'id': 0, 'lun': 1},
                       {'device': '/dev/sdf', 'host': 2,
                        'channel': 0, 'id': 0, 'lun': 1}, ]

            info = {"device": "dm-3",
                    "id": "350002ac20398383d",
                    "devices": devices}
            return info

        mock_multipath.side_effect = fake_find_multipath_device

        self.linuxscsi.remove_multipath_device('/dev/dm-3')
        expected_commands = [
            ('blockdev --flushbufs /dev/sde'),
            ('tee -a /sys/block/sde/device/delete'),
            ('blockdev --flushbufs /dev/sdf'),
            ('tee -a /sys/block/sdf/device/delete'),
            ('multipath -f 350002ac20398383d'), ]
        self.assertEqual(expected_commands, self.cmds)

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
            out = ("Oct 13 10:24:01 | /lib/udev/scsi_id exitted with 1\n"
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

    @mock.patch.object(time, 'sleep')
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

    @mock.patch.object(time, 'sleep')
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

    @mock.patch.object(time, 'sleep')
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
        LOG.error("Device info: %s" % info)

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
        self.assertEqual(None, ret_size)

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

        ret_size = self.linuxscsi.extend_volume('/dev/fake')
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
        fake_device = {'host': '0',
                       'channel': '0',
                       'id': '0',
                       'lun': '1'}
        mock_device_info.return_value = fake_device

        first_size = 1024
        second_size = 2048
        third_size = 1024
        fourth_size = 2048

        mock_device_size.side_effect = [first_size, second_size,
                                        third_size, fourth_size]
        wwn = '1234567890123456'
        mock_scsi_wwn.return_value = wwn
        mock_find_mpath_path.return_value = ('/dev/mapper/dm-uuid-mpath-%s' %
                                             wwn)

        ret_size = self.linuxscsi.extend_volume('/dev/fake')
        self.assertEqual(fourth_size, ret_size)

        # because we don't mock out the echo_scsi_command
        expected_cmds = ['tee -a /sys/bus/scsi/drivers/sd/0:0:0:1/rescan',
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
        fake_device = {'host': '0',
                       'channel': '0',
                       'id': '0',
                       'lun': '1'}
        mock_device_info.return_value = fake_device

        first_size = 1024
        second_size = 2048
        third_size = 1024
        fourth_size = 2048

        mock_device_size.side_effect = [first_size, second_size,
                                        third_size, fourth_size]
        wwn = '1234567890123456'
        mock_scsi_wwn.return_value = wwn
        mock_find_mpath_path.return_value = ('/dev/mapper/dm-uuid-mpath-%s' %
                                             wwn)

        mock_mpath_resize_map.return_value = 'fail'

        ret_size = self.linuxscsi.extend_volume('/dev/fake')
        self.assertIsNone(ret_size)

        # because we don't mock out the echo_scsi_command
        expected_cmds = ['tee -a /sys/bus/scsi/drivers/sd/0:0:0:1/rescan',
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
