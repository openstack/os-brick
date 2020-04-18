# Copyright (c) 2015 Scality
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

import errno
from unittest import mock


from os_brick.initiator import host_driver
from os_brick.tests import base


class HostDriverTestCase(base.TestCase):

    def test_get_all_block_devices(self):
        fake_dev = ['device1', 'device2']
        expected = ['/dev/disk/by-path/' + dev for dev in fake_dev]

        driver = host_driver.HostDriver()
        with mock.patch('os.listdir', return_value=fake_dev):
            actual = driver.get_all_block_devices()

        self.assertEqual(expected, actual)

    def test_get_all_block_devices_when_oserror_is_enoent(self):
        driver = host_driver.HostDriver()
        oserror = OSError(errno.ENOENT, "")
        with mock.patch('os.listdir', side_effect=oserror):
            block_devices = driver.get_all_block_devices()

        self.assertEqual([], block_devices)

    def test_get_all_block_devices_when_oserror_is_not_enoent(self):
        driver = host_driver.HostDriver()
        oserror = OSError(errno.ENOMEM, "")
        with mock.patch('os.listdir', side_effect=oserror):
            self.assertRaises(OSError, driver.get_all_block_devices)
