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


import mock
from os_brick import exception
from os_brick.initiator import linuxsheepdog
from os_brick.tests import base
from oslo_concurrency import processutils

SHEEP_ADDR = '127.0.0.1'
SHEEP_PORT = 7000


class SheepdogVolumeIOWrapperTestCase(base.TestCase):
    def setUp(self):
        super(SheepdogVolumeIOWrapperTestCase, self).setUp()
        self.volume = 'volume-2f9b2ff5-987b-4412-a91c-23caaf0d5aff'
        self.snapshot_name = 'snapshot-bf452d80-068a-43d7-ba9f-196cf47bd0be'

        self.vdi_wrapper = linuxsheepdog.SheepdogVolumeIOWrapper(
            SHEEP_ADDR, SHEEP_PORT, self.volume)
        self.snapshot_wrapper = linuxsheepdog.SheepdogVolumeIOWrapper(
            SHEEP_ADDR, SHEEP_PORT, self.volume, self.snapshot_name)

        self.execute = mock.MagicMock()
        self.mock_object(processutils, 'execute', self.execute)

    def test_init(self):
        self.assertEqual(self.volume, self.vdi_wrapper._vdiname)
        self.assertIsNone(self.vdi_wrapper._snapshot_name)
        self.assertEqual(0, self.vdi_wrapper._offset)

        self.assertEqual(self.snapshot_name,
                         self.snapshot_wrapper._snapshot_name)

    def test_execute(self):
        cmd = ('cmd1', 'arg1')
        data = 'data1'

        self.vdi_wrapper._execute(cmd, data)

        self.execute.assert_called_once_with(*cmd, process_input=data)

    def test_execute_error(self):
        cmd = ('cmd1', 'arg1')
        data = 'data1'
        self.mock_object(processutils, 'execute',
                         mock.MagicMock(side_effect=OSError))

        args = (cmd, data)
        self.assertRaises(exception.VolumeDriverException,
                          self.vdi_wrapper._execute,
                          *args)

    def test_read_vdi(self):
        self.vdi_wrapper.read()
        self.execute.assert_called_once_with(
            'dog', 'vdi', 'read', '-a', SHEEP_ADDR, '-p', SHEEP_PORT,
            self.volume, 0, process_input=None)

    def test_read_vdi_invalid(self):
        self.vdi_wrapper._valid = False
        self.assertRaises(exception.VolumeDriverException,
                          self.vdi_wrapper.read)

    def test_write_vdi(self):
        data = 'data1'

        self.vdi_wrapper.write(data)

        self.execute.assert_called_once_with(
            'dog', 'vdi', 'write', '-a', SHEEP_ADDR, '-p', SHEEP_PORT,
            self.volume, 0, len(data),
            process_input=data)
        self.assertEqual(len(data), self.vdi_wrapper.tell())

    def test_write_vdi_invalid(self):
        self.vdi_wrapper._valid = False
        self.assertRaises(exception.VolumeDriverException,
                          self.vdi_wrapper.write, 'dummy_data')

    def test_read_snapshot(self):
        self.snapshot_wrapper.read()
        self.execute.assert_called_once_with(
            'dog', 'vdi', 'read', '-a', SHEEP_ADDR, '-p', SHEEP_PORT,
            '-s', self.snapshot_name, self.volume, 0,
            process_input=None)

    def test_seek(self):
        self.vdi_wrapper.seek(12345)
        self.assertEqual(12345, self.vdi_wrapper.tell())

        self.vdi_wrapper.seek(-2345, whence=1)
        self.assertEqual(10000, self.vdi_wrapper.tell())

        # This results in negative offset.
        self.assertRaises(IOError, self.vdi_wrapper.seek, -20000, whence=1)

    def test_seek_invalid(self):
        seek_num = 12345
        self.vdi_wrapper._valid = False
        self.assertRaises(exception.VolumeDriverException,
                          self.vdi_wrapper.seek, seek_num)

    def test_flush(self):
        # flush does nothing.
        self.vdi_wrapper.flush()
        self.assertFalse(self.execute.called)

    def test_fileno(self):
        self.assertRaises(IOError, self.vdi_wrapper.fileno)
