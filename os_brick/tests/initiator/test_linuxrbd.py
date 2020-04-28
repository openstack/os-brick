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

from unittest import mock

from os_brick import exception
from os_brick.initiator import linuxrbd
from os_brick.tests import base
from os_brick import utils


class MockRados(object):

    class Error(Exception):
        pass

    class ioctx(object):
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self, *args, **kwargs):
            return self

        def __exit__(self, *args, **kwargs):
            return False

        def close(self, *args, **kwargs):
            pass

    class Rados(object):

        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self, *args, **kwargs):
            return self

        def __exit__(self, *args, **kwargs):
            return False

        def connect(self, *args, **kwargs):
            pass

        def open_ioctx(self, *args, **kwargs):
            return MockRados.ioctx()

        def shutdown(self, *args, **kwargs):
            pass


class RBDClientTestCase(base.TestCase):

    def setUp(self):
        super(RBDClientTestCase, self).setUp()

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    def test_with_client(self, mock_rados, mock_rbd):
        with linuxrbd.RBDClient('test_user', 'test_pool') as client:

            # Verify object attributes are assigned as expected
            self.assertEqual('/etc/ceph/ceph.conf', client.rbd_conf)
            self.assertEqual(utils.convert_str('test_user'), client.rbd_user)
            self.assertEqual(utils.convert_str('test_pool'), client.rbd_pool)

            # Assert connect is called with correct paramaters
            mock_rados.Rados.assert_called_once_with(
                clustername='ceph',
                rados_id=utils.convert_str('test_user'),
                conffile='/etc/ceph/ceph.conf')

            # Ensure correct calls to connect to cluster
            self.assertEqual(
                1, mock_rados.Rados.return_value.connect.call_count)
            mock_rados.Rados.return_value.open_ioctx.assert_called_once_with(
                utils.convert_str('test_pool'))

        self.assertEqual(1, mock_rados.Rados.return_value.shutdown.call_count)

    @mock.patch.object(MockRados.Rados, 'connect', side_effect=MockRados.Error)
    def test_with_client_error(self, _):
        linuxrbd.rados = MockRados
        linuxrbd.rados.Error = MockRados.Error

        def test():
            with linuxrbd.RBDClient('test_user', 'test_pool'):
                pass

        self.assertRaises(exception.BrickException, test)


class RBDVolumeIOWrapperTestCase(base.TestCase):

    def setUp(self):
        super(RBDVolumeIOWrapperTestCase, self).setUp()
        self.mock_volume = mock.Mock()
        self.mock_volume_wrapper = \
            linuxrbd.RBDVolumeIOWrapper(self.mock_volume)
        self.data_length = 1024
        self.full_data = 'abcd' * 256

    def test_init(self):
        self.assertEqual(self.mock_volume,
                         self.mock_volume_wrapper._rbd_volume)
        self.assertEqual(0, self.mock_volume_wrapper._offset)

    def test_inc_offset(self):
        self.mock_volume_wrapper._inc_offset(10)
        self.mock_volume_wrapper._inc_offset(10)
        self.assertEqual(20, self.mock_volume_wrapper._offset)

    def test_read(self):

        def mock_read(offset, length):
            return self.full_data[offset:length]

        self.mock_volume.image.read.side_effect = mock_read
        self.mock_volume.image.size.return_value = self.data_length

        data = self.mock_volume_wrapper.read()
        self.assertEqual(self.full_data, data)

        data = self.mock_volume_wrapper.read()
        self.assertEqual(b'', data)

        self.mock_volume_wrapper.seek(0)
        data = self.mock_volume_wrapper.read()
        self.assertEqual(self.full_data, data)

        self.mock_volume_wrapper.seek(0)
        data = self.mock_volume_wrapper.read(10)
        self.assertEqual(self.full_data[:10], data)

    def test_write(self):
        self.mock_volume_wrapper.write(self.full_data)
        self.assertEqual(1024, self.mock_volume_wrapper._offset)

    def test_seekable(self):
        self.assertTrue(self.mock_volume_wrapper.seekable)

    def test_seek(self):
        self.assertEqual(0, self.mock_volume_wrapper._offset)
        self.mock_volume_wrapper.seek(10)
        self.assertEqual(10, self.mock_volume_wrapper._offset)
        self.mock_volume_wrapper.seek(10)
        self.assertEqual(10, self.mock_volume_wrapper._offset)
        self.mock_volume_wrapper.seek(10, 1)
        self.assertEqual(20, self.mock_volume_wrapper._offset)

        self.mock_volume_wrapper.seek(0)
        self.mock_volume_wrapper.write(self.full_data)
        self.mock_volume.image.size.return_value = self.data_length
        self.mock_volume_wrapper.seek(0)
        self.assertEqual(0, self.mock_volume_wrapper._offset)

        self.mock_volume_wrapper.seek(10, 2)
        self.assertEqual(self.data_length + 10,
                         self.mock_volume_wrapper._offset)
        self.mock_volume_wrapper.seek(-10, 2)
        self.assertEqual(self.data_length - 10,
                         self.mock_volume_wrapper._offset)

        # test exceptions.
        self.assertRaises(IOError, self.mock_volume_wrapper.seek, 0, 3)
        self.assertRaises(IOError, self.mock_volume_wrapper.seek, -1)
        # offset should not have been changed by any of the previous
        # operations.
        self.assertEqual(self.data_length - 10,
                         self.mock_volume_wrapper._offset)

    def test_tell(self):
        self.assertEqual(0, self.mock_volume_wrapper.tell())
        self.mock_volume_wrapper._inc_offset(10)
        self.assertEqual(10, self.mock_volume_wrapper.tell())

    def test_flush(self):
        with mock.patch.object(linuxrbd, 'LOG') as mock_logger:
            self.mock_volume.image.flush = mock.Mock()
            self.mock_volume_wrapper.flush()
            self.assertEqual(1, self.mock_volume.image.flush.call_count)
            self.mock_volume.image.flush.reset_mock()
            # this should be caught and logged silently.
            self.mock_volume.image.flush.side_effect = AttributeError
            self.mock_volume_wrapper.flush()
            self.assertEqual(1, self.mock_volume.image.flush.call_count)
            self.assertEqual(1, mock_logger.warning.call_count)

    def test_fileno(self):
        self.assertRaises(IOError, self.mock_volume_wrapper.fileno)

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    @mock.patch.object(linuxrbd.RBDClient, 'disconnect')
    def test_close(self, rbd_disconnect, mock_rados, mock_rbd):
        rbd_client = linuxrbd.RBDClient('user', 'pool')
        rbd_volume = linuxrbd.RBDVolume(rbd_client, 'volume')
        rbd_handle = linuxrbd.RBDVolumeIOWrapper(
            linuxrbd.RBDImageMetadata(rbd_volume, 'pool', 'user', None))
        rbd_handle.close()
        self.assertEqual(1, rbd_disconnect.call_count)


class RBDVolumeTestCase(base.TestCase):
    def test_name_attribute(self):
        mock_client = mock.Mock()
        rbd_volume = linuxrbd.RBDVolume(mock_client, 'volume')
        self.assertEqual('volume', rbd_volume.name)
