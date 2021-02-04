# Copyright 2020 Cloudbase Solutions Srl
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

from unittest import mock

import ddt
from oslo_concurrency import processutils

from os_brick import exception
from os_brick.initiator.windows import rbd
from os_brick.tests.initiator.connectors import test_base_rbd
from os_brick.tests.windows import test_base


@ddt.ddt
class WindowsRBDConnectorTestCase(test_base_rbd.RBDConnectorTestMixin,
                                  test_base.WindowsConnectorTestBase):
    def setUp(self):
        super(WindowsRBDConnectorTestCase, self).setUp()

        self._diskutils = mock.Mock()
        self._execute = mock.Mock(return_value=['fake_stdout', 'fake_stderr'])

        self._conn = rbd.WindowsRBDConnector(execute=self._execute)
        self._conn._diskutils = self._diskutils

        self.dev_name = '\\\\.\\PhysicalDrive5'

    @ddt.data(True, False)
    def test_check_rbd(self, rbd_available):
        self._execute.side_effect = (
            None if rbd_available
            else processutils.ProcessExecutionError)

        self.assertEqual(rbd_available, self._conn._check_rbd())

        if rbd_available:
            self._conn._ensure_rbd_available()
        else:
            self.assertRaises(exception.BrickException,
                              self._conn._ensure_rbd_available)

        expected_cmd = ['where.exe', 'rbd']
        self._execute.assert_any_call(*expected_cmd)

    @mock.patch.object(rbd.WindowsRBDConnector, 'get_device_name')
    def test_get_volume_paths(self, mock_get_dev_name):
        vol_paths = self._conn.get_volume_paths(mock.sentinel.conn_props)
        self.assertEqual([mock_get_dev_name.return_value], vol_paths)

        mock_get_dev_name.assert_called_once_with(mock.sentinel.conn_props)

    @ddt.data(True, False)
    @mock.patch.object(rbd.WindowsRBDConnector, 'get_device_name')
    @mock.patch('oslo_utils.eventletutils.EventletEvent.wait')
    def test_wait_for_volume(self, device_found, mock_wait, mock_get_dev_name):
        mock_open = mock.mock_open()
        if device_found:
            mock_get_dev_name.return_value = mock.sentinel.dev_name
        else:
            # First call fails to locate the device, the following ones can't
            # open it.
            mock_get_dev_name.side_effect = (
                [None] +
                [mock.sentinel.dev_name] * self._conn.device_scan_attempts)
            mock_open.side_effect = FileNotFoundError

        with mock.patch.object(rbd, 'open', mock_open,
                               create=True):
            if device_found:
                dev_name = self._conn._wait_for_volume(
                    self.connection_properties)
                self.assertEqual(mock.sentinel.dev_name, dev_name)
            else:
                self.assertRaises(exception.VolumeDeviceNotFound,
                                  self._conn._wait_for_volume,
                                  self.connection_properties)

            mock_open.assert_any_call(mock.sentinel.dev_name, 'rb')
            mock_get_dev_name.assert_any_call(self.connection_properties,
                                              expect=False)

    @mock.patch.object(rbd.WindowsRBDConnector, '_wait_for_volume')
    @mock.patch.object(rbd.WindowsRBDConnector, 'get_device_name')
    def test_connect_volume(self, mock_get_dev_name, mock_wait_vol):
        mock_get_dev_name.return_value = None
        mock_wait_vol.return_value = self.dev_name

        ret_val = self._conn.connect_volume(self.connection_properties)
        exp_ret_val = {
            'path': self.dev_name,
            'type': 'block'
        }
        self.assertEqual(exp_ret_val, ret_val)

        exp_exec_args = ['rbd', 'device', 'map', self.image_name]
        exp_exec_args += self._conn._get_rbd_args(self.connection_properties)
        self._execute.assert_any_call(*exp_exec_args)

        mock_wait_vol.assert_called_once_with(self.connection_properties)
        mock_get_dev_num = self._diskutils.get_device_number_from_device_name
        mock_get_dev_num.assert_called_once_with(self.dev_name)
        self._diskutils.set_disk_offline.assert_called_once_with(
            mock_get_dev_num.return_value)

    @ddt.data(True, False)
    @mock.patch.object(rbd.WindowsRBDConnector, 'get_device_name')
    def test_disconnect_volume(self, force, mock_get_dev_name):
        mock_get_dev_name.return_value = self.dev_name

        self._conn.disconnect_volume(self.connection_properties, force=force)

        exp_exec_args = ['rbd', 'device', 'unmap', self.image_name]
        exp_exec_args += self._conn._get_rbd_args(self.connection_properties)
        if force:
            exp_exec_args += ["-o", "hard-disconnect"]

        self._execute.assert_any_call(*exp_exec_args)
