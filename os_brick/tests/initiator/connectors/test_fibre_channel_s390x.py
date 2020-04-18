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
from unittest import mock

from os_brick.initiator.connectors import fibre_channel_s390x
from os_brick.initiator import linuxfc
from os_brick.tests.initiator import test_connector


class FibreChannelConnectorS390XTestCase(test_connector.ConnectorTestCase):

    def setUp(self):
        super(FibreChannelConnectorS390XTestCase, self).setUp()
        self.connector = fibre_channel_s390x.FibreChannelConnectorS390X(
            None, execute=self.fake_execute, use_multipath=False)
        self.assertIsNotNone(self.connector)
        self.assertIsNotNone(self.connector._linuxfc)
        self.assertEqual(self.connector._linuxfc.__class__.__name__,
                         "LinuxFibreChannelS390X")
        self.assertIsNotNone(self.connector._linuxscsi)

    @mock.patch.object(linuxfc.LinuxFibreChannelS390X, 'configure_scsi_device')
    def test_get_host_devices(self, mock_configure_scsi_device):
        possible_devs = [(3, 5, 2), ]
        devices = self.connector._get_host_devices(possible_devs)
        mock_configure_scsi_device.assert_called_with(3, 5,
                                                      "0x0002000000000000")
        self.assertEqual(3, len(devices))
        device_path = "/dev/disk/by-path/ccw-3-zfcp-5:0x0002000000000000"
        self.assertEqual(devices[0], device_path)
        device_path = "/dev/disk/by-path/ccw-3-fc-5-lun-2"
        self.assertEqual(devices[1], device_path)
        device_path = "/dev/disk/by-path/ccw-3-fc-5-lun-0x0002000000000000"
        self.assertEqual(devices[2], device_path)

    def test_get_lun_string(self):
        lun = 1
        lunstring = self.connector._get_lun_string(lun)
        self.assertEqual(lunstring, "0x0001000000000000")
        lun = 0xff
        lunstring = self.connector._get_lun_string(lun)
        self.assertEqual(lunstring, "0x00ff000000000000")
        lun = 0x101
        lunstring = self.connector._get_lun_string(lun)
        self.assertEqual(lunstring, "0x0101000000000000")
        lun = 0x4020400a
        lunstring = self.connector._get_lun_string(lun)
        self.assertEqual(lunstring, "0x4020400a00000000")

    @mock.patch.object(fibre_channel_s390x.FibreChannelConnectorS390X,
                       '_get_possible_devices', return_value=[(3, 5, 2), ])
    @mock.patch.object(linuxfc.LinuxFibreChannelS390X, 'get_fc_hbas_info',
                       return_value=[])
    @mock.patch.object(linuxfc.LinuxFibreChannelS390X,
                       'deconfigure_scsi_device')
    def test_remove_devices(self, mock_deconfigure_scsi_device,
                            mock_get_fc_hbas_info, mock_get_possible_devices):
        connection_properties = {'targets': [5, 2]}
        self.connector._remove_devices(connection_properties, devices=None,
                                       device_info=None)
        mock_deconfigure_scsi_device.assert_called_with(3, 5,
                                                        "0x0002000000000000")
        mock_get_fc_hbas_info.assert_called_once_with()
        mock_get_possible_devices.assert_called_once_with([], [5, 2])
