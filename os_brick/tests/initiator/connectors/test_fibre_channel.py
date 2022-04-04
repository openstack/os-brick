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
from unittest import mock

import ddt

from os_brick import exception
from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import fibre_channel
from os_brick.initiator import linuxfc
from os_brick.initiator import linuxscsi
from os_brick.tests.initiator import test_connector


@ddt.ddt
class FibreChannelConnectorTestCase(test_connector.ConnectorTestCase):

    def setUp(self):
        super(FibreChannelConnectorTestCase, self).setUp()
        self.connector = fibre_channel.FibreChannelConnector(
            None, execute=self.fake_execute, use_multipath=False)
        self.assertIsNotNone(self.connector)
        self.assertIsNotNone(self.connector._linuxfc)
        self.assertIsNotNone(self.connector._linuxscsi)

    def fake_get_fc_hbas(self):
        return [{'ClassDevice': 'host1',
                 'ClassDevicePath': '/sys/devices/pci0000:00/0000:00:03.0'
                                    '/0000:05:00.2/host1/fc_host/host1',
                 'dev_loss_tmo': '30',
                 'fabric_name': '0x1000000533f55566',
                 'issue_lip': '<store method only>',
                 'max_npiv_vports': '255',
                 'maxframe_size': '2048 bytes',
                 'node_name': '0x200010604b019419',
                 'npiv_vports_inuse': '0',
                 'port_id': '0x680409',
                 'port_name': '0x100010604b019419',
                 'port_state': 'Online',
                 'port_type': 'NPort (fabric via point-to-point)',
                 'speed': '10 Gbit',
                 'supported_classes': 'Class 3',
                 'supported_speeds': '10 Gbit',
                 'symbolic_name': 'Emulex 554M FV4.0.493.0 DV8.3.27',
                 'tgtid_bind_type': 'wwpn (World Wide Port Name)',
                 'uevent': None,
                 'vport_create': '<store method only>',
                 'vport_delete': '<store method only>'}]

    def fake_get_fc_hbas_with_platform(self):
        return [{'ClassDevice': 'host1',
                 'ClassDevicePath': '/sys/devices/platform/smb'
                                    '/smb:motherboard/80040000000.peu0-c0'
                                    '/pci0000:00/0000:00:03.0'
                                    '/0000:05:00.2/host1/fc_host/host1',
                 'dev_loss_tmo': '30',
                 'fabric_name': '0x1000000533f55566',
                 'issue_lip': '<store method only>',
                 'max_npiv_vports': '255',
                 'maxframe_size': '2048 bytes',
                 'node_name': '0x200010604b019419',
                 'npiv_vports_inuse': '0',
                 'port_id': '0x680409',
                 'port_name': '0x100010604b019419',
                 'port_state': 'Online',
                 'port_type': 'NPort (fabric via point-to-point)',
                 'speed': '10 Gbit',
                 'supported_classes': 'Class 3',
                 'supported_speeds': '10 Gbit',
                 'symbolic_name': 'Emulex 554M FV4.0.493.0 DV8.3.27',
                 'tgtid_bind_type': 'wwpn (World Wide Port Name)',
                 'uevent': None,
                 'vport_create': '<store method only>',
                 'vport_delete': '<store method only>'}]

    def fake_get_fc_hbas_info(self):
        hbas = self.fake_get_fc_hbas()
        info = [{'port_name': hbas[0]['port_name'].replace('0x', ''),
                 'node_name': hbas[0]['node_name'].replace('0x', ''),
                 'host_device': hbas[0]['ClassDevice'],
                 'device_path': hbas[0]['ClassDevicePath']}]
        return info

    def fake_get_fc_hbas_info_with_platform(self):
        hbas = self.fake_get_fc_hbas_with_platform()
        info = [{'port_name': hbas[0]['port_name'].replace('0x', ''),
                 'node_name': hbas[0]['node_name'].replace('0x', ''),
                 'host_device': hbas[0]['ClassDevice'],
                 'device_path': hbas[0]['ClassDevicePath']}]
        return info

    def fibrechan_connection(self, volume, location, wwn, lun=1):
        return {'driver_volume_type': 'fibrechan',
                'data': {
                    'volume_id': volume['id'],
                    'target_portal': location,
                    'target_wwn': wwn,
                    'target_lun': lun,
                }}

    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    def test_get_connector_properties(self, mock_hbas):
        mock_hbas.return_value = self.fake_get_fc_hbas()
        multipath = True
        enforce_multipath = True
        props = fibre_channel.FibreChannelConnector.get_connector_properties(
            'sudo', multipath=multipath,
            enforce_multipath=enforce_multipath)

        hbas = self.fake_get_fc_hbas()
        expected_props = {'wwpns': [hbas[0]['port_name'].replace('0x', '')],
                          'wwnns': [hbas[0]['node_name'].replace('0x', '')]}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        search_path = self.connector.get_search_path()
        expected = "/dev/disk/by-path"
        self.assertEqual(expected, search_path)

    def test_get_pci_num(self):
        hba = {'device_path': "/sys/devices/pci0000:00/0000:00:03.0"
                              "/0000:05:00.3/host2/fc_host/host2"}
        platform, pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:05:00.3", pci_num)
        self.assertIsNone(platform)

        hba = {'device_path': "/sys/devices/pci0000:00/0000:00:03.0"
                              "/0000:05:00.3/0000:06:00.6/host2/fc_host/host2"}
        platform, pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:06:00.6", pci_num)
        self.assertIsNone(platform)

        hba = {'device_path': "/sys/devices/pci0000:20/0000:20:03.0"
                              "/0000:21:00.2/net/ens2f2/ctlr_2/host3"
                              "/fc_host/host3"}
        platform, pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:21:00.2", pci_num)
        self.assertIsNone(platform)

    def test_get_pci_num_with_platform(self):
        hba = {'device_path': "/sys/devices/platform/smb/smb:motherboard/"
                              "80040000000.peu0-c0/pci0000:00/0000:00:03.0"
                              "/0000:05:00.3/host2/fc_host/host2"}
        platform, pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:05:00.3", pci_num)
        self.assertEqual("platform-80040000000.peu0-c0", platform)

        hba = {'device_path': "/sys/devices/platform/smb/smb:motherboard"
                              "/80040000000.peu0-c0/pci0000:00/0000:00:03.0"
                              "/0000:05:00.3/0000:06:00.6/host2/fc_host/host2"}
        platform, pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:06:00.6", pci_num)
        self.assertEqual("platform-80040000000.peu0-c0", platform)

        hba = {'device_path': "/sys/devices/platform/smb"
                              "/smb:motherboard/80040000000.peu0-c0/pci0000:20"
                              "/0000:20:03.0/0000:21:00.2"
                              "/net/ens2f2/ctlr_2/host3/fc_host/host3"}
        platform, pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:21:00.2", pci_num)
        self.assertEqual("platform-80040000000.peu0-c0", platform)

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    def test_get_volume_paths(self, fake_fc_hbas_info,
                              fake_fc_hbas, fake_exists):
        fake_fc_hbas.side_effect = self.fake_get_fc_hbas
        fake_fc_hbas_info.side_effect = self.fake_get_fc_hbas_info

        name = 'volume-00000001'
        vol = {'id': 1, 'name': name}
        location = '10.0.2.15:3260'
        wwn = '1234567890123456'
        connection_info = self.fibrechan_connection(vol, location, wwn)
        conn_data = self.connector._add_targets_to_connection_properties(
            connection_info['data']
        )
        volume_paths = self.connector.get_volume_paths(conn_data)

        expected = ['/dev/disk/by-path/pci-0000:05:00.2'
                    '-fc-0x1234567890123456-lun-1']
        self.assertEqual(expected, volume_paths)

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    def test_get_volume_paths_with_platform(self, fake_fc_hbas_info,
                                            fake_fc_hbas, fake_exists):
        fake_fc_hbas.side_effect = self.fake_get_fc_hbas_with_platform
        fake_fc_hbas_info.side_effect \
            = self.fake_get_fc_hbas_info_with_platform

        name = 'volume-00000001'
        vol = {'id': 1, 'name': name}
        location = '10.0.2.15:3260'
        wwn = '1234567890123456'
        connection_info = self.fibrechan_connection(vol, location, wwn)
        conn_data = self.connector._add_targets_to_connection_properties(
            connection_info['data']
        )
        volume_paths = self.connector.get_volume_paths(conn_data)

        expected = ['/dev/disk/by-path'
                    '/platform-80040000000.peu0-c0-pci-0000:05:00.2'
                    '-fc-0x1234567890123456-lun-1']
        self.assertEqual(expected, volume_paths)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    @mock.patch.object(base.BaseLinuxConnector, 'check_valid_device')
    def test_connect_volume(self, check_valid_device_mock,
                            get_device_info_mock,
                            get_scsi_wwn_mock,
                            remove_device_mock,
                            get_fc_hbas_info_mock,
                            get_fc_hbas_mock,
                            realpath_mock,
                            exists_mock,
                            wait_for_rw_mock):
        check_valid_device_mock.return_value = True
        get_fc_hbas_mock.side_effect = self.fake_get_fc_hbas
        get_fc_hbas_info_mock.side_effect = self.fake_get_fc_hbas_info

        wwn = '1234567890'
        multipath_devname = '/dev/md-1'
        devices = {"device": multipath_devname,
                   "id": wwn,
                   "devices": [{'device': '/dev/sdb',
                                'address': '1:0:0:1',
                                'host': 1, 'channel': 0,
                                'id': 0, 'lun': 1}]}
        get_device_info_mock.return_value = devices['devices'][0]
        get_scsi_wwn_mock.return_value = wwn

        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        vol = {'id': 1, 'name': name}
        # Should work for string, unicode, and list
        wwns_luns = [
            ('1234567890123456', 1),
            (str('1234567890123456'), 1),
            (['1234567890123456', '1234567890123457'], 1),
            (['1234567890123456', '1234567890123457'], 1),
        ]
        for wwn, lun in wwns_luns:
            connection_info = self.fibrechan_connection(vol, location,
                                                        wwn, lun)
            dev_info = self.connector.connect_volume(connection_info['data'])
            exp_wwn = wwn[0] if isinstance(wwn, list) else wwn
            dev_str = ('/dev/disk/by-path/pci-0000:05:00.2-fc-0x%s-lun-1' %
                       exp_wwn)
            self.assertEqual(dev_info['type'], 'block')
            self.assertEqual(dev_info['path'], dev_str)
            self.assertNotIn('multipath_id', dev_info)
            self.assertNotIn('devices', dev_info)

            self.connector.disconnect_volume(connection_info['data'], dev_info)
            expected_commands = []
            self.assertEqual(expected_commands, self.cmds)

        # Should not work for anything other than string, unicode, and list
        connection_info = self.fibrechan_connection(vol, location, 123)
        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector.connect_volume,
                          connection_info['data'])

        get_fc_hbas_mock.side_effect = [[]]
        get_fc_hbas_info_mock.side_effect = [[]]
        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector.connect_volume,
                          connection_info['data'])

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    def _test_connect_volume_multipath(self, get_device_info_mock,
                                       get_scsi_wwn_mock,
                                       get_fc_hbas_info_mock,
                                       get_fc_hbas_mock,
                                       realpath_mock,
                                       exists_mock,
                                       wait_for_rw_mock,
                                       find_mp_dev_mock,
                                       access_mode,
                                       should_wait_for_rw,
                                       find_mp_device_path_mock):
        self.connector.use_multipath = True
        get_fc_hbas_mock.side_effect = self.fake_get_fc_hbas
        get_fc_hbas_info_mock.side_effect = self.fake_get_fc_hbas_info

        wwn = '1234567890'
        multipath_devname = '/dev/md-1'
        devices = {"device": multipath_devname,
                   "id": wwn,
                   "devices": [{'device': '/dev/sdb',
                                'address': '1:0:0:1',
                                'host': 1, 'channel': 0,
                                'id': 0, 'lun': 1},
                               {'device': '/dev/sdc',
                                'address': '1:0:0:2',
                                'host': 1, 'channel': 0,
                                'id': 0, 'lun': 1}]}
        get_device_info_mock.side_effect = devices['devices']
        get_scsi_wwn_mock.return_value = wwn

        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        vol = {'id': 1, 'name': name}
        initiator_wwn = ['1234567890123456', '1234567890123457']

        find_mp_device_path_mock.return_value = '/dev/mapper/mpatha'
        find_mp_dev_mock.return_value = {"device": "dm-3",
                                         "id": wwn,
                                         "name": "mpatha"}

        connection_info = self.fibrechan_connection(vol, location,
                                                    initiator_wwn)
        connection_info['data']['access_mode'] = access_mode

        self.connector.connect_volume(connection_info['data'])

        self.assertEqual(should_wait_for_rw, wait_for_rw_mock.called)

        self.connector.disconnect_volume(connection_info['data'],
                                         devices['devices'][0])
        expected_commands = [
            'multipath -f ' + find_mp_device_path_mock.return_value,
            'tee -a /sys/block/sdb/device/delete',
            'tee -a /sys/block/sdc/device/delete',
        ]
        self.assertEqual(expected_commands, self.cmds)
        return connection_info

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    @mock.patch.object(base.BaseLinuxConnector, 'check_valid_device')
    def test_connect_volume_multipath_rw(self, check_valid_device_mock,
                                         get_device_info_mock,
                                         get_scsi_wwn_mock,
                                         get_fc_hbas_info_mock,
                                         get_fc_hbas_mock,
                                         realpath_mock,
                                         exists_mock,
                                         wait_for_rw_mock,
                                         find_mp_dev_mock):

        check_valid_device_mock.return_value = True
        self._test_connect_volume_multipath(get_device_info_mock,
                                            get_scsi_wwn_mock,
                                            get_fc_hbas_info_mock,
                                            get_fc_hbas_mock,
                                            realpath_mock,
                                            exists_mock,
                                            wait_for_rw_mock,
                                            find_mp_dev_mock,
                                            'rw',
                                            True)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    @mock.patch.object(base.BaseLinuxConnector, 'check_valid_device')
    def test_connect_volume_multipath_no_access_mode(self,
                                                     check_valid_device_mock,
                                                     get_device_info_mock,
                                                     get_scsi_wwn_mock,
                                                     get_fc_hbas_info_mock,
                                                     get_fc_hbas_mock,
                                                     realpath_mock,
                                                     exists_mock,
                                                     wait_for_rw_mock,
                                                     find_mp_dev_mock):

        check_valid_device_mock.return_value = True
        self._test_connect_volume_multipath(get_device_info_mock,
                                            get_scsi_wwn_mock,
                                            get_fc_hbas_info_mock,
                                            get_fc_hbas_mock,
                                            realpath_mock,
                                            exists_mock,
                                            wait_for_rw_mock,
                                            find_mp_dev_mock,
                                            None,
                                            True)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    @mock.patch.object(base.BaseLinuxConnector, 'check_valid_device')
    def test_connect_volume_multipath_ro(self, check_valid_device_mock,
                                         get_device_info_mock,
                                         get_scsi_wwn_mock,
                                         get_fc_hbas_info_mock,
                                         get_fc_hbas_mock,
                                         realpath_mock,
                                         exists_mock,
                                         wait_for_rw_mock,
                                         find_mp_dev_mock):

        check_valid_device_mock.return_value = True
        self._test_connect_volume_multipath(get_device_info_mock,
                                            get_scsi_wwn_mock,
                                            get_fc_hbas_info_mock,
                                            get_fc_hbas_mock,
                                            realpath_mock,
                                            exists_mock,
                                            wait_for_rw_mock,
                                            find_mp_dev_mock,
                                            'ro',
                                            False)

    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    @mock.patch.object(base.BaseLinuxConnector, 'check_valid_device')
    def test_connect_volume_multipath_not_found(self,
                                                check_valid_device_mock,
                                                get_device_info_mock,
                                                get_scsi_wwn_mock,
                                                get_fc_hbas_info_mock,
                                                get_fc_hbas_mock,
                                                realpath_mock,
                                                exists_mock,
                                                wait_for_rw_mock,
                                                find_mp_dev_mock,
                                                discover_mp_dev_mock):
        check_valid_device_mock.return_value = True
        discover_mp_dev_mock.return_value = ("/dev/disk/by-path/something",
                                             None)

        connection_info = self._test_connect_volume_multipath(
            get_device_info_mock, get_scsi_wwn_mock, get_fc_hbas_info_mock,
            get_fc_hbas_mock, realpath_mock, exists_mock, wait_for_rw_mock,
            find_mp_dev_mock, 'rw', False)

        self.assertNotIn('multipathd_id', connection_info['data'])
        # Ensure we don't call it with the real path
        device_name = discover_mp_dev_mock.call_args[0][-1]
        self.assertNotEqual(realpath_mock.return_value, device_name)

    @mock.patch.object(fibre_channel.FibreChannelConnector, 'get_volume_paths')
    def test_extend_volume_no_path(self, mock_volume_paths):
        mock_volume_paths.return_value = []
        volume = {'id': 'fake_uuid'}
        wwn = '1234567890123456'
        connection_info = self.fibrechan_connection(volume,
                                                    "10.0.2.15:3260",
                                                    wwn)

        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector.extend_volume,
                          connection_info['data'])

    @mock.patch.object(linuxscsi.LinuxSCSI, 'extend_volume')
    @mock.patch.object(fibre_channel.FibreChannelConnector, 'get_volume_paths')
    def test_extend_volume(self, mock_volume_paths, mock_scsi_extend):
        fake_new_size = 1024
        mock_volume_paths.return_value = ['/dev/vdx']
        mock_scsi_extend.return_value = fake_new_size
        volume = {'id': 'fake_uuid'}
        wwn = '1234567890123456'
        connection_info = self.fibrechan_connection(volume,
                                                    "10.0.2.15:3260",
                                                    wwn)
        new_size = self.connector.extend_volume(connection_info['data'])
        self.assertEqual(fake_new_size, new_size)

    @mock.patch.object(os.path, 'isdir')
    def test_get_all_available_volumes_path_not_dir(self, mock_isdir):
        mock_isdir.return_value = False
        expected = []
        actual = self.connector.get_all_available_volumes()
        self.assertCountEqual(expected, actual)

    @mock.patch('eventlet.greenthread.sleep', mock.Mock())
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    @mock.patch.object(base.BaseLinuxConnector, 'check_valid_device')
    def test_connect_volume_device_not_valid(self, check_valid_device_mock,
                                             get_device_info_mock,
                                             get_scsi_wwn_mock,
                                             get_fc_hbas_info_mock,
                                             get_fc_hbas_mock,
                                             realpath_mock,
                                             exists_mock,
                                             wait_for_rw_mock,
                                             find_mp_dev_mock):

        check_valid_device_mock.return_value = False
        self.assertRaises(exception.NoFibreChannelVolumeDeviceFound,
                          self._test_connect_volume_multipath,
                          get_device_info_mock,
                          get_scsi_wwn_mock,
                          get_fc_hbas_info_mock,
                          get_fc_hbas_mock,
                          realpath_mock,
                          exists_mock,
                          wait_for_rw_mock,
                          find_mp_dev_mock,
                          'rw',
                          True)

    @ddt.data(
        {
            "target_info": {
                "target_lun": 1,
                "target_wwn": '1234567890123456',
            },
            "expected_targets": [
                ('1234567890123456', 1)
            ]
        },
        {
            "target_info": {
                "target_lun": 1,
                "target_wwn": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 1),
            ]
        },
        {
            "target_info": {
                "target_luns": [1, 1],
                "target_wwn": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 1),
            ]
        },
        {
            "target_info": {
                "target_luns": [1, 2],
                "target_wwn": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 2),
            ]
        },
        {
            "target_info": {
                "target_luns": [1, 1],
                "target_wwns": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 1),
            ]
        },
        {
            "target_info": {
                "target_lun": 7,
                "target_luns": [1, 1],
                "target_wwn": 'foo',
                "target_wwns": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 1),
            ]
        },
        # Add the zone map in now
        {
            "target_info": {
                "target_lun": 1,
                "target_wwn": '1234567890123456',
            },
            "expected_targets": [
                ('1234567890123456', 1)
            ],
            "itmap": {
                '0004567890123456': ['1234567890123456']
            },
            "expected_map": {
                '0004567890123456': [('1234567890123456', 1)]
            }
        },
        {
            "target_info": {
                "target_lun": 1,
                "target_wwn": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 1),
            ],
            "itmap": {
                '0004567890123456': ['1234567890123456',
                                     '1234567890123457']
            },
            "expected_map": {
                '0004567890123456': [('1234567890123456', 1),
                                     ('1234567890123457', 1)]
            }
        },
        {
            "target_info": {
                "target_luns": [1, 2],
                "target_wwn": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 2),
            ],
            "itmap": {
                '0004567890123456': ['1234567890123456'],
                '1004567890123456': ['1234567890123457'],
            },
            "expected_map": {
                '0004567890123456': [('1234567890123456', 1)],
                '1004567890123456': [('1234567890123457', 2)],
            }
        },
        {
            "target_info": {
                "target_luns": [1, 2],
                "target_wwn": ['1234567890123456', '1234567890123457'],
            },
            "expected_targets": [
                ('1234567890123456', 1),
                ('1234567890123457', 2),
            ],
            "itmap": {
                '0004567890123456': ['1234567890123456',
                                     '1234567890123457']
            },
            "expected_map": {
                '0004567890123456': [('1234567890123456', 1),
                                     ('1234567890123457', 2)]
            }
        },
        {
            "target_info": {
                "target_lun": 1,
                "target_wwn": ['20320002AC01E166', '21420002AC01E166',
                               '20410002AC01E166', '21410002AC01E166']
            },
            "expected_targets": [
                ('20320002ac01e166', 1),
                ('21420002ac01e166', 1),
                ('20410002ac01e166', 1),
                ('21410002ac01e166', 1)
            ],
            "itmap": {
                '10001409DCD71FF6': ['20320002AC01E166', '21420002AC01E166'],
                '10001409DCD71FF7': ['20410002AC01E166', '21410002AC01E166']
            },
            "expected_map": {
                '10001409dcd71ff6': [('20320002ac01e166', 1),
                                     ('21420002ac01e166', 1)],
                '10001409dcd71ff7': [('20410002ac01e166', 1),
                                     ('21410002ac01e166', 1)]
            }
        },
    )
    @ddt.unpack
    def test__add_targets_to_connection_properties(self, target_info,
                                                   expected_targets,
                                                   itmap=None,
                                                   expected_map=None):
        volume = {'id': 'fake_uuid'}
        wwn = '1234567890123456'
        conn = self.fibrechan_connection(volume, "10.0.2.15:3260", wwn)
        conn['data'].update(target_info)

        conn['data']['initiator_target_map'] = itmap

        connection_info = self.connector._add_targets_to_connection_properties(
            conn['data'])
        self.assertIn('targets', connection_info)
        self.assertEqual(expected_targets, connection_info['targets'])

        # Check that we turn to lowercase target wwns
        key = 'target_wwns' if 'target_wwns' in target_info else 'target_wwn'
        wwns = target_info.get(key)
        wwns = [wwns] if isinstance(wwns, str) else wwns
        wwns = [w.lower() for w in wwns]
        if wwns:
            self.assertEqual(wwns, conn['data'][key])

        if itmap:
            self.assertIn('initiator_target_lun_map', connection_info)
            self.assertEqual(expected_map,
                             connection_info['initiator_target_lun_map'])

    @ddt.data(('/dev/mapper/<WWN>', True),
              ('/dev/mapper/mpath0', True),
              # Check real devices are properly detected as non multipaths
              ('/dev/sda', False),
              ('/dev/disk/by-path/pci-1-fc-1-lun-1', False))
    @ddt.unpack
    @mock.patch('os_brick.initiator.linuxscsi.LinuxSCSI.remove_scsi_device')
    @mock.patch('os_brick.initiator.linuxscsi.LinuxSCSI.requires_flush')
    @mock.patch('os_brick.utils.get_dev_path')
    def test__remove_devices(self, path_used, was_multipath, get_dev_path_mock,
                             flush_mock, remove_mock):
        get_dev_path_mock.return_value = path_used
        self.connector._remove_devices(mock.sentinel.con_props,
                                       [{'device': '/dev/sda'}],
                                       mock.sentinel.device_info)
        get_dev_path_mock.assert_called_once_with(mock.sentinel.con_props,
                                                  mock.sentinel.device_info)
        flush_mock.assert_called_once_with('/dev/sda', path_used,
                                           was_multipath)
        remove_mock.assert_called_once_with('/dev/sda',
                                            flush=flush_mock.return_value)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    @mock.patch.object(base.BaseLinuxConnector, 'check_valid_device')
    def test_disconnect_volume(self, check_valid_device_mock,
                               find_mp_device_path_mock,
                               get_device_info_mock,
                               get_scsi_wwn_mock,
                               get_fc_hbas_info_mock,
                               get_fc_hbas_mock,
                               realpath_mock,
                               exists_mock,
                               wait_for_rw_mock,
                               find_mp_dev_mock):

        check_valid_device_mock.return_value = True
        self.connector.use_multipath = True
        get_fc_hbas_mock.side_effect = self.fake_get_fc_hbas
        get_fc_hbas_info_mock.side_effect = self.fake_get_fc_hbas_info

        wwn = '1234567890'
        multipath_devname = '/dev/md-1'
        devices = {"device": multipath_devname,
                   "id": wwn,
                   "devices": [{'device': '/dev/sdb',
                                'address': '1:0:0:1',
                                'host': 1, 'channel': 0,
                                'id': 0, 'lun': 1},
                               {'device': '/dev/sdc',
                                'address': '1:0:0:2',
                                'host': 1, 'channel': 0,
                                'id': 0, 'lun': 1}]}
        get_device_info_mock.side_effect = devices['devices']
        get_scsi_wwn_mock.return_value = wwn

        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        vol = {'id': 1, 'name': name}
        initiator_wwn = ['1234567890123456', '1234567890123457']

        find_mp_device_path_mock.return_value = '/dev/mapper/mpatha'
        find_mp_dev_mock.return_value = {"device": "dm-3",
                                         "id": wwn,
                                         "name": "mpatha"}

        connection_info = self.fibrechan_connection(vol, location,
                                                    initiator_wwn)
        self.connector.disconnect_volume(connection_info['data'],
                                         devices['devices'][0])
        expected_commands = [
            'multipath -f ' + find_mp_device_path_mock.return_value,
            'tee -a /sys/block/sdb/device/delete',
            'tee -a /sys/block/sdc/device/delete',
        ]
        self.assertEqual(expected_commands, self.cmds)
