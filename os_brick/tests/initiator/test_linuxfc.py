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

import os.path
from unittest import mock


from os_brick.initiator import linuxfc
from os_brick.tests import base


class LinuxFCTestCase(base.TestCase):

    def setUp(self):
        super(LinuxFCTestCase, self).setUp()
        self.cmds = []

        self.mock_object(os.path, 'exists', return_value=True)
        self.mock_object(os.path, 'isdir', return_value=True)
        self.lfc = linuxfc.LinuxFibreChannel(None, execute=self.fake_execute)

    def fake_execute(self, *cmd, **kwargs):
        self.cmds.append(" ".join(cmd))
        return "", None

    @staticmethod
    def __get_rescan_info(zone_manager=False):

        connection_properties = {
            'initiator_target_map': {'50014380186af83c': ['514f0c50023f6c00'],
                                     '50014380186af83e': ['514f0c50023f6c01']},
            'initiator_target_lun_map': {
                '50014380186af83c': [('514f0c50023f6c00', 1)],
                '50014380186af83e': [('514f0c50023f6c01', 1)]
            },
            'target_discovered': False,
            'target_lun': 1,
            'target_wwn': ['514f0c50023f6c00', '514f0c50023f6c01'],
            'targets': [
                ('514f0c50023f6c00', 1),
                ('514f0c50023f6c01', 1),
            ]
        }

        hbas = [
            {'device_path': ('/sys/devices/pci0000:00/0000:00:02.0/'
                             '0000:04:00.0/host6/fc_host/host6'),
             'host_device': 'host6',
             'node_name': '50014380186af83d',
             'port_name': '50014380186af83c'},
            {'device_path': ('/sys/devices/pci0000:00/0000:00:02.0/'
                             '0000:04:00.1/host7/fc_host/host7'),
             'host_device': 'host7',
             'node_name': '50014380186af83f',
             'port_name': '50014380186af83e'},
        ]
        if not zone_manager:
            del connection_properties['initiator_target_map']
            del connection_properties['initiator_target_lun_map']
        return hbas, connection_properties

    def test__get_hba_channel_scsi_target_lun_single_wwpn(self):
        execute_results = ('/sys/class/fc_transport/target6:0:1/port_name\n',
                           '')
        hbas, con_props = self.__get_rescan_info()
        con_props['target_wwn'] = con_props['target_wwn'][0]
        con_props['targets'] = con_props['targets'][0:1]
        with mock.patch.object(self.lfc, '_execute',
                               return_value=execute_results) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            execute_mock.assert_called_once_with(
                'grep -Gil "514f0c50023f6c00" '
                '/sys/class/fc_transport/target6:*/port_name',
                shell=True)
        expected = ([['0', '1', 1]], set())
        self.assertEqual(expected, res)

    def test__get_hba_channel_scsi_target_lun_with_initiator_target_map(self):
        execute_results = ('/sys/class/fc_transport/target6:0:1/port_name\n',
                           '')
        hbas, con_props = self.__get_rescan_info(zone_manager=True)
        con_props['target_wwn'] = con_props['target_wwn'][0]
        con_props['targets'] = con_props['targets'][0:1]
        hbas[0]['port_name'] = '50014380186af83e'
        with mock.patch.object(self.lfc, '_execute',
                               return_value=execute_results) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            execute_mock.assert_called_once_with(
                'grep -Gil "514f0c50023f6c01" '
                '/sys/class/fc_transport/target6:*/port_name',
                shell=True)
        expected = ([['0', '1', 1]], set())
        self.assertEqual(expected, res)

    def test__get_hba_channel_scsi_target_lun_with_initiator_target_map_none(
            self):
        execute_results = ('/sys/class/fc_transport/target6:0:1/port_name\n',
                           '')
        hbas, con_props = self.__get_rescan_info()
        con_props['target_wwn'] = con_props['target_wwn'][0]
        con_props['targets'] = con_props['targets'][0:1]
        con_props['initiator_target_map'] = None
        hbas[0]['port_name'] = '50014380186af83e'
        with mock.patch.object(self.lfc, '_execute',
                               return_value=execute_results) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            execute_mock.assert_called_once_with(
                'grep -Gil "514f0c50023f6c00" '
                '/sys/class/fc_transport/target6:*/port_name',
                shell=True)
        expected = ([['0', '1', 1]], set())
        self.assertEqual(expected, res)

    def test__get_hba_channel_scsi_target_lun_multiple_wwpn(self):
        execute_results = [
            ['/sys/class/fc_transport/target6:0:1/port_name\n', ''],
            ['/sys/class/fc_transport/target6:0:2/port_name\n', ''],
        ]
        hbas, con_props = self.__get_rescan_info()
        with mock.patch.object(self.lfc, '_execute',
                               side_effect=execute_results) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            expected_cmds = [
                mock.call('grep -Gil "514f0c50023f6c00" '
                          '/sys/class/fc_transport/target6:*/port_name',
                          shell=True),
                mock.call('grep -Gil "514f0c50023f6c01" '
                          '/sys/class/fc_transport/target6:*/port_name',
                          shell=True),
            ]
            execute_mock.assert_has_calls(expected_cmds)

        expected = ([['0', '1', 1], ['0', '2', 1]], set())
        self.assertEqual(expected, res)

    def test__get_hba_channel_scsi_target_lun_multiple_wwpn_and_luns(self):
        execute_results = [
            ['/sys/class/fc_transport/target6:0:1/port_name\n', ''],
            ['/sys/class/fc_transport/target6:0:2/port_name\n', ''],
        ]
        hbas, con_props = self.__get_rescan_info()
        con_props['target_lun'] = [1, 7]
        con_props['targets'] = [
            ('514f0c50023f6c00', 1),
            ('514f0c50023f6c01', 7),
        ]
        with mock.patch.object(self.lfc, '_execute',
                               side_effect=execute_results) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            expected_cmds = [
                mock.call('grep -Gil "514f0c50023f6c00" '
                          '/sys/class/fc_transport/target6:*/port_name',
                          shell=True),
                mock.call('grep -Gil "514f0c50023f6c01" '
                          '/sys/class/fc_transport/target6:*/port_name',
                          shell=True),
            ]
            execute_mock.assert_has_calls(expected_cmds)

        expected = ([['0', '1', 1], ['0', '2', 7]], set())
        self.assertEqual(expected, res)

    def test__get_hba_channel_scsi_target_lun_zone_manager(self):
        execute_results = ('/sys/class/fc_transport/target6:0:1/port_name\n',
                           '')
        hbas, con_props = self.__get_rescan_info(zone_manager=True)
        with mock.patch.object(self.lfc, '_execute',
                               return_value=execute_results) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            execute_mock.assert_called_once_with(
                'grep -Gil "514f0c50023f6c00" '
                '/sys/class/fc_transport/target6:*/port_name',
                shell=True)
        expected = ([['0', '1', 1]], set())
        self.assertEqual(expected, res)

    def test__get_hba_channel_scsi_target_lun_not_found(self):
        hbas, con_props = self.__get_rescan_info(zone_manager=True)
        with mock.patch.object(self.lfc, '_execute',
                               return_value=('', '')) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            execute_mock.assert_called_once_with(
                'grep -Gil "514f0c50023f6c00" '
                '/sys/class/fc_transport/target6:*/port_name',
                shell=True)
        self.assertEqual(([], set()), res)

    def test__get_hba_channel_scsi_target_lun_exception(self):
        hbas, con_props = self.__get_rescan_info(zone_manager=True)
        with mock.patch.object(self.lfc, '_execute',
                               side_effect=Exception) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            execute_mock.assert_called_once_with(
                'grep -Gil "514f0c50023f6c00" '
                '/sys/class/fc_transport/target6:*/port_name',
                shell=True)
        self.assertEqual(([], {1}), res)

    def test__get_hba_channel_scsi_target_lun_some_exception(self):
        execute_effects = [
            ('/sys/class/fc_transport/target6:0:1/port_name\n', ''),
            Exception()
        ]
        expected_cmds = [
            mock.call('grep -Gil "514f0c50023f6c00" '
                      '/sys/class/fc_transport/target6:*/port_name',
                      shell=True),
            mock.call('grep -Gil "514f0c50023f6c01" '
                      '/sys/class/fc_transport/target6:*/port_name',
                      shell=True),
        ]
        hbas, con_props = self.__get_rescan_info()

        with mock.patch.object(self.lfc, '_execute',
                               side_effect=execute_effects) as execute_mock:
            res = self.lfc._get_hba_channel_scsi_target_lun(hbas[0], con_props)
            execute_mock.assert_has_calls(expected_cmds)
        expected = ([['0', '1', 1]], {1})
        self.assertEqual(expected, res)

    def test_rescan_hosts_initiator_map(self):
        """Test FC rescan with initiator map and not every HBA connected."""
        get_chan_results = [([['2', '3', 1], ['4', '5', 1]], set()),
                            ([['6', '7', 1]], set())]

        hbas, con_props = self.__get_rescan_info(zone_manager=True)

        # This HBA is not in the initiator map, so we should not scan it or try
        # to get the channel and target
        hbas.append({'device_path': ('/sys/devices/pci0000:00/0000:00:02.0/'
                                     '0000:04:00.2/host8/fc_host/host8'),
                     'host_device': 'host8',
                     'node_name': '50014380186af83g',
                     'port_name': '50014380186af83h'})

        with mock.patch.object(self.lfc, '_execute',
                               return_value=None) as execute_mock, \
            mock.patch.object(self.lfc, '_get_hba_channel_scsi_target_lun',
                              side_effect=get_chan_results) as mock_get_chan:

            self.lfc.rescan_hosts(hbas, con_props)
            expected_commands = [
                mock.call('tee', '-a', '/sys/class/scsi_host/host6/scan',
                          process_input='2 3 1',
                          root_helper=None, run_as_root=True),
                mock.call('tee', '-a', '/sys/class/scsi_host/host6/scan',
                          process_input='4 5 1',
                          root_helper=None, run_as_root=True),
                mock.call('tee', '-a', '/sys/class/scsi_host/host7/scan',
                          process_input='6 7 1',
                          root_helper=None, run_as_root=True)]

            execute_mock.assert_has_calls(expected_commands)
            self.assertEqual(len(expected_commands), execute_mock.call_count)

            expected_calls = [mock.call(hbas[0], con_props),
                              mock.call(hbas[1], con_props)]
            mock_get_chan.assert_has_calls(expected_calls)

    def test_rescan_hosts_single_wwnn(self):
        """Test FC rescan with no initiator map and single WWNN for ports."""
        get_chan_results = [
            [[['2', '3', 1], ['4', '5', 1]], set()],
            [[['6', '7', 1]], set()],
            [[], {1}],
        ]

        hbas, con_props = self.__get_rescan_info(zone_manager=False)

        # This HBA is the one that is not included in the single WWNN.
        hbas.append({'device_path': ('/sys/devices/pci0000:00/0000:00:02.0/'
                                     '0000:04:00.2/host8/fc_host/host8'),
                     'host_device': 'host8',
                     'node_name': '50014380186af83g',
                     'port_name': '50014380186af83h'})

        with mock.patch.object(self.lfc, '_execute',
                               return_value=None) as execute_mock, \
            mock.patch.object(self.lfc, '_get_hba_channel_scsi_target_lun',
                              side_effect=get_chan_results) as mock_get_chan:

            self.lfc.rescan_hosts(hbas, con_props)
            expected_commands = [
                mock.call('tee', '-a', '/sys/class/scsi_host/host6/scan',
                          process_input='2 3 1',
                          root_helper=None, run_as_root=True),
                mock.call('tee', '-a', '/sys/class/scsi_host/host6/scan',
                          process_input='4 5 1',
                          root_helper=None, run_as_root=True),
                mock.call('tee', '-a', '/sys/class/scsi_host/host7/scan',
                          process_input='6 7 1',
                          root_helper=None, run_as_root=True)]

            execute_mock.assert_has_calls(expected_commands)
            self.assertEqual(len(expected_commands), execute_mock.call_count)

            expected_calls = [mock.call(hbas[0], con_props),
                              mock.call(hbas[1], con_props)]
            mock_get_chan.assert_has_calls(expected_calls)

    def test_rescan_hosts_initiator_map_single_wwnn(self):
        """Test FC rescan with initiator map and single WWNN."""
        get_chan_results = [([['2', '3', 1], ['4', '5', 1]], set()),
                            ([], {1})]

        hbas, con_props = self.__get_rescan_info(zone_manager=True)

        with mock.patch.object(self.lfc, '_execute',
                               return_value=None) as execute_mock, \
            mock.patch.object(self.lfc, '_get_hba_channel_scsi_target_lun',
                              side_effect=get_chan_results) as mock_get_chan:

            self.lfc.rescan_hosts(hbas, con_props)
            expected_commands = [
                mock.call('tee', '-a', '/sys/class/scsi_host/host6/scan',
                          process_input='2 3 1',
                          root_helper=None, run_as_root=True),
                mock.call('tee', '-a', '/sys/class/scsi_host/host6/scan',
                          process_input='4 5 1',
                          root_helper=None, run_as_root=True)]

            execute_mock.assert_has_calls(expected_commands)
            self.assertEqual(len(expected_commands), execute_mock.call_count)

            expected_calls = [mock.call(hbas[0], con_props),
                              mock.call(hbas[1], con_props)]
            mock_get_chan.assert_has_calls(expected_calls)

    def test_rescan_hosts_port_not_found(self):
        """Test when we don't find the target ports."""
        get_chan_results = [([], {1}), ([], {1})]
        hbas, con_props = self.__get_rescan_info(zone_manager=True)
        # Remove the initiator map
        con_props.pop('initiator_target_map')
        con_props.pop('initiator_target_lun_map')
        with mock.patch.object(self.lfc, '_get_hba_channel_scsi_target_lun',
                               side_effect=get_chan_results), \
            mock.patch.object(self.lfc, '_execute',
                              side_effect=None) as execute_mock:

            self.lfc.rescan_hosts(hbas, con_props)

            expected_commands = [
                mock.call('tee', '-a', '/sys/class/scsi_host/host6/scan',
                          process_input='- - 1',
                          root_helper=None, run_as_root=True),
                mock.call('tee', '-a', '/sys/class/scsi_host/host7/scan',
                          process_input='- - 1',
                          root_helper=None, run_as_root=True)]
            execute_mock.assert_has_calls(expected_commands)
            self.assertEqual(len(expected_commands), execute_mock.call_count)

    def test_rescan_hosts_port_not_found_driver_disables_wildcards(self):
        """Test when we don't find the target ports but driver forces scan."""
        get_chan_results = [([], {1}), ([], {1})]
        hbas, con_props = self.__get_rescan_info(zone_manager=True)
        con_props['enable_wildcard_scan'] = False
        with mock.patch.object(self.lfc, '_get_hba_channel_scsi_target_lun',
                               side_effect=get_chan_results), \
            mock.patch.object(self.lfc, '_execute',
                              side_effect=None) as execute_mock:

            self.lfc.rescan_hosts(hbas, con_props)
            execute_mock.assert_not_called()

    @mock.patch('glob.glob', return_value=[])
    def test_get_fc_hbas_no_hbas(self, mock_glob):
        hbas = self.lfc.get_fc_hbas()
        self.assertListEqual([], hbas)
        mock_glob.assert_called_once_with('/sys/class/fc_host/*')

    @mock.patch('os.path.realpath')
    @mock.patch('glob.glob', return_value=['/sys/class/fc_host/host0',
                                           '/sys/class/fc_host/host2'])
    @mock.patch('builtins.open', side_effect=IOError)
    def test_get_fc_hbas_fail(self, mock_open, mock_glob, mock_path):
        hbas = self.lfc.get_fc_hbas()
        mock_glob.assert_called_once_with('/sys/class/fc_host/*')
        self.assertListEqual([], hbas)
        self.assertEqual(2, mock_open.call_count)
        mock_open.assert_has_calls(
            (mock.call('/sys/class/fc_host/host0/port_name', 'rt'),
             mock.call('/sys/class/fc_host/host2/port_name', 'rt'))
        )
        self.assertEqual(2, mock_path.call_count)
        mock_path.assert_has_calls(
            (mock.call('/sys/class/fc_host/host0'),
             mock.call('/sys/class/fc_host/host2'))
        )

    @mock.patch('os.path.realpath')
    @mock.patch('glob.glob', return_value=['/sys/class/fc_host/host0',
                                           '/sys/class/fc_host/host2'])
    @mock.patch('builtins.open')
    def test_get_fc_hbas(self, mock_open, mock_glob, mock_path):
        mock_open.return_value.__enter__.return_value.read.side_effect = [
            '0x50014380242b9750\n', '0x50014380242b9751\n', 'Online',
            '0x50014380242b9752\n', '0x50014380242b9753\n', 'Online',
        ]
        pci_path = '/sys/devices/pci0000:20/0000:20:03.0/0000:21:00.'
        host0_pci = f'{pci_path}0/host0/fc_host/host0'
        host2_pci = f'{pci_path}1/host2/fc_host/host2'
        mock_path.side_effect = [host0_pci, host2_pci]

        hbas = self.lfc.get_fc_hbas()

        expected = [
            {'ClassDevice': 'host0',
             'ClassDevicepath': host0_pci,
             'port_name': '0x50014380242b9750',
             'node_name': '0x50014380242b9751',
             'port_state': 'Online'},
            {'ClassDevice': 'host2',
             'ClassDevicepath': host2_pci,
             'port_name': '0x50014380242b9752',
             'node_name': '0x50014380242b9753',
             'port_state': 'Online'},
        ]
        self.assertListEqual(expected, hbas)
        mock_glob.assert_called_once_with('/sys/class/fc_host/*')
        self.assertEqual(6, mock_open.call_count)
        mock_open.assert_has_calls(
            (mock.call('/sys/class/fc_host/host0/port_name', 'rt'),
             mock.call('/sys/class/fc_host/host0/node_name', 'rt'),
             mock.call('/sys/class/fc_host/host0/port_state', 'rt'),
             mock.call('/sys/class/fc_host/host2/port_name', 'rt'),
             mock.call('/sys/class/fc_host/host2/node_name', 'rt'),
             mock.call('/sys/class/fc_host/host2/port_state', 'rt')),
            any_order=True,
        )
        self.assertEqual(2, mock_path.call_count)
        mock_path.assert_has_calls(
            (mock.call('/sys/class/fc_host/host0'),
             mock.call('/sys/class/fc_host/host2'))
        )

    def _set_get_fc_hbas(self):
        pci_path = '/sys/devices/pci0000:20/0000:20:03.0/0000:21:00.'
        host0_pci = f'{pci_path}0/host0/fc_host/host0'
        host2_pci = f'{pci_path}1/host2/fc_host/host2'
        return_value = [{'ClassDevice': 'host0',
                         'ClassDevicepath': host0_pci,
                         'port_name': '0x50014380242b9750',
                         'node_name': '0x50014380242b9751',
                         'port_state': 'Online'},
                        {'ClassDevice': 'host2',
                         'ClassDevicepath': host2_pci,
                         'port_name': '0x50014380242b9752',
                         'node_name': '0x50014380242b9753',
                         'port_state': 'Online'}]
        mocked = self.mock_object(linuxfc.LinuxFibreChannel, 'get_fc_hbas',
                                  return_value=return_value)
        return mocked

    def test_get_fc_hbas_info(self):
        mock_hbas = self._set_get_fc_hbas()
        hbas_info = self.lfc.get_fc_hbas_info()
        expected_info = [{'device_path': '/sys/devices/pci0000:20/'
                                         '0000:20:03.0/0000:21:00.0/'
                                         'host0/fc_host/host0',
                          'host_device': 'host0',
                          'node_name': '50014380242b9751',
                          'port_name': '50014380242b9750'},
                         {'device_path': '/sys/devices/pci0000:20/'
                                         '0000:20:03.0/0000:21:00.1/'
                                         'host2/fc_host/host2',
                          'host_device': 'host2',
                          'node_name': '50014380242b9753',
                          'port_name': '50014380242b9752'}, ]
        self.assertListEqual(expected_info, hbas_info)
        mock_hbas.assert_called_once_with()

    def test_get_fc_wwpns(self):
        self._set_get_fc_hbas()
        wwpns = self.lfc.get_fc_wwpns()
        expected_wwpns = ['50014380242b9750', '50014380242b9752']
        self.assertEqual(expected_wwpns, wwpns)

    def test_get_fc_wwnns(self):
        self._set_get_fc_hbas()
        wwnns = self.lfc.get_fc_wwnns()
        expected_wwnns = ['50014380242b9751', '50014380242b9753']
        self.assertEqual(expected_wwnns, wwnns)


class LinuxFCS390XTestCase(LinuxFCTestCase):

    def setUp(self):
        super(LinuxFCS390XTestCase, self).setUp()
        self.cmds = []
        self.lfc = linuxfc.LinuxFibreChannelS390X(None,
                                                  execute=self.fake_execute)

    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    def test_get_fc_hbas_info(self, mock_hbas):
        host_pci = '/sys/devices/css0/0.0.02ea/0.0.3080/host0/fc_host/host0'
        mock_hbas.return_value = [{'ClassDevice': 'host0',
                                   'ClassDevicepath': host_pci,
                                   'port_name': '0xc05076ffe680a960',
                                   'node_name': '0x1234567898765432',
                                   'port_state': 'Online'}]
        hbas_info = self.lfc.get_fc_hbas_info()
        expected = [{'device_path': '/sys/devices/css0/0.0.02ea/'
                                    '0.0.3080/host0/fc_host/host0',
                     'host_device': 'host0',
                     'node_name': '1234567898765432',
                     'port_name': 'c05076ffe680a960'}]
        self.assertEqual(expected, hbas_info)

    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_configure_scsi_device(self, mock_execute):
        device_number = "0.0.2319"
        target_wwn = "0x50014380242b9751"
        lun = 1
        self.lfc.configure_scsi_device(device_number, target_wwn, lun)
        expected_commands = [('tee -a /sys/bus/ccw/drivers/zfcp/0.0.2319/'
                             'port_rescan'),
                             ('tee -a /sys/bus/ccw/drivers/zfcp/0.0.2319/'
                                 '0x50014380242b9751/unit_add')]
        self.assertEqual(expected_commands, self.cmds)

    def test_deconfigure_scsi_device(self):
        device_number = "0.0.2319"
        target_wwn = "0x50014380242b9751"
        lun = 1
        self.lfc.deconfigure_scsi_device(device_number, target_wwn, lun)
        expected_commands = [('tee -a /sys/bus/ccw/drivers/zfcp/'
                              '0.0.2319/0x50014380242b9751/unit_remove')]
        self.assertEqual(expected_commands, self.cmds)
