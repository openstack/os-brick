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
import collections
import os
from unittest import mock

import ddt
from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator.connectors import iscsi
from os_brick.initiator import linuxscsi
from os_brick.initiator import utils
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests.initiator import test_connector


@ddt.ddt
class ISCSIConnectorTestCase(test_connector.ConnectorTestCase):
    SINGLE_CON_PROPS = {'volume_id': 'vol_id',
                        'target_portal': 'ip1:port1',
                        'target_iqn': 'tgt1',
                        'encryption': False,
                        'target_lun': '1'}
    CON_PROPS = {
        'volume_id': 'vol_id',
        'target_portal': 'ip1:port1',
        'target_iqn': 'tgt1',
        'target_lun': 4,
        'target_portals': ['ip1:port1', 'ip2:port2', 'ip3:port3',
                           'ip4:port4'],
        'target_iqns': ['tgt1', 'tgt2', 'tgt3', 'tgt4'],
        'target_luns': [4, 5, 6, 7],
    }

    def setUp(self):
        super(ISCSIConnectorTestCase, self).setUp()
        self.connector = iscsi.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=False)

        self.connector_with_multipath = iscsi.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=True)
        self.mock_object(self.connector._linuxscsi, 'get_name_from_path',
                         return_value="/dev/sdb")
        self._fake_iqn = 'iqn.1234-56.foo.bar:01:23456789abc'
        self._name = 'volume-00000001'
        self._iqn = 'iqn.2010-10.org.openstack:%s' % self._name
        self._location = '10.0.2.15:3260'
        self._lun = 1

    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsi_session')
    def test_get_iscsi_sessions_full(self, sessions_mock):
        iscsiadm_result = ('tcp: [session1] ip1:port1,1 tgt1 (non-flash)\n'
                           'tcp: [session2] ip2:port2,-1 tgt2 (non-flash)\n'
                           'tcp: [session3] ip3:port3,1 tgt3\n')
        sessions_mock.return_value = (iscsiadm_result, '')
        res = self.connector._get_iscsi_sessions_full()
        expected = [('tcp:', 'session1', 'ip1:port1', '1', 'tgt1'),
                    ('tcp:', 'session2', 'ip2:port2', '-1', 'tgt2'),
                    ('tcp:', 'session3', 'ip3:port3', '1', 'tgt3')]
        self.assertListEqual(expected, res)

    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsi_session')
    def test_get_iscsi_sessions_full_stderr(self, sessions_mock):
        iscsiadm_result = ('tcp: [session1] ip1:port1,1 tgt1 (non-flash)\n'
                           'tcp: [session2] ip2:port2,-1 tgt2 (non-flash)\n'
                           'tcp: [session3] ip3:port3,1 tgt3\n')
        sessions_mock.return_value = (iscsiadm_result, 'error')
        res = self.connector._get_iscsi_sessions_full()
        expected = [('tcp:', 'session1', 'ip1:port1', '1', 'tgt1'),
                    ('tcp:', 'session2', 'ip2:port2', '-1', 'tgt2'),
                    ('tcp:', 'session3', 'ip3:port3', '1', 'tgt3')]
        self.assertListEqual(expected, res)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    def test_get_iscsi_sessions(self, sessions_mock):
        sessions_mock.return_value = [
            ('tcp:', 'session1', 'ip1:port1', '1', 'tgt1'),
            ('tcp:', 'session2', 'ip2:port2', '-1', 'tgt2'),
            ('tcp:', 'session3', 'ip3:port3', '1', 'tgt3')]
        res = self.connector._get_iscsi_sessions()
        expected = ['ip1:port1', 'ip2:port2', 'ip3:port3']
        self.assertListEqual(expected, res)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full',
                       return_value=[])
    def test_get_iscsi_sessions_no_sessions(self, sessions_mock):
        res = self.connector._get_iscsi_sessions()
        self.assertListEqual([], res)
        sessions_mock.assert_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_execute')
    def test_get_iscsi_nodes(self, exec_mock):
        iscsiadm_result = ('ip1:port1,1 tgt1\nip2:port2,-1 tgt2\n'
                           'ip3:port3,1 tgt3\n')
        exec_mock.return_value = (iscsiadm_result, '')
        res = self.connector._get_iscsi_nodes()
        expected = [('ip1:port1', 'tgt1'), ('ip2:port2', 'tgt2'),
                    ('ip3:port3', 'tgt3')]
        self.assertListEqual(expected, res)
        exec_mock.assert_called_once_with(
            'iscsiadm', '-m', 'node', run_as_root=True,
            root_helper=self.connector._root_helper, check_exit_code=False)

    @mock.patch.object(iscsi.ISCSIConnector, '_execute')
    def test_get_iscsi_nodes_error(self, exec_mock):
        exec_mock.return_value = (None, 'error')
        res = self.connector._get_iscsi_nodes()
        self.assertEqual([], res)

    @mock.patch.object(iscsi.ISCSIConnector, '_execute')
    def test_get_iscsi_nodes_corrupt(self, exec_mock):
        iscsiadm_result = ('ip1:port1,-1 tgt1\n'
                           'ip2:port2,-1 tgt2\n'
                           '[]:port3,-1\n'
                           'ip4:port4,-1 tgt4\n')
        exec_mock.return_value = (iscsiadm_result, '')
        res = self.connector._get_iscsi_nodes()
        expected = [('ip1:port1', 'tgt1'), ('ip2:port2', 'tgt2'),
                    ('ip4:port4', 'tgt4')]
        self.assertListEqual(expected, res)
        exec_mock.assert_called_once_with(
            'iscsiadm', '-m', 'node', run_as_root=True,
            root_helper=self.connector._root_helper, check_exit_code=False)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_ips_iqns_luns')
    @mock.patch('glob.glob')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_nodes')
    def test_get_connection_devices(self, nodes_mock, sessions_mock,
                                    glob_mock, iql_mock):
        iql_mock.return_value = self.connector._get_all_targets(self.CON_PROPS)

        # List sessions from other targets and non tcp sessions
        sessions_mock.return_value = [
            ('non-tcp:', '0', 'ip1:port1', '1', 'tgt1'),
            ('tcp:', '1', 'ip1:port1', '1', 'tgt1'),
            ('tcp:', '2', 'ip2:port2', '-1', 'tgt2'),
            ('tcp:', '3', 'ip1:port1', '1', 'tgt4'),
            ('tcp:', '4', 'ip2:port2', '-1', 'tgt5')]
        # List 1 node without sessions
        nodes_mock.return_value = [('ip1:port1', 'tgt1'),
                                   ('ip2:port2', 'tgt2'),
                                   ('ip3:port3', 'tgt3')]
        sys_cls = '/sys/class/scsi_host/host'
        glob_mock.side_effect = [
            [sys_cls + '1/device/session1/target6/1:2:6:4/block/sda',
             sys_cls + '1/device/session1/target6/1:2:6:4/block/sda1'],
            [sys_cls + '2/device/session2/target7/2:2:7:5/block/sdb',
             sys_cls + '2/device/session2/target7/2:2:7:4/block/sdc'],
        ]
        res = self.connector._get_connection_devices(self.CON_PROPS)
        expected = {('ip1:port1', 'tgt1'): ({'sda'}, set()),
                    ('ip2:port2', 'tgt2'): ({'sdb'}, {'sdc'}),
                    ('ip3:port3', 'tgt3'): (set(), set())}
        self.assertDictEqual(expected, res)
        iql_mock.assert_called_once_with(self.CON_PROPS, discover=False,
                                         is_disconnect_call=False)

    @mock.patch('glob.glob')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_nodes')
    def test_get_connection_devices_with_iqns(self, nodes_mock, sessions_mock,
                                              glob_mock):
        ips_iqns_luns = self.connector._get_all_targets(self.CON_PROPS)

        # List sessions from other targets and non tcp sessions
        sessions_mock.return_value = [
            ('non-tcp:', '0', 'ip1:port1', '1', 'tgt1'),
            ('tcp:', '1', 'ip1:port1', '1', 'tgt1'),
            ('tcp:', '2', 'ip2:port2', '-1', 'tgt2'),
            ('tcp:', '3', 'ip1:port1', '1', 'tgt4'),
            ('tcp:', '4', 'ip2:port2', '-1', 'tgt5')]
        # List 1 node without sessions
        nodes_mock.return_value = [('ip1:port1', 'tgt1'),
                                   ('ip2:port2', 'tgt2'),
                                   ('ip3:port3', 'tgt3')]
        sys_cls = '/sys/class/scsi_host/host'
        glob_mock.side_effect = [
            [sys_cls + '1/device/session1/target6/1:2:6:4/block/sda',
             sys_cls + '1/device/session1/target6/1:2:6:4/block/sda1'],
            [sys_cls + '2/device/session2/target7/2:2:7:5/block/sdb',
             sys_cls + '2/device/session2/target7/2:2:7:4/block/sdc'],
        ]
        with mock.patch.object(iscsi.ISCSIConnector,
                               '_get_all_targets') as get_targets_mock:
            res = self.connector._get_connection_devices(mock.sentinel.props,
                                                         ips_iqns_luns)
        expected = {('ip1:port1', 'tgt1'): ({'sda'}, set()),
                    ('ip2:port2', 'tgt2'): ({'sdb'}, {'sdc'}),
                    ('ip3:port3', 'tgt3'): (set(), set())}
        self.assertDictEqual(expected, res)
        get_targets_mock.assert_not_called()

    def generate_device(self, location, iqn, transport=None, lun=1):
        dev_format = "ip-%s-iscsi-%s-lun-%s" % (location, iqn, lun)
        if transport:
            dev_format = "pci-0000:00:00.0-" + dev_format
        fake_dev_path = "/dev/disk/by-path/" + dev_format
        return fake_dev_path

    def iscsi_connection(self, volume, location, iqn):
        return {
            'driver_volume_type': 'iscsi',
            'data': {
                'volume_id': volume['id'],
                'target_portal': location,
                'target_iqn': iqn,
                'target_lun': 1,
            }
        }

    def iscsi_connection_multipath(self, volume, locations, iqns, luns):
        return {
            'driver_volume_type': 'iscsi',
            'data': {
                'volume_id': volume['id'],
                'target_portals': locations,
                'target_iqns': iqns,
                'target_luns': luns,
            }
        }

    def iscsi_connection_chap(self, volume, location, iqn, auth_method,
                              auth_username, auth_password,
                              discovery_auth_method, discovery_auth_username,
                              discovery_auth_password):
        return {
            'driver_volume_type': 'iscsi',
            'data': {
                'auth_method': auth_method,
                'auth_username': auth_username,
                'auth_password': auth_password,
                'discovery_auth_method': discovery_auth_method,
                'discovery_auth_username': discovery_auth_username,
                'discovery_auth_password': discovery_auth_password,
                'target_lun': 1,
                'volume_id': volume['id'],
                'target_iqn': iqn,
                'target_portal': location,
            }
        }

    def _initiator_get_text(self, *arg, **kwargs):
        text = ('## DO NOT EDIT OR REMOVE THIS FILE!\n'
                '## If you remove this file, the iSCSI daemon '
                'will not start.\n'
                '## If you change the InitiatorName, existing '
                'access control lists\n'
                '## may reject this initiator.  The InitiatorName must '
                'be unique\n'
                '## for each iSCSI initiator.  Do NOT duplicate iSCSI '
                'InitiatorNames.\n'
                'InitiatorName=%s' % self._fake_iqn)
        return text, None

    def test_get_initiator(self):
        def initiator_no_file(*args, **kwargs):
            raise putils.ProcessExecutionError('No file')

        self.connector._execute = initiator_no_file
        initiator = self.connector.get_initiator()
        self.assertIsNone(initiator)
        self.connector._execute = self._initiator_get_text
        initiator = self.connector.get_initiator()
        self.assertEqual(initiator, self._fake_iqn)

    def test_get_connector_properties(self):
        with mock.patch.object(priv_rootwrap, 'execute') as mock_exec:
            mock_exec.return_value = self._initiator_get_text()
            multipath = True
            enforce_multipath = True
            props = iscsi.ISCSIConnector.get_connector_properties(
                'sudo', multipath=multipath,
                enforce_multipath=enforce_multipath)

            expected_props = {'initiator': self._fake_iqn}
            self.assertEqual(expected_props, props)

    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm_bare')
    def test_brick_iscsi_validate_transport(self, mock_iscsiadm):
        sample_output = ('# BEGIN RECORD 2.0-872\n'
                         'iface.iscsi_ifacename = %s.fake_suffix\n'
                         'iface.net_ifacename = <empty>\n'
                         'iface.ipaddress = <empty>\n'
                         'iface.hwaddress = 00:53:00:00:53:00\n'
                         'iface.transport_name = %s\n'
                         'iface.initiatorname = <empty>\n'
                         '# END RECORD')
        for tport in self.connector.supported_transports:
            mock_iscsiadm.return_value = (sample_output % (tport, tport), '')
            self.assertEqual(tport + '.fake_suffix',
                             self.connector._validate_iface_transport(
                                 tport + '.fake_suffix'))

        mock_iscsiadm.return_value = ("", 'iscsiadm: Could not '
                                      'read iface fake_transport (6)')
        self.assertEqual('default',
                         self.connector._validate_iface_transport(
                             'fake_transport'))

    def test_get_search_path(self):
        search_path = self.connector.get_search_path()
        expected = "/dev/disk/by-path"
        self.assertEqual(expected, search_path)

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(iscsi.ISCSIConnector, '_get_potential_volume_paths')
    def test_get_volume_paths(self, mock_potential_paths, mock_exists):
        name1 = 'volume-00000001-1'
        vol = {'id': 1, 'name': name1}
        location = '10.0.2.15:3260'
        iqn = 'iqn.2010-10.org.openstack:%s' % name1

        fake_path = ("/dev/disk/by-path/ip-%(ip)s-iscsi-%(iqn)s-lun-%(lun)s" %
                     {'ip': '10.0.2.15', 'iqn': iqn, 'lun': 1})
        fake_devices = [fake_path]
        expected = fake_devices
        mock_potential_paths.return_value = fake_devices

        connection_properties = self.iscsi_connection(vol, [location],
                                                      [iqn])
        volume_paths = self.connector.get_volume_paths(
            connection_properties['data'])
        self.assertEqual(expected, volume_paths)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    def test_discover_mpath_device(self, mock_multipath_device,
                                   mock_multipath_device_path):
        location1 = '10.0.2.15:3260'
        location2 = '[2001:db8::1]:3260'
        name1 = 'volume-00000001-1'
        name2 = 'volume-00000001-2'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        fake_multipath_dev = '/dev/mapper/fake-multipath-dev'
        fake_raw_dev = '/dev/disk/by-path/fake-raw-lun'
        vol = {'id': 1, 'name': name1}
        connection_properties = self.iscsi_connection_multipath(
            vol, [location1, location2], [iqn1, iqn2], [1, 2])
        mock_multipath_device_path.return_value = fake_multipath_dev
        mock_multipath_device.return_value = test_connector.FAKE_SCSI_WWN
        (result_path, result_mpath_id) = (
            self.connector_with_multipath._discover_mpath_device(
                test_connector.FAKE_SCSI_WWN,
                connection_properties['data'],
                fake_raw_dev))
        result = {'path': result_path, 'multipath_id': result_mpath_id}
        expected_result = {'path': fake_multipath_dev,
                           'multipath_id': test_connector.FAKE_SCSI_WWN}
        self.assertEqual(expected_result, result)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(os.path, 'realpath')
    def test_discover_mpath_device_by_realpath(self, mock_realpath,
                                               mock_multipath_device,
                                               mock_multipath_device_path):

        FAKE_SCSI_WWN = '1234567890'
        location1 = '10.0.2.15:3260'
        location2 = '[2001:db8::1]:3260'
        name1 = 'volume-00000001-1'
        name2 = 'volume-00000001-2'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        fake_multipath_dev = None
        fake_raw_dev = '/dev/disk/by-path/fake-raw-lun'
        vol = {'id': 1, 'name': name1}
        connection_properties = self.iscsi_connection_multipath(
            vol, [location1, location2], [iqn1, iqn2], [1, 2])
        mock_multipath_device_path.return_value = fake_multipath_dev
        mock_multipath_device.return_value = {
            'device': '/dev/mapper/%s' % FAKE_SCSI_WWN}
        mock_realpath.return_value = '/dev/sdvc'
        (result_path, result_mpath_id) = (
            self.connector_with_multipath._discover_mpath_device(
                FAKE_SCSI_WWN,
                connection_properties['data'],
                fake_raw_dev))
        mock_multipath_device.assert_called_with('/dev/sdvc')
        result = {'path': result_path, 'multipath_id': result_mpath_id}
        expected_result = {'path': '/dev/mapper/%s' % FAKE_SCSI_WWN,
                           'multipath_id': FAKE_SCSI_WWN}
        self.assertEqual(expected_result, result)

    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_multipath_volume')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_single_volume')
    def test_connect_volume_mp(self, con_single_mock, con_mp_mock, clean_mock):
        self.connector.use_multipath = True
        res = self.connector.connect_volume(self.CON_PROPS)
        self.assertEqual(con_mp_mock.return_value, res)
        con_single_mock.assert_not_called()
        con_mp_mock.assert_called_once_with(self.CON_PROPS)
        clean_mock.assert_not_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_multipath_volume')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_single_volume')
    def test_connect_volume_mp_failure(self, con_single_mock, con_mp_mock,
                                       clean_mock):
        self.connector.use_multipath = True
        con_mp_mock.side_effect = exception.BrickException
        self.assertRaises(exception.BrickException,
                          self.connector.connect_volume, self.CON_PROPS)
        con_single_mock.assert_not_called()
        con_mp_mock.assert_called_once_with(self.CON_PROPS)
        clean_mock.assert_called_once_with(self.CON_PROPS, force=True)

    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_multipath_volume')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_single_volume')
    def test_connect_volume_sp(self, con_single_mock, con_mp_mock, clean_mock):
        self.connector.use_multipath = False
        res = self.connector.connect_volume(self.CON_PROPS)
        self.assertEqual(con_single_mock.return_value, res)
        con_mp_mock.assert_not_called()
        con_single_mock.assert_called_once_with(self.CON_PROPS)
        clean_mock.assert_not_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_multipath_volume')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_single_volume')
    def test_connect_volume_sp_failure(self, con_single_mock, con_mp_mock,
                                       clean_mock):
        self.connector.use_multipath = False
        con_single_mock.side_effect = exception.BrickException
        self.assertRaises(exception.BrickException,
                          self.connector.connect_volume, self.CON_PROPS)
        con_mp_mock.assert_not_called()
        con_single_mock.assert_called_once_with(self.CON_PROPS)
        clean_mock.assert_called_once_with(self.CON_PROPS, force=True)

    def test_discover_iscsi_portals(self):
        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        vol = {'id': 1, 'name': name}
        auth_method = 'CHAP'
        auth_username = 'fake_chap_username'
        auth_password = 'fake_chap_password'
        discovery_auth_method = 'CHAP'
        discovery_auth_username = 'fake_chap_username'
        discovery_auth_password = 'fake_chap_password'
        connection_properties = self.iscsi_connection_chap(
            vol, location, iqn, auth_method, auth_username, auth_password,
            discovery_auth_method, discovery_auth_username,
            discovery_auth_password)
        self.connector_with_multipath = iscsi.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=True)

        for transport in ['default', 'iser', 'badTransport']:
            interface = 'iser' if transport == 'iser' else 'default'
            self.mock_object(self.connector_with_multipath, '_get_transport',
                             mock.Mock(return_value=interface))

            self.connector_with_multipath._discover_iscsi_portals(
                connection_properties['data'])

            expected_cmds = [
                'iscsiadm -m discoverydb -t sendtargets -I %(iface)s '
                '-p %(location)s --op update '
                '-n discovery.sendtargets.auth.authmethod -v %(auth_method)s '
                '-n discovery.sendtargets.auth.username -v %(username)s '
                '-n discovery.sendtargets.auth.password -v %(password)s' %
                {'iface': interface, 'location': location,
                 'auth_method': discovery_auth_method,
                 'username': discovery_auth_username,
                 'password': discovery_auth_password},
                'iscsiadm -m node --op show -p %s' % location,
                'iscsiadm -m discoverydb -t sendtargets -I %(iface)s'
                ' -p %(location)s --discover' % {'iface': interface,
                                                 'location': location},
                'iscsiadm -m node --op show -p %s' % location]
            self.assertEqual(expected_cmds, self.cmds)
            # Reset to run with a different transport type
            self.cmds = list()

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_run_iscsiadm_update_discoverydb')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_iscsi_portals_with_chap_discovery(
            self, exists, update_discoverydb):
        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        vol = {'id': 1, 'name': name}
        auth_method = 'CHAP'
        auth_username = 'fake_chap_username'
        auth_password = 'fake_chap_password'
        discovery_auth_method = 'CHAP'
        discovery_auth_username = 'fake_chap_username'
        discovery_auth_password = 'fake_chap_password'
        connection_properties = self.iscsi_connection_chap(
            vol, location, iqn, auth_method, auth_username, auth_password,
            discovery_auth_method, discovery_auth_username,
            discovery_auth_password)
        self.connector_with_multipath = iscsi.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=True)
        self.cmds = []
        # The first call returns an error code = 6, mocking an empty
        # discovery db. The second one mocks a successful return and the
        # third one a dummy exit code, which will trigger the
        # TargetPortalNotFound exception in connect_volume
        update_discoverydb.side_effect = [
            putils.ProcessExecutionError(None, None, 6),
            ("", ""),
            putils.ProcessExecutionError(None, None, 9)]

        self.connector_with_multipath._discover_iscsi_portals(
            connection_properties['data'])
        update_discoverydb.assert_called_with(connection_properties['data'])

        expected_cmds = [
            'iscsiadm -m discoverydb -t sendtargets -p %s -I default'
            ' --op new' % location,
            'iscsiadm -m node --op show -p %s' % location,
            'iscsiadm -m discoverydb -t sendtargets -I default -p %s'
            ' --discover' % location,
            'iscsiadm -m node --op show -p %s' % location]
        self.assertEqual(expected_cmds, self.cmds)

        self.assertRaises(exception.TargetPortalNotFound,
                          self.connector_with_multipath.connect_volume,
                          connection_properties['data'])

    def test_get_target_portals_from_iscsiadm_output(self):
        connector = self.connector
        test_output = '''10.15.84.19:3260,1 iqn.1992-08.com.netapp:sn.33615311
                         10.15.85.19:3260,2 iqn.1992-08.com.netapp:sn.33615311
                         '''
        res = connector._get_target_portals_from_iscsiadm_output(test_output)
        ips = ['10.15.84.19:3260', '10.15.85.19:3260']
        iqns = ['iqn.1992-08.com.netapp:sn.33615311',
                'iqn.1992-08.com.netapp:sn.33615311']
        expected = (ips, iqns)
        self.assertEqual(expected, res)

    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    def test_disconnect_volume(self, cleanup_mock):
        res = self.connector.disconnect_volume(mock.sentinel.con_props,
                                               mock.sentinel.dev_info,
                                               mock.sentinel.Force,
                                               mock.sentinel.ignore_errors)
        self.assertEqual(cleanup_mock.return_value, res)
        cleanup_mock.assert_called_once_with(
            mock.sentinel.con_props,
            force=mock.sentinel.Force,
            ignore_errors=mock.sentinel.ignore_errors,
            device_info=mock.sentinel.dev_info,
            is_disconnect_call=True)

    @ddt.data(True, False)
    @mock.patch.object(iscsi.ISCSIConnector, '_get_transport')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm_bare')
    def test_get_discoverydb_portals(self, is_iser, iscsiadm_mock,
                                     transport_mock):
        params = {
            'iqn1': self.SINGLE_CON_PROPS['target_iqn'],
            'iqn2': 'iqn.2004-04.com.qnap:ts-831x:iscsi.cinder-2017.9ef',
            'addr': self.SINGLE_CON_PROPS['target_portal'].replace(':', ','),
            'ip1': self.SINGLE_CON_PROPS['target_portal'],
            'ip2': '192.168.1.3:3260',
            'transport': 'iser' if is_iser else 'default',
            'other_transport': 'default' if is_iser else 'iser',
        }

        iscsiadm_mock.return_value = (
            'SENDTARGETS:\n'
            'DiscoveryAddress: 192.168.1.33,3260\n'
            'DiscoveryAddress: %(addr)s\n'
            'Target: %(iqn1)s\n'
            '	Portal: %(ip2)s,1\n'
            '		Iface Name: %(transport)s\n'
            '	Portal: %(ip1)s,1\n'
            '		Iface Name: %(transport)s\n'
            '	Portal: %(ip1)s,1\n'
            '		Iface Name: %(other_transport)s\n'
            'Target: %(iqn2)s\n'
            '	Portal: %(ip2)s,1\n'
            '		Iface Name: %(transport)s\n'
            '	Portal: %(ip1)s,1\n'
            '		Iface Name: %(transport)s\n'
            'DiscoveryAddress: 192.168.1.38,3260\n'
            'iSNS:\n'
            'No targets found.\n'
            'STATIC:\n'
            'No targets found.\n'
            'FIRMWARE:\n'
            'No targets found.\n' % params, None)
        transport_mock.return_value = 'iser' if is_iser else 'non-iser'

        res = self.connector._get_discoverydb_portals(self.SINGLE_CON_PROPS)
        expected = [(params['ip2'], params['iqn1'],
                     self.SINGLE_CON_PROPS['target_lun']),
                    (params['ip1'], params['iqn1'],
                     self.SINGLE_CON_PROPS['target_lun']),
                    (params['ip2'], params['iqn2'],
                     self.SINGLE_CON_PROPS['target_lun']),
                    (params['ip1'], params['iqn2'],
                     self.SINGLE_CON_PROPS['target_lun'])]
        self.assertListEqual(expected, res)
        iscsiadm_mock.assert_called_once_with(
            ['-m', 'discoverydb', '-o', 'show', '-P', 1])
        transport_mock.assert_called_once_with()

    @mock.patch.object(iscsi.ISCSIConnector, '_get_transport', return_value='')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm_bare')
    def test_get_discoverydb_portals_error(self, iscsiadm_mock,
                                           transport_mock):
        """DiscoveryAddress is not present."""
        iscsiadm_mock.return_value = (
            'SENDTARGETS:\n'
            'DiscoveryAddress: 192.168.1.33,3260\n'
            'DiscoveryAddress: 192.168.1.38,3260\n'
            'iSNS:\n'
            'No targets found.\n'
            'STATIC:\n'
            'No targets found.\n'
            'FIRMWARE:\n'
            'No targets found.\n', None)

        self.assertRaises(exception.TargetPortalsNotFound,
                          self.connector._get_discoverydb_portals,
                          self.SINGLE_CON_PROPS)
        iscsiadm_mock.assert_called_once_with(
            ['-m', 'discoverydb', '-o', 'show', '-P', 1])
        transport_mock.assert_not_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_get_transport', return_value='')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm_bare')
    def test_get_discoverydb_portals_error_is_present(self, iscsiadm_mock,
                                                      transport_mock):
        """DiscoveryAddress is present but wrong iterface."""
        params = {
            'iqn': self.SINGLE_CON_PROPS['target_iqn'],
            'addr': self.SINGLE_CON_PROPS['target_portal'].replace(':', ','),
            'ip': self.SINGLE_CON_PROPS['target_portal'],
        }
        iscsiadm_mock.return_value = (
            'SENDTARGETS:\n'
            'DiscoveryAddress: 192.168.1.33,3260\n'
            'DiscoveryAddress: %(addr)s\n'
            'Target: %(iqn)s\n'
            '	Portal: %(ip)s,1\n'
            '		Iface Name: iser\n'
            'DiscoveryAddress: 192.168.1.38,3260\n'
            'iSNS:\n'
            'No targets found.\n'
            'STATIC:\n'
            'No targets found.\n'
            'FIRMWARE:\n'
            'No targets found.\n' % params, None)

        self.assertRaises(exception.TargetPortalsNotFound,
                          self.connector._get_discoverydb_portals,
                          self.SINGLE_CON_PROPS)
        iscsiadm_mock.assert_called_once_with(
            ['-m', 'discoverydb', '-o', 'show', '-P', 1])
        transport_mock.assert_called_once_with()

    @ddt.data(('/dev/sda', False),
              ('/dev/disk/by-id/scsi-WWID', False),
              ('/dev/dm-11', True),
              ('/dev/disk/by-id/dm-uuid-mpath-MPATH', True))
    @ddt.unpack
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_dev_path')
    @mock.patch.object(iscsi.ISCSIConnector, '_disconnect_connection')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_connection_devices')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_connection',
                       return_value=None)
    def test_cleanup_connection(self, path_used, was_multipath, remove_mock,
                                flush_mock, con_devs_mock, discon_mock,
                                get_dev_path_mock):
        get_dev_path_mock.return_value = path_used
        # Return an ordered dicts instead of normal dict for discon_mock.assert
        con_devs_mock.return_value = collections.OrderedDict((
            (('ip1:port1', 'tgt1'), ({'sda'}, set())),
            (('ip2:port2', 'tgt2'), ({'sdb'}, {'sdc'})),
            (('ip3:port3', 'tgt3'), (set(), set()))))

        self.connector._cleanup_connection(
            self.CON_PROPS, ips_iqns_luns=mock.sentinel.ips_iqns_luns,
            force=False, ignore_errors=False,
            device_info=mock.sentinel.device_info)

        get_dev_path_mock.called_once_with(self.CON_PROPS,
                                           mock.sentinel.device_info)
        con_devs_mock.assert_called_once_with(self.CON_PROPS,
                                              mock.sentinel.ips_iqns_luns,
                                              False)
        remove_mock.assert_called_once_with({'sda', 'sdb'}, False, mock.ANY,
                                            path_used, was_multipath)
        discon_mock.assert_called_once_with(
            self.CON_PROPS,
            [('ip1:port1', 'tgt1'), ('ip3:port3', 'tgt3')],
            False, mock.ANY)
        flush_mock.assert_not_called()

    @mock.patch('os_brick.exception.ExceptionChainer.__nonzero__',
                mock.Mock(return_value=True))
    @mock.patch('os_brick.exception.ExceptionChainer.__bool__',
                mock.Mock(return_value=True))
    @mock.patch.object(iscsi.ISCSIConnector, '_disconnect_connection')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_connection_devices')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_connection',
                       return_value=mock.sentinel.mp_name)
    def test_cleanup_connection_force_failure(self, remove_mock, flush_mock,
                                              con_devs_mock, discon_mock):

        # Return an ordered dicts instead of normal dict for discon_mock.assert
        con_devs_mock.return_value = collections.OrderedDict((
            (('ip1:port1', 'tgt1'), ({'sda'}, set())),
            (('ip2:port2', 'tgt2'), ({'sdb'}, {'sdc'})),
            (('ip3:port3', 'tgt3'), (set(), set()))))

        self.assertRaises(exception.ExceptionChainer,
                          self.connector._cleanup_connection,
                          self.CON_PROPS,
                          ips_iqns_luns=mock.sentinel.ips_iqns_luns,
                          force=mock.sentinel.force, ignore_errors=False)

        con_devs_mock.assert_called_once_with(self.CON_PROPS,
                                              mock.sentinel.ips_iqns_luns,
                                              False)
        remove_mock.assert_called_once_with({'sda', 'sdb'},
                                            mock.sentinel.force, mock.ANY,
                                            '', False)
        discon_mock.assert_called_once_with(
            self.CON_PROPS,
            [('ip1:port1', 'tgt1'), ('ip3:port3', 'tgt3')],
            mock.sentinel.force, mock.ANY)
        flush_mock.assert_called_once_with(mock.sentinel.mp_name)

    def test_cleanup_connection_no_data_discoverydb(self):
        self.connector.use_multipath = True
        with mock.patch.object(self.connector, '_get_discoverydb_portals',
                               side_effect=exception.TargetPortalsNotFound), \
                mock.patch.object(self.connector._linuxscsi,
                                  'remove_connection') as mock_remove:
            # This will not raise and exception
            self.connector._cleanup_connection(self.SINGLE_CON_PROPS)
            mock_remove.assert_not_called()

    @ddt.data({'do_raise': False, 'force': False},
              {'do_raise': True, 'force': True},
              {'do_raise': True, 'force': False})
    @ddt.unpack
    @mock.patch.object(iscsi.ISCSIConnector, '_disconnect_from_iscsi_portal')
    def test_disconnect_connection(self, disconnect_mock, do_raise, force):
        will_raise = do_raise and not force
        actual_call_args = []

        # Since we reuse the copied dictionary on _disconnect_connection
        # changing its values we cannot use mock's assert_has_calls
        def my_disconnect(con_props):
            actual_call_args.append(con_props.copy())
            if do_raise:
                raise exception.ExceptionChainer()

        disconnect_mock.side_effect = my_disconnect

        connections = (('ip1:port1', 'tgt1'), ('ip2:port2', 'tgt2'))
        original_props = self.CON_PROPS.copy()
        exc = exception.ExceptionChainer()
        if will_raise:
            self.assertRaises(exception.ExceptionChainer,
                              self.connector._disconnect_connection,
                              self.CON_PROPS, connections,
                              force=force, exc=exc)
        else:
            self.connector._disconnect_connection(self.CON_PROPS, connections,
                                                  force=force, exc=exc)

        # Passed properties should not be altered by the method call
        self.assertDictEqual(original_props, self.CON_PROPS)
        expected = [original_props.copy(), original_props.copy()]
        for i, (ip, iqn) in enumerate(connections):
            expected[i].update(target_portal=ip, target_iqn=iqn)
        # If we are failing and not forcing we won't make all the alls
        if will_raise:
            expected = expected[:1]
        self.assertListEqual(expected, actual_call_args)
        # No exceptions have been caught by ExceptionChainer context manager
        self.assertEqual(do_raise, bool(exc))

    def test_disconnect_from_iscsi_portal(self):
        self.connector._disconnect_from_iscsi_portal(self.CON_PROPS)
        expected_prefix = ('iscsiadm -m node -T %s -p %s ' %
                           (self.CON_PROPS['target_iqn'],
                            self.CON_PROPS['target_portal']))
        expected = [
            expected_prefix + '--op update -n node.startup -v manual',
            expected_prefix + '--logout',
            expected_prefix + '--op delete',
        ]
        self.assertListEqual(expected, self.cmds)

    def test_iscsiadm_discover_parsing(self):
        # Ensure that parsing iscsiadm discover ignores cruft.

        ips = ["192.168.204.82:3260", "192.168.204.82:3261"]
        iqns = ["iqn.2010-10.org.openstack:volume-"
                "f9b12623-6ce3-4dac-a71f-09ad4249bdd3",
                "iqn.2010-10.org.openstack:volume-"
                "f9b12623-6ce3-4dac-a71f-09ad4249bdd4"]

        # This slight wonkiness brought to you by pep8, as the actual
        # example output runs about 97 chars wide.
        sample_input = """Loading iscsi modules: done
Starting iSCSI initiator service: done
Setting up iSCSI targets: unused
%s %s
%s %s
""" % (ips[0] + ',1', iqns[0], ips[1] + ',1', iqns[1])
        out = self.connector.\
            _get_target_portals_from_iscsiadm_output(sample_input)
        self.assertEqual((ips, iqns), out)

    def test_sanitize_log_run_iscsiadm(self):
        # Tests that the parameters to the _run_iscsiadm function
        # are sanitized for when passwords are logged.
        def fake_debug(*args, **kwargs):
            self.assertIn('node.session.auth.password', args[0])
            self.assertNotIn('scrubme', args[0])

        volume = {'id': 'fake_uuid'}
        connection_info = self.iscsi_connection(volume,
                                                "10.0.2.15:3260",
                                                "fake_iqn")

        iscsi_properties = connection_info['data']
        with mock.patch.object(iscsi.LOG, 'debug',
                               side_effect=fake_debug) as debug_mock:
            self.connector._iscsiadm_update(iscsi_properties,
                                            'node.session.auth.password',
                                            'scrubme')

            # we don't care what the log message is, we just want to make sure
            # our stub method is called which asserts the password is scrubbed
            self.assertTrue(debug_mock.called)

    @mock.patch.object(iscsi.ISCSIConnector, 'get_volume_paths')
    def test_extend_volume_no_path(self, mock_volume_paths):
        mock_volume_paths.return_value = []
        volume = {'id': 'fake_uuid'}
        connection_info = self.iscsi_connection(volume,
                                                "10.0.2.15:3260",
                                                "fake_iqn")

        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector.extend_volume,
                          connection_info['data'])

    @mock.patch.object(linuxscsi.LinuxSCSI, 'extend_volume')
    @mock.patch.object(iscsi.ISCSIConnector, 'get_volume_paths')
    def test_extend_volume(self, mock_volume_paths, mock_scsi_extend):
        fake_new_size = 1024
        mock_volume_paths.return_value = ['/dev/vdx']
        mock_scsi_extend.return_value = fake_new_size
        volume = {'id': 'fake_uuid'}
        connection_info = self.iscsi_connection(volume,
                                                "10.0.2.15:3260",
                                                "fake_iqn")
        new_size = self.connector.extend_volume(connection_info['data'])
        self.assertEqual(fake_new_size, new_size)

    @mock.patch.object(iscsi.LOG, 'info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'extend_volume')
    @mock.patch.object(iscsi.ISCSIConnector, 'get_volume_paths')
    def test_extend_volume_mask_password(self, mock_volume_paths,
                                         mock_scsi_extend,
                                         mock_log_info):
        fake_new_size = 1024
        mock_volume_paths.return_value = ['/dev/vdx']
        mock_scsi_extend.return_value = fake_new_size
        volume = {'id': 'fake_uuid'}
        connection_info = self.iscsi_connection_chap(
            volume, "10.0.2.15:3260", "fake_iqn",
            'CHAP', 'fake_user', 'fake_password',
            'CHAP1', 'fake_user1', 'fake_password1')
        self.connector.extend_volume(connection_info['data'])

        self.assertEqual(2, mock_log_info.call_count)
        self.assertIn("'auth_password': '***'",
                      str(mock_log_info.call_args_list[0]))
        self.assertIn("'discovery_auth_password': '***'",
                      str(mock_log_info.call_args_list[0]))

    @mock.patch.object(iscsi.LOG, 'warning')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'extend_volume')
    @mock.patch.object(iscsi.ISCSIConnector, 'get_volume_paths')
    def test_extend_volume_mask_password_no_paths(self, mock_volume_paths,
                                                  mock_scsi_extend,
                                                  mock_log_warning):
        fake_new_size = 1024
        mock_volume_paths.return_value = []
        mock_scsi_extend.return_value = fake_new_size
        volume = {'id': 'fake_uuid'}
        connection_info = self.iscsi_connection_chap(
            volume, "10.0.2.15:3260", "fake_iqn",
            'CHAP', 'fake_user', 'fake_password',
            'CHAP1', 'fake_user1', 'fake_password1')

        self.assertRaises(exception.VolumePathsNotFound,
                          self.connector.extend_volume,
                          connection_info['data'])

        self.assertEqual(1, mock_log_warning.call_count)
        self.assertIn("'auth_password': '***'",
                      str(mock_log_warning.call_args_list[0]))
        self.assertIn("'discovery_auth_password': '***'",
                      str(mock_log_warning.call_args_list[0]))

    @mock.patch.object(os.path, 'isdir')
    def test_get_all_available_volumes_path_not_dir(self, mock_isdir):
        mock_isdir.return_value = False
        expected = []
        actual = self.connector.get_all_available_volumes()
        self.assertCountEqual(expected, actual)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_device_path')
    def test_get_potential_paths_mpath(self, get_path_mock):
        self.connector.use_multipath = True
        res = self.connector._get_potential_volume_paths(self.CON_PROPS)
        get_path_mock.assert_called_once_with(self.CON_PROPS)
        self.assertEqual(get_path_mock.return_value, res)
        self.assertEqual([], self.cmds)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_device_path')
    def test_get_potential_paths_single_path(self, get_path_mock,
                                             get_sessions_mock):
        get_path_mock.side_effect = [['path1'], ['path2'], ['path3', 'path4']]
        get_sessions_mock.return_value = [
            'ip1:port1', 'ip2:port2', 'ip3:port3']

        self.connector.use_multipath = False
        res = self.connector._get_potential_volume_paths(self.CON_PROPS)
        self.assertEqual({'path1', 'path2', 'path3', 'path4'}, set(res))
        get_sessions_mock.assert_called_once_with()

    @mock.patch.object(iscsi.ISCSIConnector, '_discover_iscsi_portals')
    def test_get_ips_iqns_luns_with_target_iqns(self, discover_mock):
        res = self.connector._get_ips_iqns_luns(self.CON_PROPS)
        expected = list(self.connector._get_all_targets(self.CON_PROPS))
        self.assertListEqual(expected, res)
        discover_mock.assert_not_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_get_discoverydb_portals')
    @mock.patch.object(iscsi.ISCSIConnector, '_discover_iscsi_portals')
    def test_get_ips_iqns_luns_discoverydb(self, discover_mock,
                                           db_portals_mock):
        db_portals_mock.return_value = [('ip1:port1', 'tgt1', '1'),
                                        ('ip2:port2', 'tgt2', '2')]
        res = self.connector._get_ips_iqns_luns(self.SINGLE_CON_PROPS,
                                                discover=False)
        self.assertListEqual(db_portals_mock.return_value, res)
        db_portals_mock.assert_called_once_with(self.SINGLE_CON_PROPS)
        discover_mock.assert_not_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_get_all_targets')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_discoverydb_portals')
    @mock.patch.object(iscsi.ISCSIConnector, '_discover_iscsi_portals')
    def test_get_ips_iqns_luns_disconnect_single_path(self, discover_mock,
                                                      db_portals_mock,
                                                      get_targets_mock):
        db_portals_mock.side_effect = exception.TargetPortalsNotFound
        res = self.connector._get_ips_iqns_luns(self.SINGLE_CON_PROPS,
                                                discover=False,
                                                is_disconnect_call=True)
        db_portals_mock.assert_called_once_with(self.SINGLE_CON_PROPS)
        discover_mock.assert_not_called()
        get_targets_mock.assert_called_once_with(self.SINGLE_CON_PROPS)
        self.assertEqual(get_targets_mock.return_value, res)

    @mock.patch.object(iscsi.ISCSIConnector, '_discover_iscsi_portals')
    def test_get_ips_iqns_luns_no_target_iqns_share_iqn(self, discover_mock):
        discover_mock.return_value = [('ip1:port1', 'tgt1', '1'),
                                      ('ip1:port1', 'tgt2', '1'),
                                      ('ip2:port2', 'tgt1', '2'),
                                      ('ip2:port2', 'tgt2', '2')]
        res = self.connector._get_ips_iqns_luns(self.SINGLE_CON_PROPS)
        expected = {('ip1:port1', 'tgt1', '1'),
                    ('ip2:port2', 'tgt1', '2')}
        self.assertEqual(expected, set(res))

    @mock.patch.object(iscsi.ISCSIConnector, '_discover_iscsi_portals')
    def test_get_ips_iqns_luns_no_target_iqns_diff_iqn(self, discover_mock):
        discover_mock.return_value = [('ip1:port1', 'tgt1', '1'),
                                      ('ip2:port2', 'tgt2', '2')]
        res = self.connector._get_ips_iqns_luns(self.SINGLE_CON_PROPS)
        self.assertEqual(discover_mock.return_value, res)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    def test_connect_to_iscsi_portal_all_new(self, get_sessions_mock):
        """Connect creating node and session."""
        session = 'session2'
        get_sessions_mock.side_effect = [
            [('tcp:', 'session1', 'ip1:port1', '1', 'tgt')],
            [('tcp:', 'session1', 'ip1:port1', '1', 'tgt'),
             ('tcp:', session, 'ip1:port1', '-1', 'tgt1')]
        ]
        utils.ISCSI_SUPPORTS_MANUAL_SCAN = None
        with mock.patch.object(self.connector, '_execute') as exec_mock:
            exec_mock.side_effect = [('', 'error'), ('', None),
                                     ('', None), ('', None),
                                     ('', None)]
            res = self.connector._connect_to_iscsi_portal(self.CON_PROPS)

        # True refers to "manual scans", since the call to update
        # node.session.scan didn't fail they are set to manual
        self.assertEqual((session, True), res)
        self.assertTrue(utils.ISCSI_SUPPORTS_MANUAL_SCAN)
        prefix = 'iscsiadm -m node -T tgt1 -p ip1:port1'
        expected_cmds = [
            prefix,
            prefix + ' --interface default --op new',
            prefix + ' --op update -n node.session.scan -v manual',
            prefix + ' --login',
            prefix + ' --op update -n node.startup -v automatic'
        ]
        actual_cmds = [' '.join(args[0]) for args in exec_mock.call_args_list]
        self.assertListEqual(expected_cmds, actual_cmds)
        self.assertEqual(2, get_sessions_mock.call_count)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    def test_connect_to_iscsi_portal_ip_case_insensitive(self,
                                                         get_sessions_mock):
        """Connect creating node and session."""
        session = 'session2'
        get_sessions_mock.side_effect = [
            [('tcp:', 'session1', 'iP1:port1', '1', 'tgt')],
            [('tcp:', 'session1', 'Ip1:port1', '1', 'tgt'),
             ('tcp:', session, 'IP1:port1', '-1', 'tgt1')]
        ]
        utils.ISCSI_SUPPORTS_MANUAL_SCAN = None
        with mock.patch.object(self.connector, '_execute') as exec_mock:
            exec_mock.side_effect = [('', 'error'), ('', None),
                                     ('', None), ('', None),
                                     ('', None)]
            res = self.connector._connect_to_iscsi_portal(self.CON_PROPS)

        # True refers to "manual scans", since the call to update
        # node.session.scan didn't fail they are set to manual
        self.assertEqual((session, True), res)
        self.assertTrue(utils.ISCSI_SUPPORTS_MANUAL_SCAN)
        prefix = 'iscsiadm -m node -T tgt1 -p ip1:port1'
        expected_cmds = [
            prefix,
            prefix + ' --interface default --op new',
            prefix + ' --op update -n node.session.scan -v manual',
            prefix + ' --login',
            prefix + ' --op update -n node.startup -v automatic'
        ]
        actual_cmds = [' '.join(args[0]) for args in exec_mock.call_args_list]
        self.assertListEqual(expected_cmds, actual_cmds)
        self.assertEqual(2, get_sessions_mock.call_count)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    def test_connect_to_iscsi_portal_all_exists_chap(self, get_sessions_mock):
        """Node and session already exists and we use chap authentication."""
        session = 'session2'
        get_sessions_mock.return_value = [('tcp:', session, 'ip1:port1',
                                           '-1', 'tgt1')]
        con_props = self.CON_PROPS.copy()
        con_props.update(auth_method='CHAP', auth_username='user',
                         auth_password='pwd')
        utils.ISCSI_SUPPORTS_MANUAL_SCAN = None
        res = self.connector._connect_to_iscsi_portal(con_props)
        # False refers to "manual scans", so we have manual iscsi scans
        self.assertEqual((session, True), res)
        self.assertTrue(utils.ISCSI_SUPPORTS_MANUAL_SCAN)
        prefix = 'iscsiadm -m node -T tgt1 -p ip1:port1'
        expected_cmds = [
            prefix,
            prefix + ' --op update -n node.session.scan -v manual',
            prefix + ' --op update -n node.session.auth.authmethod -v CHAP',
            prefix + ' --op update -n node.session.auth.username -v user',
            prefix + ' --op update -n node.session.auth.password -v pwd',
        ]
        self.assertListEqual(expected_cmds, self.cmds)
        get_sessions_mock.assert_called_once_with()

    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    def test_connect_to_iscsi_portal_fail_login(self, get_sessions_mock):
        get_sessions_mock.return_value = []
        with mock.patch.object(self.connector, '_execute') as exec_mock:
            exec_mock.side_effect = [('', None), ('', None),
                                     putils.ProcessExecutionError]
            res = self.connector._connect_to_iscsi_portal(self.CON_PROPS)
        self.assertEqual((None, None), res)
        expected_cmds = ['iscsiadm -m node -T tgt1 -p ip1:port1',
                         'iscsiadm -m node -T tgt1 -p ip1:port1 '
                         '--op update -n node.session.scan -v manual',
                         'iscsiadm -m node -T tgt1 -p ip1:port1 --login']
        actual_cmds = [' '.join(args[0]) for args in exec_mock.call_args_list]
        self.assertListEqual(expected_cmds, actual_cmds)
        get_sessions_mock.assert_called_once_with()

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn',
                       side_effect=(None, 'tgt2'))
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_single_volume(self, sleep_mock, cleanup_mock,
                                   connect_mock, get_wwn_mock):
        def my_connect(rescans, props, data):
            if props['target_iqn'] == 'tgt2':
                # Succeed on second call
                data['found_devices'].append('sdz')

        connect_mock.side_effect = my_connect

        res = self.connector._connect_single_volume(self.CON_PROPS)

        expected = {'type': 'block', 'scsi_wwn': 'tgt2', 'path': '/dev/sdz'}
        self.assertEqual(expected, res)
        get_wwn_mock.assert_has_calls([mock.call(['sdz']), mock.call(['sdz'])])
        sleep_mock.assert_called_once_with(1)
        cleanup_mock.assert_called_once_with(
            {'target_lun': 4, 'volume_id': 'vol_id',
             'target_portal': 'ip1:port1', 'target_iqn': 'tgt1'},
            (('ip1:port1', 'tgt1', 4),),
            force=True, ignore_errors=True)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn', return_value='')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_single_volume_no_wwn(self, sleep_mock, cleanup_mock,
                                          connect_mock, get_wwn_mock):
        def my_connect(rescans, props, data):
            data['found_devices'].append('sdz')

        connect_mock.side_effect = my_connect

        res = self.connector._connect_single_volume(self.CON_PROPS)

        expected = {'type': 'block', 'scsi_wwn': '', 'path': '/dev/sdz'}
        self.assertEqual(expected, res)
        get_wwn_mock.assert_has_calls([mock.call(['sdz'])] * 10)
        self.assertEqual(10, get_wwn_mock.call_count)
        sleep_mock.assert_has_calls([mock.call(1)] * 10)
        self.assertEqual(10, sleep_mock.call_count)
        cleanup_mock.assert_not_called()

    @staticmethod
    def _get_connect_vol_data():
        return {'stop_connecting': False, 'num_logins': 0, 'failed_logins': 0,
                'stopped_threads': 0, 'found_devices': [],
                'just_added_devices': []}

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn',
                       side_effect=(None, 'tgt2'))
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch.object(iscsi.ISCSIConnector, '_cleanup_connection')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_single_volume_not_found(self, sleep_mock, cleanup_mock,
                                             connect_mock, get_wwn_mock):

        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_single_volume,
                          self.CON_PROPS)

        get_wwn_mock.assert_not_called()

        # Called twice by the retry mechanism
        self.assertEqual(2, sleep_mock.call_count)

        props = list(self.connector._get_all_targets(self.CON_PROPS))
        calls_per_try = [
            mock.call({'target_portal': prop[0], 'target_iqn': prop[1],
                       'target_lun': prop[2], 'volume_id': 'vol_id'},
                      (prop,), force=True, ignore_errors=True)
            for prop in props
        ]
        cleanup_mock.assert_has_calls(calls_per_try * 3)

        data = self._get_connect_vol_data()
        calls_per_try = [mock.call(self.connector.device_scan_attempts,
                                   {'target_portal': prop[0],
                                    'target_iqn': prop[1],
                                    'target_lun': prop[2],
                                    'volume_id': 'vol_id'},
                                   data)
                         for prop in props]
        connect_mock.assert_has_calls(calls_per_try * 3)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm',
                       side_effect=[None, 'dm-0'])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn',
                       return_value='wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_wwid')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_multipath_volume_all_succeed(self, sleep_mock,
                                                  connect_mock, add_wwid_mock,
                                                  add_path_mock, get_wwn_mock,
                                                  find_dm_mock):
        def my_connect(rescans, props, data):
            devs = {'tgt1': 'sda', 'tgt2': 'sdb', 'tgt3': 'sdc', 'tgt4': 'sdd'}
            data['stopped_threads'] += 1
            data['num_logins'] += 1
            dev = devs[props['target_iqn']]
            data['found_devices'].append(dev)
            data['just_added_devices'].append(dev)

        connect_mock.side_effect = my_connect

        res = self.connector._connect_multipath_volume(self.CON_PROPS)

        expected = {'type': 'block', 'scsi_wwn': 'wwn', 'multipath_id': 'wwn',
                    'path': '/dev/dm-0'}
        self.assertEqual(expected, res)

        self.assertEqual(1, get_wwn_mock.call_count)
        result = list(get_wwn_mock.call_args[0][0])
        result.sort()
        self.assertEqual(['sda', 'sdb', 'sdc', 'sdd'], result)
        # Check we pass the mpath
        self.assertIsNone(get_wwn_mock.call_args[0][1])
        add_wwid_mock.assert_called_once_with('wwn')
        self.assertNotEqual(0, add_path_mock.call_count)
        self.assertGreaterEqual(find_dm_mock.call_count, 2)
        self.assertEqual(4, connect_mock.call_count)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm',
                       side_effect=[None, 'dm-0'])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn', return_value='')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_wwid')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_multipath_volume_no_wwid(self, sleep_mock, connect_mock,
                                              add_wwid_mock, add_path_mock,
                                              get_wwn_mock, find_dm_mock):
        # Even if we don't have the wwn we'll be able to find the multipath
        def my_connect(rescans, props, data):
            devs = {'tgt1': 'sda', 'tgt2': 'sdb', 'tgt3': 'sdc', 'tgt4': 'sdd'}
            data['stopped_threads'] += 1
            data['num_logins'] += 1
            dev = devs[props['target_iqn']]
            data['found_devices'].append(dev)
            data['just_added_devices'].append(dev)

        connect_mock.side_effect = my_connect

        with mock.patch.object(self.connector,
                               'use_multipath'):
            res = self.connector._connect_multipath_volume(self.CON_PROPS)

        expected = {'type': 'block', 'scsi_wwn': '', 'multipath_id': '',
                    'path': '/dev/dm-0'}
        self.assertEqual(expected, res)

        self.assertEqual(3, get_wwn_mock.call_count)
        result = list(get_wwn_mock.call_args[0][0])
        result.sort()
        self.assertEqual(['sda', 'sdb', 'sdc', 'sdd'], result)
        # Initially mpath we pass is None, but on last call is the mpath
        mpath_values = [c[1][1] for c in get_wwn_mock._mock_mock_calls]
        self.assertEqual([None, None, 'dm-0'], mpath_values)
        add_wwid_mock.assert_not_called()
        add_path_mock.assert_not_called()
        self.assertGreaterEqual(find_dm_mock.call_count, 2)
        self.assertEqual(4, connect_mock.call_count)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm',
                       side_effect=[None, 'dm-0'])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn',
                       return_value='wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_wwid')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_multipath_volume_all_fail(self, sleep_mock, connect_mock,
                                               add_wwid_mock, add_path_mock,
                                               get_wwn_mock, find_dm_mock):
        def my_connect(rescans, props, data):
            data['stopped_threads'] += 1
            data['failed_logins'] += 1

        connect_mock.side_effect = my_connect

        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_multipath_volume,
                          self.CON_PROPS)

        get_wwn_mock.assert_not_called()
        add_wwid_mock.assert_not_called()
        add_path_mock.assert_not_called()
        find_dm_mock.assert_not_called()
        self.assertEqual(4 * 3, connect_mock.call_count)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm',
                       side_effect=[None, 'dm-0'])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn',
                       return_value='wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_wwid')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_multipath_volume_some_fail_mp_found(self, sleep_mock,
                                                         connect_mock,
                                                         add_wwid_mock,
                                                         add_path_mock,
                                                         get_wwn_mock,
                                                         find_dm_mock):
        def my_connect(rescans, props, data):
            devs = {'tgt1': '', 'tgt2': 'sdb', 'tgt3': '', 'tgt4': 'sdd'}
            data['stopped_threads'] += 1
            dev = devs[props['target_iqn']]
            if dev:
                data['num_logins'] += 1
                data['found_devices'].append(dev)
                data['just_added_devices'].append(dev)
            else:
                data['failed_logins'] += 1

        connect_mock.side_effect = my_connect

        res = self.connector._connect_multipath_volume(self.CON_PROPS)

        expected = {'type': 'block', 'scsi_wwn': 'wwn', 'multipath_id': 'wwn',
                    'path': '/dev/dm-0'}
        self.assertEqual(expected, res)
        self.assertEqual(1, get_wwn_mock.call_count)
        result = list(get_wwn_mock.call_args[0][0])
        result.sort()
        self.assertEqual(['sdb', 'sdd'], result)
        add_wwid_mock.assert_called_once_with('wwn')
        self.assertNotEqual(0, add_path_mock.call_count)
        self.assertGreaterEqual(find_dm_mock.call_count, 2)
        self.assertEqual(4, connect_mock.call_count)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm',
                       return_value=None)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn',
                       return_value='wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_wwid')
    @mock.patch.object(iscsi.time, 'time', side_effect=(0, 0, 11, 0))
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch('os_brick.utils._time_sleep')
    def test_connect_multipath_volume_some_fail_mp_not_found(self, sleep_mock,
                                                             connect_mock,
                                                             time_mock,
                                                             add_wwid_mock,
                                                             add_path_mock,
                                                             get_wwn_mock,
                                                             find_dm_mock):
        def my_connect(rescans, props, data):
            devs = {'tgt1': '', 'tgt2': 'sdb', 'tgt3': '', 'tgt4': 'sdd'}
            data['stopped_threads'] += 1
            dev = devs[props['target_iqn']]
            if dev:
                data['num_logins'] += 1
                data['found_devices'].append(dev)
                data['just_added_devices'].append(dev)
            else:
                data['failed_logins'] += 1

        connect_mock.side_effect = my_connect

        res = self.connector._connect_multipath_volume(self.CON_PROPS)

        expected = [{'type': 'block', 'scsi_wwn': 'wwn', 'path': '/dev/sdb'},
                    {'type': 'block', 'scsi_wwn': 'wwn', 'path': '/dev/sdd'}]
        # It can only be one of the 2
        self.assertIn(res, expected)
        self.assertEqual(1, get_wwn_mock.call_count)
        result = list(get_wwn_mock.call_args[0][0])
        result.sort()
        self.assertEqual(['sdb', 'sdd'], result)
        add_wwid_mock.assert_called_once_with('wwn')
        self.assertNotEqual(0, add_path_mock.call_count)
        self.assertGreaterEqual(find_dm_mock.call_count, 4)
        self.assertEqual(4, connect_mock.call_count)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_sysfs_multipath_dm',
                       return_value=None)
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_sysfs_wwn',
                       return_value='wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_path')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'multipath_add_wwid')
    @mock.patch.object(iscsi.time, 'time', side_effect=(0, 0, 11, 0))
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_vol')
    @mock.patch('os_brick.utils._time_sleep', mock.Mock())
    def test_connect_multipath_volume_all_loging_not_found(self,
                                                           connect_mock,
                                                           time_mock,
                                                           add_wwid_mock,
                                                           add_path_mock,
                                                           get_wwn_mock,
                                                           find_dm_mock):
        def my_connect(rescans, props, data):
            data['stopped_threads'] += 1
            data['num_logins'] += 1

        connect_mock.side_effect = my_connect

        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_multipath_volume,
                          self.CON_PROPS)

        get_wwn_mock.assert_not_called()
        add_wwid_mock.assert_not_called()
        add_path_mock.assert_not_called()
        find_dm_mock.assert_not_called()
        self.assertEqual(12, connect_mock.call_count)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'scan_iscsi')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'device_name_by_hctl',
                       return_value='sda')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    def test_connect_vol(self, connect_mock, dev_name_mock, scan_mock,
                         sleep_mock):
        lscsi = self.connector._linuxscsi
        data = self._get_connect_vol_data()
        hctl = [mock.sentinel.host, mock.sentinel.channel,
                mock.sentinel.target, mock.sentinel.lun]

        connect_mock.return_value = (mock.sentinel.session, False)

        with mock.patch.object(lscsi, 'get_hctl',
                               side_effect=(None, hctl)) as hctl_mock:
            self.connector._connect_vol(3, self.CON_PROPS, data)

        expected = self._get_connect_vol_data()
        expected.update(num_logins=1, stopped_threads=1,
                        found_devices=['sda'], just_added_devices=['sda'])
        self.assertDictEqual(expected, data)

        connect_mock.assert_called_once_with(self.CON_PROPS)
        hctl_mock.assert_has_calls([mock.call(mock.sentinel.session,
                                              self.CON_PROPS['target_lun']),
                                    mock.call(mock.sentinel.session,
                                              self.CON_PROPS['target_lun'])])

        scan_mock.assert_not_called()
        dev_name_mock.assert_called_once_with(mock.sentinel.session, hctl)
        sleep_mock.assert_called_once_with(1)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'scan_iscsi')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'device_name_by_hctl',
                       side_effect=(None, None, None, None, 'sda'))
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    def test_connect_vol_rescan(self, connect_mock, dev_name_mock, scan_mock,
                                sleep_mock):
        lscsi = self.connector._linuxscsi
        data = self._get_connect_vol_data()
        hctl = [mock.sentinel.host, mock.sentinel.channel,
                mock.sentinel.target, mock.sentinel.lun]

        connect_mock.return_value = (mock.sentinel.session, False)

        with mock.patch.object(lscsi, 'get_hctl',
                               return_value=hctl) as hctl_mock:
            self.connector._connect_vol(3, self.CON_PROPS, data)

        expected = self._get_connect_vol_data()
        expected.update(num_logins=1, stopped_threads=1,
                        found_devices=['sda'], just_added_devices=['sda'])
        self.assertDictEqual(expected, data)

        connect_mock.assert_called_once_with(self.CON_PROPS)
        hctl_mock.assert_called_once_with(mock.sentinel.session,
                                          self.CON_PROPS['target_lun'])

        scan_mock.assert_called_once_with(*hctl)
        self.assertEqual(5, dev_name_mock.call_count)
        self.assertEqual(4, sleep_mock.call_count)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'scan_iscsi')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'device_name_by_hctl',
                       side_effect=(None, None, None, None, 'sda'))
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    def test_connect_vol_manual(self, connect_mock, dev_name_mock, scan_mock,
                                sleep_mock):
        lscsi = self.connector._linuxscsi
        data = self._get_connect_vol_data()
        hctl = [mock.sentinel.host, mock.sentinel.channel,
                mock.sentinel.target, mock.sentinel.lun]

        # Simulate manual scan
        connect_mock.return_value = (mock.sentinel.session, True)

        with mock.patch.object(lscsi, 'get_hctl',
                               return_value=hctl) as hctl_mock:
            self.connector._connect_vol(3, self.CON_PROPS, data)

        expected = self._get_connect_vol_data()
        expected.update(num_logins=1, stopped_threads=1,
                        found_devices=['sda'], just_added_devices=['sda'])
        self.assertDictEqual(expected, data)

        connect_mock.assert_called_once_with(self.CON_PROPS)
        hctl_mock.assert_called_once_with(mock.sentinel.session,
                                          self.CON_PROPS['target_lun'])

        self.assertEqual(2, scan_mock.call_count)
        self.assertEqual(5, dev_name_mock.call_count)
        self.assertEqual(4, sleep_mock.call_count)

    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal',
                       return_value=(None, False))
    def test_connect_vol_no_session(self, connect_mock):
        data = self._get_connect_vol_data()

        self.connector._connect_vol(3, self.CON_PROPS, data)

        expected = self._get_connect_vol_data()
        expected.update(failed_logins=1, stopped_threads=1)
        self.assertDictEqual(expected, data)

    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    def test_connect_vol_with_connection_failure(self, connect_mock):
        data = self._get_connect_vol_data()

        connect_mock.side_effect = Exception()

        self.connector._connect_vol(3, self.CON_PROPS, data)

        expected = self._get_connect_vol_data()
        expected.update(failed_logins=1, stopped_threads=1)
        self.assertDictEqual(expected, data)

    @mock.patch('os_brick.utils._time_sleep', mock.Mock())
    @mock.patch.object(linuxscsi.LinuxSCSI, 'scan_iscsi')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'device_name_by_hctl',
                       return_value=None)
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    def test_connect_vol_not_found(self, connect_mock, dev_name_mock,
                                   scan_mock):
        lscsi = self.connector._linuxscsi
        data = self._get_connect_vol_data()
        hctl = [mock.sentinel.host, mock.sentinel.channel,
                mock.sentinel.target, mock.sentinel.lun]

        # True because we are simulating we have manual scans
        connect_mock.return_value = (mock.sentinel.session, True)

        with mock.patch.object(lscsi, 'get_hctl',
                               side_effect=(hctl,)) as hctl_mock:
            self.connector._connect_vol(3, self.CON_PROPS, data)

        expected = self._get_connect_vol_data()
        expected.update(num_logins=1, stopped_threads=1)
        self.assertDictEqual(expected, data)

        hctl_mock.assert_called_once_with(mock.sentinel.session,
                                          self.CON_PROPS['target_lun'])
        # We have 3 scans because on manual mode we also scan on connect
        scan_mock.assert_has_calls([mock.call(*hctl)] * 3)
        dev_name_mock.assert_has_calls(
            [mock.call(mock.sentinel.session, hctl),
             mock.call(mock.sentinel.session, hctl)])

    @mock.patch('os_brick.utils._time_sleep', mock.Mock())
    @mock.patch.object(linuxscsi.LinuxSCSI, 'scan_iscsi')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    def test_connect_vol_stop_connecting(self, connect_mock, scan_mock):
        data = self._get_connect_vol_data()

        def device_name_by_hctl(session, hctl):
            data['stop_connecting'] = True
            return None

        lscsi = self.connector._linuxscsi
        hctl = [mock.sentinel.host, mock.sentinel.channel,
                mock.sentinel.target, mock.sentinel.lun]

        connect_mock.return_value = (mock.sentinel.session, False)

        with mock.patch.object(lscsi, 'get_hctl',
                               return_value=hctl) as hctl_mock, \
                mock.patch.object(
                    lscsi, 'device_name_by_hctl',
                    side_effect=device_name_by_hctl) as dev_name_mock:

            self.connector._connect_vol(3, self.CON_PROPS, data)

        expected = self._get_connect_vol_data()
        expected.update(num_logins=1, stopped_threads=1, stop_connecting=True)
        self.assertDictEqual(expected, data)

        hctl_mock.assert_called_once_with(mock.sentinel.session,
                                          self.CON_PROPS['target_lun'])
        scan_mock.assert_not_called()
        dev_name_mock.assert_called_once_with(mock.sentinel.session, hctl)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_device_link')
    def test__get_connect_result(self, get_link_mock):
        props = self.CON_PROPS.copy()
        props['encrypted'] = False
        res = self.connector._get_connect_result(props, 'wwn', ['sda', 'sdb'])
        expected = {'type': 'block', 'scsi_wwn': 'wwn', 'path': '/dev/sda'}
        self.assertDictEqual(expected, res)
        get_link_mock.assert_not_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_get_device_link')
    def test__get_connect_result_mpath(self, get_link_mock):
        props = self.CON_PROPS.copy()
        props['encrypted'] = False
        res = self.connector._get_connect_result(props, 'wwn', ['sda', 'sdb'],
                                                 'mpath')
        expected = {'type': 'block', 'scsi_wwn': 'wwn', 'path': '/dev/mpath',
                    'multipath_id': 'wwn'}
        self.assertDictEqual(expected, res)
        get_link_mock.assert_not_called()

    @mock.patch.object(iscsi.ISCSIConnector, '_get_device_link',
                       return_value='/dev/disk/by-id/scsi-wwn')
    def test__get_connect_result_encrypted(self, get_link_mock):
        props = self.CON_PROPS.copy()
        props['encrypted'] = True
        res = self.connector._get_connect_result(props, 'wwn', ['sda', 'sdb'])
        expected = {'type': 'block', 'scsi_wwn': 'wwn',
                    'path': get_link_mock.return_value}
        self.assertDictEqual(expected, res)
        get_link_mock.assert_called_once_with('wwn', '/dev/sda', None)

    @mock.patch('os.path.realpath', return_value='/dev/sda')
    def test__get_device_link(self, realpath_mock):
        symlink = '/dev/disk/by-id/scsi-wwn'
        res = self.connector._get_device_link('wwn', '/dev/sda', None)
        self.assertEqual(symlink, res)
        realpath_mock.assert_called_once_with(symlink)

    @mock.patch('os.path.realpath', return_value='/dev/dm-0')
    def test__get_device_link_multipath(self, realpath_mock):
        symlink = '/dev/disk/by-id/dm-uuid-mpath-wwn'
        res = self.connector._get_device_link('wwn', '/dev/dm-0', 'wwn')
        self.assertEqual(symlink, res)
        realpath_mock.assert_called_once_with(symlink)

    @mock.patch('os.path.realpath', side_effect=('/dev/sdz', '/dev/sdy',
                                                 '/dev/sda', '/dev/sdx'))
    @mock.patch('os.listdir', return_value=['dm-...', 'scsi-wwn', 'scsi-...'])
    def test__get_device_link_check_links(self, listdir_mock, realpath_mock):
        res = self.connector._get_device_link('wwn', '/dev/sda', None)
        self.assertEqual(res, '/dev/disk/by-id/scsi-wwn')
        listdir_mock.assert_called_once_with('/dev/disk/by-id/')
        realpath_mock.assert_has_calls([
            mock.call('/dev/disk/by-id/scsi-wwn'),
            mock.call('/dev/disk/by-id/dm-...'),
            mock.call('/dev/disk/by-id/scsi-wwn')])

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch('os.path.realpath', return_value='/dev/sdz')
    @mock.patch('os.listdir', return_value=['dm-...', 'scsi-...'])
    def test__get_device_link_not_found(self, listdir_mock, realpath_mock,
                                        mock_time):
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._get_device_link,
                          'wwn', '/dev/sda', None)
        listdir_mock.assert_has_calls(3 * [mock.call('/dev/disk/by-id/')])
        self.assertEqual(3, listdir_mock.call_count)
        realpath_mock.assert_has_calls(
            3 * [mock.call('/dev/disk/by-id/scsi-wwn'),
                 mock.call('/dev/disk/by-id/dm-...'),
                 mock.call('/dev/disk/by-id/scsi-...')])
        self.assertEqual(9, realpath_mock.call_count)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch('os.path.realpath')
    @mock.patch('os.listdir', return_value=['dm-...', 'scsi-...'])
    def test__get_device_link_symlink_found_after_retry(self, mock_listdir,
                                                        mock_realpath,
                                                        mock_time):
        # Return the expected realpath on the third retry
        mock_realpath.side_effect = [
            None, None, None, None, None, None, '/dev/sda']

        # Assert that VolumeDeviceNotFound isn't raised
        self.connector._get_device_link('wwn', '/dev/sda', None)

        # Assert that listdir and realpath have been called correctly
        mock_listdir.assert_has_calls(2 * [mock.call('/dev/disk/by-id/')])
        self.assertEqual(2, mock_listdir.call_count)
        mock_realpath.assert_has_calls(
            2 * [mock.call('/dev/disk/by-id/scsi-wwn'),
                 mock.call('/dev/disk/by-id/dm-...'),
                 mock.call('/dev/disk/by-id/scsi-...')]
            + [mock.call('/dev/disk/by-id/scsi-wwn')])
        self.assertEqual(7, mock_realpath.call_count)

    @mock.patch('os_brick.utils._time_sleep')
    @mock.patch('os.path.realpath')
    @mock.patch('os.listdir', return_value=['dm-...', 'scsi-...'])
    def test__get_device_link_symlink_found_after_retry_by_listdir(
            self, mock_listdir, mock_realpath, mock_time):

        # Return the expected realpath on the second retry while looping over
        # the devices returned by listdir
        mock_realpath.side_effect = [
            None, None, None, None, None, '/dev/sda']

        # Assert that VolumeDeviceNotFound isn't raised
        self.connector._get_device_link('wwn', '/dev/sda', None)

        # Assert that listdir and realpath have been called correctly
        mock_listdir.assert_has_calls(2 * [mock.call('/dev/disk/by-id/')])
        self.assertEqual(2, mock_listdir.call_count)
        mock_realpath.assert_has_calls(
            2 * [mock.call('/dev/disk/by-id/scsi-wwn'),
                 mock.call('/dev/disk/by-id/dm-...'),
                 mock.call('/dev/disk/by-id/scsi-...')])
        self.assertEqual(6, mock_realpath.call_count)

    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm_bare')
    def test_get_node_startup_values(self, run_iscsiadm_bare_mock):
        name1 = 'volume-00000001-1'
        name2 = 'volume-00000001-2'
        name3 = 'volume-00000001-3'
        vol = {'id': 1, 'name': name1}
        location = '10.0.2.15:3260'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        iqn3 = 'iqn.2010-10.org.openstack:%s' % name3
        connection_properties = self.iscsi_connection(vol, [location], [iqn1])

        node_startup1 = "manual"
        node_startup2 = "automatic"
        node_startup3 = "manual"
        node_values = (
            '# BEGIN RECORD 2.0-873\n'
            'node.name = %s\n'
            'node.tpgt = 1\n'
            'node.startup = %s\n'
            'iface.hwaddress = <empty>\n'
            '# END RECORD\n'
            '# BEGIN RECORD 2.0-873\n'
            'node.name = %s\n'
            'node.tpgt = 1\n'
            'node.startup = %s\n'
            'iface.hwaddress = <empty>\n'
            '# END RECORD\n'
            '# BEGIN RECORD 2.0-873\n'
            'node.name = %s\n'
            'node.tpgt = 1\n'
            'node.startup = %s\n'
            'iface.hwaddress = <empty>\n'
            '# END RECORD\n') % (iqn1, node_startup1, iqn2, node_startup2,
                                 iqn3, node_startup3)
        run_iscsiadm_bare_mock.return_value = (node_values, None)

        node_startups =\
            self.connector._get_node_startup_values(
                connection_properties['data'])
        expected_node_startups = {iqn1: node_startup1, iqn2: node_startup2,
                                  iqn3: node_startup3}
        self.assertEqual(node_startups, expected_node_startups)

    @mock.patch.object(iscsi.ISCSIConnector, '_execute')
    def test_get_node_startup_values_no_nodes(self, exec_mock):
        connection_properties = {'target_portal': 'ip1:port1'}
        no_nodes_output = ''
        no_nodes_err = 'iscsiadm: No records found\n'
        exec_mock.return_value = (no_nodes_output, no_nodes_err)
        res = self.connector._get_node_startup_values(connection_properties)
        self.assertEqual({}, res)
        exec_mock.assert_called_once_with(
            'iscsiadm', '-m', 'node', '--op', 'show', '-p',
            connection_properties['target_portal'],
            root_helper=self.connector._root_helper, run_as_root=True,
            check_exit_code=(0, 21))

    @mock.patch.object(iscsi.ISCSIConnector, '_get_node_startup_values')
    @mock.patch.object(iscsi.ISCSIConnector, '_iscsiadm_update')
    def test_recover_node_startup_values(self, iscsiadm_update_mock,
                                         get_node_startup_values_mock):
        name1 = 'volume-00000001-1'
        name2 = 'volume-00000001-2'
        name3 = 'volume-00000001-3'
        vol = {'id': 1, 'name': name1}
        location = '10.0.2.15:3260'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        iqn3 = 'iqn.2010-10.org.openstack:%s' % name3
        connection_properties = self.iscsi_connection(vol, [location], iqn1)
        recover_connection = self.iscsi_connection(vol, [location], iqn2)

        node_startup1 = "manual"
        node_startup2 = "automatic"
        node_startup3 = "manual"
        get_node_startup_values_mock.return_value = {iqn1: node_startup1,
                                                     iqn2: node_startup2,
                                                     iqn3: node_startup3}

        old_node_startup_values = {iqn1: node_startup1,
                                   iqn2: "manual",
                                   iqn3: node_startup3}
        self.connector._recover_node_startup_values(
            connection_properties['data'], old_node_startup_values)
        iscsiadm_update_mock.assert_called_once_with(
            recover_connection['data'], "node.startup", "manual")
