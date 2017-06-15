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
import glob
import mock
import os
import testtools
import time

import ddt
from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import iscsi
from os_brick.initiator import host_driver
from os_brick.initiator import linuxscsi
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests.initiator import test_connector


@ddt.ddt
class ISCSIConnectorTestCase(test_connector.ConnectorTestCase):
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

    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsi_session',
                       return_value=(None, 'error'))
    def test_get_iscsi_sessions_full_error(self, sessions_mock):
        res = self.connector._get_iscsi_sessions_full()
        self.assertEqual([], res)
        sessions_mock.assert_called()

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

    @mock.patch('glob.glob')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_sessions_full')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_nodes')
    def test_get_connection_devices(self, nodes_mock, sessions_mock,
                                    glob_mock):
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
        fake_props = {}
        fake_devices = [fake_path]
        expected = fake_devices
        mock_potential_paths.return_value = (fake_devices, fake_props)

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

    @mock.patch('time.sleep', mock.Mock())
    @mock.patch.object(iscsi.ISCSIConnector, 'disconnect_volume')
    def _test_connect_volume(self, extra_props, additional_commands,
                             disconnect_vol_mock, transport=None):
        # for making sure the /dev/disk/by-path is gone
        exists_mock = mock.Mock()
        exists_mock.return_value = True
        os.path.exists = exists_mock

        vol = {'id': 1, 'name': self._name}
        connection_info = self.iscsi_connection(vol, self._location, self._iqn)
        for key, value in extra_props.items():
            connection_info['data'][key] = value
        if transport is not None:
            dev_list = self.generate_device(self._location, self._iqn,
                                            transport)
            with mock.patch.object(glob, 'glob', return_value=[dev_list]):
                device = self.connector.connect_volume(connection_info['data'])
        else:
            device = self.connector.connect_volume(connection_info['data'])

        dev_str = self.generate_device(self._location, self._iqn, transport)
        self.assertEqual(device['type'], 'block')
        self.assertEqual(device['path'], dev_str)

        self.count = 0

        # Disconnect has its own tests, should not be tested here
        expected_commands = [
            ('iscsiadm -m node -T %s -p %s' % (self._iqn, self._location)),
            ('iscsiadm -m session'),
            ('iscsiadm -m node -T %s -p %s --login' % (self._iqn,
                                                       self._location)),
            ('iscsiadm -m node -T %s -p %s --op update'
             ' -n node.startup -v automatic' % (self._iqn,
                                                self._location)),
            ('/lib/udev/scsi_id --page 0x83 --whitelisted %s' % dev_str),
        ] + additional_commands

        self.assertEqual(expected_commands, self.cmds)

    @testtools.skipUnless(os.path.exists('/dev/disk/by-path'),
                          'Test requires /dev/disk/by-path')
    def test_connect_volume(self):
        self._test_connect_volume({}, [])

    @testtools.skipUnless(os.path.exists('/dev/disk/by-path'),
                          'Test requires /dev/disk/by-path')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_transport')
    def test_connect_volume_with_transport(self, mock_transport):
        mock_transport.return_value = 'fake_transport'
        self._test_connect_volume({}, [], transport='fake_transport')

    @testtools.skipUnless(os.path.exists('/dev/disk/by-path'),
                          'Test requires /dev/disk/by-path')
    @mock.patch('os.path.exists', side_effect=(True,) * 4 + (False, False))
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm')
    def test_connect_volume_with_alternative_targets_primary_error(
            self, mock_iscsiadm, mock_exists):
        location2 = '[2001:db8::1]:3260'
        dev_loc2 = '2001:db8::1:3260'  # udev location2
        iqn2 = 'iqn.2010-10.org.openstack:%s-2' % self._name
        vol = {'id': 1, 'name': self._name}
        connection_info = self.iscsi_connection(vol, self._location, self._iqn)
        connection_info['data']['target_portals'] = [self._location, location2]
        connection_info['data']['target_iqns'] = [self._iqn, iqn2]
        connection_info['data']['target_luns'] = [self._lun, 2]
        dev_str2 = '/dev/disk/by-path/ip-%s-iscsi-%s-lun-2' % (dev_loc2, iqn2)

        def fake_run_iscsiadm(iscsi_properties, iscsi_command, **kwargs):
            if iscsi_properties['target_portal'] == self._location:
                if iscsi_command == ('--login',):
                    raise putils.ProcessExecutionError(None, None, 21)
            return mock.DEFAULT

        mock_iscsiadm.side_effect = fake_run_iscsiadm
        mock_exists.side_effect = lambda x: x == dev_str2
        device = self.connector.connect_volume(connection_info['data'])
        self.assertEqual('block', device['type'])
        self.assertEqual(dev_str2, device['path'])
        props = connection_info['data'].copy()
        for key in ('target_portals', 'target_iqns', 'target_luns'):
            props.pop(key, None)
        props['target_portal'] = location2
        props['target_iqn'] = iqn2
        props['target_lun'] = 2
        mock_iscsiadm.assert_any_call(props, ('--login',),
                                      check_exit_code=[0, 255])

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm_bare')
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(iscsi.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    def test_connect_volume_with_multipath(
            self, mock_discover_mpath_device, exists_mock,
            rescan_iscsi_mock, connect_to_mock,
            portals_mock, iscsiadm_mock, mock_iscsi_wwn):
        mock_iscsi_wwn.return_value = test_connector.FAKE_SCSI_WWN
        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        vol = {'id': 1, 'name': name}
        connection_properties = self.iscsi_connection(vol, location, iqn)
        mock_discover_mpath_device.return_value = (
            'iqn.2010-10.org.openstack:%s' % name,
            test_connector.FAKE_SCSI_WWN)

        self.connector_with_multipath = \
            iscsi.ISCSIConnector(None, use_multipath=True)
        iscsiadm_mock.return_value = "%s %s" % (location, iqn)
        portals_mock.return_value = ([location], [iqn])

        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])
        expected_result = {'multipath_id': test_connector.FAKE_SCSI_WWN,
                           'path': 'iqn.2010-10.org.openstack:volume-00000001',
                           'type': 'block',
                           'scsi_wwn': test_connector.FAKE_SCSI_WWN}
        self.assertEqual(expected_result, result)

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
                'iscsiadm -m discoverydb -t sendtargets -I %(iface)s'
                ' -p %(location)s --discover' % {'iface': interface,
                                                 'location': location}]
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
            'iscsiadm -m discoverydb -t sendtargets -I default -p %s'
            ' --discover' % location]
        self.assertEqual(expected_cmds, self.cmds)

        self.assertRaises(exception.TargetPortalNotFound,
                          self.connector_with_multipath.connect_volume,
                          connection_properties['data'])

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_hosts_channels_targets_luns', return_value=[])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch('os.path.exists', side_effect=(True,) * 7 + (False, False))
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'process_lun_id')
    def test_connect_volume_with_multiple_portals(
            self, mock_process_lun_id, mock_discover_mpath_device,
            mock_run_multipath, mock_devices, mock_exists, mock_scsi_wwn,
            mock_get_htcls):
        mock_scsi_wwn.return_value = test_connector.FAKE_SCSI_WWN
        location2 = '[2001:db8::1]:3260'
        dev_loc2 = '2001:db8::1:3260'  # udev location2
        name2 = 'volume-00000001-2'
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        lun2 = 2

        fake_multipath_dev = '/dev/mapper/fake-multipath-dev'
        vol = {'id': 1, 'name': self._name}
        connection_properties = self.iscsi_connection_multipath(
            vol, [self._location, location2], [self._iqn, iqn2], [self._lun,
                                                                  lun2])
        devs = ['/dev/disk/by-path/ip-%s-iscsi-%s-lun-1' % (self._location,
                                                            self._iqn),
                '/dev/disk/by-path/ip-%s-iscsi-%s-lun-2' % (dev_loc2, iqn2)]
        mock_devices.return_value = devs
        # mock_iscsi_devices.return_value = devs
        # mock_get_iqn.return_value = [self._iqn, iqn2]
        mock_discover_mpath_device.return_value = (
            fake_multipath_dev, test_connector.FAKE_SCSI_WWN)
        mock_process_lun_id.return_value = [self._lun, lun2]

        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])
        expected_result = {'multipath_id': test_connector.FAKE_SCSI_WWN,
                           'path': fake_multipath_dev, 'type': 'block',
                           'scsi_wwn': test_connector.FAKE_SCSI_WWN}
        cmd_format = 'iscsiadm -m node -T %s -p %s --%s'
        expected_commands = [cmd_format % (self._iqn, self._location, 'login'),
                             cmd_format % (iqn2, location2, 'login')]
        self.assertEqual(expected_result, result)
        for command in expected_commands:
            self.assertIn(command, self.cmds)

        mock_get_htcls.assert_called_once_with([(self._location, self._iqn,
                                                 self._lun),
                                                (location2, iqn2, lun2)])

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_hosts_channels_targets_luns', return_value=[])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm')
    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'process_lun_id')
    def test_connect_volume_with_multiple_portals_primary_error(
            self, mock_process_lun_id, mock_discover_mpath_device,
            mock_iscsiadm, mock_run_multipath, mock_devices, mock_exists,
            mock_scsi_wwn, mock_get_htcls):
        mock_scsi_wwn.return_value = test_connector.FAKE_SCSI_WWN
        location1 = '10.0.2.15:3260'
        location2 = '[2001:db8::1]:3260'
        dev_loc2 = '2001:db8::1:3260'  # udev location2
        name1 = 'volume-00000001-1'
        name2 = 'volume-00000001-2'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        fake_multipath_dev = '/dev/mapper/fake-multipath-dev'
        vol = {'id': 1, 'name': name1}
        connection_properties = self.iscsi_connection_multipath(
            vol, [location1, location2], [iqn1, iqn2], [1, 2])
        dev1 = '/dev/disk/by-path/ip-%s-iscsi-%s-lun-1' % (location1, iqn1)
        dev2 = '/dev/disk/by-path/ip-%s-iscsi-%s-lun-2' % (dev_loc2, iqn2)

        def fake_run_iscsiadm(iscsi_properties, iscsi_command, **kwargs):
            if iscsi_properties['target_portal'] == location1:
                if iscsi_command == ('--login',):
                    raise putils.ProcessExecutionError(None, None, 21)
            return mock.DEFAULT

        mock_exists.side_effect = lambda x: x != dev1
        mock_devices.return_value = [dev2]
        mock_iscsiadm.side_effect = fake_run_iscsiadm

        mock_discover_mpath_device.return_value = (
            fake_multipath_dev, test_connector.FAKE_SCSI_WWN)
        mock_process_lun_id.return_value = [1, 2]

        props = connection_properties['data'].copy()
        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])

        expected_result = {'multipath_id': test_connector.FAKE_SCSI_WWN,
                           'path': fake_multipath_dev, 'type': 'block',
                           'scsi_wwn': test_connector.FAKE_SCSI_WWN}
        self.assertEqual(expected_result, result)
        props['target_portal'] = location1
        props['target_iqn'] = iqn1
        mock_iscsiadm.assert_any_call(props, ('--login',),
                                      check_exit_code=[0, 255])
        props['target_portal'] = location2
        props['target_iqn'] = iqn2
        mock_iscsiadm.assert_any_call(props, ('--login',),
                                      check_exit_code=[0, 255])

        lun1, lun2 = connection_properties['data']['target_luns']
        mock_get_htcls.assert_called_once_with([(location1, iqn1, lun1),
                                               (location2, iqn2, lun2)])

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_hosts_channels_targets_luns', return_value=[])
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    def test_connect_volume_with_multipath_connecting(
            self, mock_discover_mpath_device, mock_run_multipath,
            mock_devices,
            mock_connect, mock_portals, mock_exists, mock_scsi_wwn,
            mock_get_htcls):
        mock_scsi_wwn.return_value = test_connector.FAKE_SCSI_WWN
        location1 = '10.0.2.15:3260'
        location2 = '[2001:db8::1]:3260'
        dev_loc2 = '2001:db8::1:3260'  # udev location2
        name1 = 'volume-00000001-1'
        name2 = 'volume-00000001-2'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        fake_multipath_dev = '/dev/mapper/fake-multipath-dev'
        vol = {'id': 1, 'name': name1}
        connection_properties = self.iscsi_connection(vol, location1, iqn1)
        devs = ['/dev/disk/by-path/ip-%s-iscsi-%s-lun-1' % (location1, iqn1),
                '/dev/disk/by-path/ip-%s-iscsi-%s-lun-2' % (dev_loc2, iqn2)]
        mock_devices.return_value = devs
        mock_portals.return_value = ([location1, location2, location2],
                                     [iqn1, iqn1, iqn2])
        mock_discover_mpath_device.return_value = (
            fake_multipath_dev, test_connector.FAKE_SCSI_WWN)

        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])
        expected_result = {'multipath_id': test_connector.FAKE_SCSI_WWN,
                           'path': fake_multipath_dev, 'type': 'block',
                           'scsi_wwn': test_connector.FAKE_SCSI_WWN}
        props1 = connection_properties['data'].copy()
        props2 = connection_properties['data'].copy()
        locations = list(set([location1, location2]))  # order may change
        props1['target_portal'] = locations[0]
        props2['target_portal'] = locations[1]
        expected_calls = [mock.call(props1), mock.call(props2)]
        self.assertEqual(expected_result, result)
        mock_connect.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(len(expected_calls), mock_connect.call_count)
        lun = connection_properties['data']['target_lun']
        self.assertEqual(1, mock_get_htcls.call_count)
        # Order of elements in the list is randomized because it comes from
        # a set.
        self.assertSetEqual({(location1, iqn1, lun), (location2, iqn1, lun)},
                            set(mock_get_htcls.call_args[0][0]))

    @mock.patch('retrying.time.sleep', mock.Mock())
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    def test_connect_volume_multipath_failed_iscsi_login(
            self, mock_run_multipath, mock_devices, mock_connect, mock_portals,
            mock_exists):
        location1 = '10.0.2.15:3260'
        location2 = '10.0.3.15:3260'
        name1 = 'volume-00000001-1'
        name2 = 'volume-00000001-2'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        iqn2 = 'iqn.2010-10.org.openstack:%s' % name2
        vol = {'id': 1, 'name': name1}
        connection_properties = self.iscsi_connection(vol, location1, iqn1)
        devs = ['/dev/disk/by-path/ip-%s-iscsi-%s-lun-1' % (location1, iqn1),
                '/dev/disk/by-path/ip-%s-iscsi-%s-lun-2' % (location2, iqn2)]
        mock_devices.return_value = devs
        mock_portals.return_value = ([location1, location2, location2],
                                     [iqn1, iqn1, iqn2])

        mock_connect.return_value = False
        self.assertRaises(exception.FailedISCSITargetPortalLogin,
                          self.connector_with_multipath.connect_volume,
                          connection_properties['data'])

    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    def test_connect_volume_failed_iscsi_login(self, mock_connect):
        location1 = '10.0.2.15:3260'
        name1 = 'volume-00000001-1'
        iqn1 = 'iqn.2010-10.org.openstack:%s' % name1
        vol = {'id': 1, 'name': name1}
        connection_properties = self.iscsi_connection(vol, location1, iqn1)

        mock_connect.return_value = False
        self.assertRaises(exception.FailedISCSITargetPortalLogin,
                          self.connector.connect_volume,
                          connection_properties['data'])

    @mock.patch.object(time, 'sleep')
    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_connect_volume_with_not_found_device(self, exists_mock,
                                                  sleep_mock):
        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        vol = {'id': 1, 'name': name}
        connection_info = self.iscsi_connection(vol, location, iqn)
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector.connect_volume,
                          connection_info['data'])

    def test_get_target_portals_from_iscsiadm_output(self):
        connector = self.connector
        test_output = '''10.15.84.19:3260 iqn.1992-08.com.netapp:sn.33615311
                         10.15.85.19:3260 iqn.1992-08.com.netapp:sn.33615311'''
        res = connector._get_target_portals_from_iscsiadm_output(test_output)
        ips = ['10.15.84.19:3260', '10.15.85.19:3260']
        iqns = ['iqn.1992-08.com.netapp:sn.33615311',
                'iqn.1992-08.com.netapp:sn.33615311']
        expected = (ips, iqns)
        self.assertEqual(expected, res)

    @mock.patch.object(iscsi.ISCSIConnector, '_disconnect_connection')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_connection_devices')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'flush_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_connection',
                       return_value=None)
    def test_disconnect_volume(self, remove_mock, flush_mock, con_devs_mock,
                               discon_mock):
        # Return an ordered dicts instead of normal dict for discon_mock.assert
        con_devs_mock.return_value = collections.OrderedDict((
            (('ip1:port1', 'tgt1'), ({'sda'}, set())),
            (('ip2:port2', 'tgt2'), ({'sdb'}, {'sdc'})),
            (('ip3:port3', 'tgt3'), (set(), set()))))

        with mock.patch.object(self.connector,
                               'use_multipath') as use_mp_mock:
            self.connector.disconnect_volume(self.CON_PROPS,
                                             mock.sentinel.dev_info)

        con_devs_mock.assert_called_once_with(self.CON_PROPS)
        remove_mock.assert_called_once_with({'sda', 'sdb'}, use_mp_mock,
                                            False, mock.ANY)
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
    def test_disconnect_volume_force_failure(self, remove_mock, flush_mock,
                                             con_devs_mock, discon_mock):
        # Return an ordered dicts instead of normal dict for discon_mock.assert
        con_devs_mock.return_value = collections.OrderedDict((
            (('ip1:port1', 'tgt1'), ({'sda'}, set())),
            (('ip2:port2', 'tgt2'), ({'sdb'}, {'sdc'})),
            (('ip3:port3', 'tgt3'), (set(), set()))))

        with mock.patch.object(self.connector, 'use_multipath',
                               wraps=True) as use_mp_mock:
            self.assertRaises(exception.ExceptionChainer,
                              self.connector.disconnect_volume,
                              self.CON_PROPS, mock.sentinel.dev_info,
                              mock.sentinel.force, ignore_errors=False)

        con_devs_mock.assert_called_once_with(self.CON_PROPS)
        remove_mock.assert_called_once_with({'sda', 'sdb'}, use_mp_mock,
                                            mock.sentinel.force, mock.ANY)
        discon_mock.assert_called_once_with(
            self.CON_PROPS,
            [('ip1:port1', 'tgt1'), ('ip3:port3', 'tgt3')],
            mock.sentinel.force, mock.ANY)
        flush_mock.assert_called_once_with(mock.sentinel.mp_name)

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

        ips = ["192.168.204.82:3260,1", "192.168.204.82:3261,1"]
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
""" % (ips[0], iqns[0], ips[1], iqns[1])
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
        self.assertItemsEqual(expected, actual)

    @mock.patch.object(iscsi.ISCSIConnector, '_discover_iscsi_portals')
    def test_get_potential_paths_failure_mpath_single_target(self,
                                                             mock_discover):
        connection_properties = {
            'target_portal': '10.0.2.15:3260'
        }
        self.connector.use_multipath = True
        mock_discover.side_effect = exception.BrickException()
        self.assertRaises(exception.TargetPortalNotFound,
                          self.connector._get_potential_volume_paths,
                          connection_properties)

    @mock.patch.object(iscsi.ISCSIConnector, '_discover_iscsi_portals')
    def test_get_potential_paths_failure_mpath_multi_target(self,
                                                            mock_discover):
        connection_properties = {
            'target_portals': ['10.0.2.15:3260', '10.0.3.15:3260']
        }
        self.connector.use_multipath = True
        mock_discover.side_effect = exception.BrickException()
        self.assertRaises(exception.TargetPortalsNotFound,
                          self.connector._get_potential_volume_paths,
                          connection_properties)

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_hosts_channels_targets_luns')
    def test_rescan_iscsi_no_hctls(self, mock_get_htcls):
        mock_get_htcls.side_effect = exception.HostChannelsTargetsNotFound(
            iqns=['iqn1', 'iqn2'], found=[])
        with mock.patch.object(self.connector, '_linuxscsi') as mock_linuxscsi:
            self.connector._rescan_iscsi(mock.sentinel.input)
            mock_linuxscsi.echo_scsi_command.assert_not_called()
        mock_get_htcls.assert_called_once_with(mock.sentinel.input)

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_hosts_channels_targets_luns')
    def test_rescan_iscsi_partial_hctls(self, mock_get_htcls):
        mock_get_htcls.side_effect = exception.HostChannelsTargetsNotFound(
            iqns=['iqn1'], found=[('h', 'c', 't', 'l')])
        with mock.patch.object(self.connector, '_linuxscsi') as mock_linuxscsi:
            self.connector._rescan_iscsi(mock.sentinel.input)
            mock_linuxscsi.echo_scsi_command.assert_called_once_with(
                'h/scan', 'c t l')
        mock_get_htcls.assert_called_once_with(mock.sentinel.input)

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_hosts_channels_targets_luns')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm_bare')
    def test_rescan_iscsi_hctls(self, mock_iscsiadm, mock_get_htcls):
        mock_get_htcls.return_value = [
            ('/sys/class/iscsi_host/host4', '0', '0', '1'),
            ('/sys/class/iscsi_host/host5', '0', '0', '2'),
        ]

        with mock.patch.object(self.connector, '_linuxscsi') as mock_linuxscsi:
            self.connector._rescan_iscsi(mock.sentinel.input)
            mock_linuxscsi.echo_scsi_command.assert_has_calls((
                mock.call('/sys/class/iscsi_host/host4/scan', '0 0 1'),
                mock.call('/sys/class/iscsi_host/host5/scan', '0 0 2'),
            ))
        mock_get_htcls.assert_called_once_with(mock.sentinel.input)
        mock_iscsiadm.assert_not_called()

    @mock.patch('six.moves.builtins.open', create=True)
    @mock.patch('glob.glob')
    def test_get_hctls(self, mock_glob, mock_open):
        host4 = '/sys/class/scsi_host/host4'
        host5 = '/sys/class/scsi_host/host5'
        host6 = '/sys/class/scsi_host/host6'
        host7 = '/sys/class/scsi_host/host7'

        mock_glob.side_effect = (
            (host4 + '/device/session5/target0:1:2',
             host5 + '/device/session6/target3:4:5',
             host6 + '/device/session7/target6:7:8',
             host7 + '/device/session8/target9:10:11'),
            (host4 + '/device/session5/iscsi_session/session5/targetname',
             host5 + '/device/session6/iscsi_session/session6/targetname',
             host6 + '/device/session7/iscsi_session/session7/targetname',
             host7 + '/device/session8/iscsi_session/session8/targetname'),
        )

        mock_open.side_effect = (
            mock.mock_open(read_data='iqn0\n').return_value,
            mock.mock_open(read_data='iqn1\n').return_value,
            mock.mock_open(read_data='iqn2\n').return_value,
            mock.mock_open(read_data='iqn3\n').return_value,
        )

        ips_iqns_luns = [('ip1', 'iqn1', 'lun1'), ('ip2', 'iqn2', 'lun2')]
        result = self.connector._get_hosts_channels_targets_luns(ips_iqns_luns)
        self.assertEqual(
            [(host5, '4', '5', 'lun1'), (host6, '7', '8', 'lun2')],
            result)
        mock_glob.assert_has_calls((
            mock.call('/sys/class/scsi_host/host*/device/session*/target*'),
            mock.call('/sys/class/scsi_host/host*/device/session*/'
                      'iscsi_session/session*/targetname'),
        ))
        self.assertEqual(3, mock_open.call_count)

    @mock.patch('retrying.time.sleep', mock.Mock())
    @mock.patch('six.moves.builtins.open', create=True)
    @mock.patch('glob.glob', return_value=[])
    def test_get_hctls_not_found(self, mock_glob, mock_open):
        host4 = '/sys/class/scsi_host/host4'
        mock_glob.side_effect = [
            [(host4 + '/device/session5/target0:1:2')],
            [(host4 + '/device/session5/iscsi_session/session5/targetname')],
        ] * 3
        # Test exception on open as well as having only half of the htcls
        mock_open.side_effect = [
            mock.Mock(side_effect=Exception()),
            mock.mock_open(read_data='iqn1\n').return_value,
            mock.mock_open(read_data='iqn1\n').return_value,
        ]

        ips_iqns_luns = [('ip1', 'iqn1', 'lun1'), ('ip2', 'iqn2', 'lun2')]

        exc = self.assertRaises(
            exception.HostChannelsTargetsNotFound,
            self.connector._get_hosts_channels_targets_luns, ips_iqns_luns)

        # Verify exception contains found results
        self.assertEqual([(host4, '1', '2', 'lun1')], exc.found)
