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
import glob
import mock
import os
import testtools
import time

from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import iscsi
from os_brick.initiator import host_driver
from os_brick.initiator import linuxscsi
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests.initiator import test_connector


class ISCSIConnectorTestCase(test_connector.ConnectorTestCase):

    def setUp(self):
        super(ISCSIConnectorTestCase, self).setUp()
        self.connector = iscsi.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=False)
        self.connector_with_multipath = iscsi.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=True)

        self.mock_object(self.connector._linuxscsi, 'get_name_from_path',
                         return_value="/dev/sdb")
        self._fake_iqn = 'iqn.1234-56.foo.bar:01:23456789abc'

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
    def _test_connect_volume(self, extra_props, additional_commands,
                             transport=None, disconnect_mock=None):
        # for making sure the /dev/disk/by-path is gone
        exists_mock = mock.Mock()
        exists_mock.return_value = True
        os.path.exists = exists_mock

        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        vol = {'id': 1, 'name': name}
        connection_info = self.iscsi_connection(vol, location, iqn)
        for key, value in extra_props.items():
            connection_info['data'][key] = value
        if transport is not None:
            dev_list = self.generate_device(location, iqn, transport)
            with mock.patch.object(glob, 'glob', return_value=[dev_list]):
                device = self.connector.connect_volume(connection_info['data'])
        else:
            device = self.connector.connect_volume(connection_info['data'])

        dev_str = self.generate_device(location, iqn, transport)
        self.assertEqual(device['type'], 'block')
        self.assertEqual(device['path'], dev_str)

        self.count = 0

        def mock_exists_effect(*args, **kwargs):
            self.count = self.count + 1
            if self.count == 4:
                return False
            else:
                return True

        if disconnect_mock is None:
            disconnect_mock = mock_exists_effect

        with mock.patch.object(os.path, 'exists',
                               side_effect=disconnect_mock):
            if transport is not None:
                dev_list = self.generate_device(location, iqn, transport)
                with mock.patch.object(glob, 'glob', return_value=[dev_list]):
                    self.connector.disconnect_volume(connection_info['data'],
                                                     device)
            else:
                self.connector.disconnect_volume(connection_info['data'],
                                                 device)

            expected_commands = [
                ('iscsiadm -m node -T %s -p %s' % (iqn, location)),
                ('iscsiadm -m session'),
                ('iscsiadm -m node -T %s -p %s --login' % (iqn, location)),
                ('iscsiadm -m node -T %s -p %s --op update'
                 ' -n node.startup -v automatic' % (iqn, location)),
                ('/lib/udev/scsi_id --page 0x83 --whitelisted %s' % dev_str),
                ('blockdev --flushbufs /dev/sdb'),
                ('tee -a /sys/block/sdb/device/delete'),
                ('iscsiadm -m node -T %s -p %s --op update'
                 ' -n node.startup -v manual' % (iqn, location)),
                ('iscsiadm -m node -T %s -p %s --logout' % (iqn, location)),
                ('iscsiadm -m node -T %s -p %s --op delete' %
                 (iqn, location)), ] + additional_commands

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
        self._test_connect_volume({}, [], 'fake_transport')

    @testtools.skipUnless(os.path.exists('/dev/disk/by-path'),
                          'Test requires /dev/disk/by-path')
    def test_connect_volume_with_alternative_targets(self):
        location = '10.0.2.15:3260'
        location2 = '[2001:db8::1]:3260'
        iqn = 'iqn.2010-10.org.openstack:volume-00000001'
        iqn2 = 'iqn.2010-10.org.openstack:volume-00000001-2'
        extra_props = {'target_portals': [location, location2],
                       'target_iqns': [iqn, iqn2],
                       'target_luns': [1, 2]}
        additional_commands = [('blockdev --flushbufs /dev/sdb'),
                               ('tee -a /sys/block/sdb/device/delete'),
                               ('iscsiadm -m node -T %s -p %s --op update'
                                ' -n node.startup -v manual' %
                                (iqn2, location2)),
                               ('iscsiadm -m node -T %s -p %s --logout' %
                                (iqn2, location2)),
                               ('iscsiadm -m node -T %s -p %s --op delete' %
                                (iqn2, location2))]

        def mock_exists_effect(*args, **kwargs):
            self.count = self.count + 1
            # we have 2 targets in this test, so we need
            # to make sure we remove and detect removal
            # for both.
            if (self.count == 4 or
               self.count == 8):
                return False
            else:
                return True

        self._test_connect_volume(extra_props, additional_commands,
                                  disconnect_mock=mock_exists_effect)

    @testtools.skipUnless(os.path.exists('/dev/disk/by-path'),
                          'Test requires /dev/disk/by-path')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm')
    def test_connect_volume_with_alternative_targets_primary_error(
            self, mock_iscsiadm, mock_exists):
        location = '10.0.2.15:3260'
        location2 = '[2001:db8::1]:3260'
        dev_loc2 = '2001:db8::1:3260'  # udev location2
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        iqn2 = 'iqn.2010-10.org.openstack:%s-2' % name
        vol = {'id': 1, 'name': name}
        connection_info = self.iscsi_connection(vol, location, iqn)
        connection_info['data']['target_portals'] = [location, location2]
        connection_info['data']['target_iqns'] = [iqn, iqn2]
        connection_info['data']['target_luns'] = [1, 2]
        dev_str2 = '/dev/disk/by-path/ip-%s-iscsi-%s-lun-2' % (dev_loc2, iqn2)

        def fake_run_iscsiadm(iscsi_properties, iscsi_command, **kwargs):
            if iscsi_properties['target_portal'] == location:
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

        mock_iscsiadm.reset_mock()
        with mock.patch.object(os.path, 'exists',
                               return_value=False):
            self.connector.disconnect_volume(connection_info['data'], device)
            props = connection_info['data'].copy()
            for key in ('target_portals', 'target_iqns', 'target_luns'):
                props.pop(key, None)
            mock_iscsiadm.assert_any_call(props, ('--logout',),
                                          check_exit_code=[0, 21, 255])
            props['target_portal'] = location2
            props['target_iqn'] = iqn2
            props['target_lun'] = 2
            mock_iscsiadm.assert_any_call(props, ('--logout',),
                                          check_exit_code=[0, 21, 255])

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
        portals_mock.return_value = [[location, iqn]]

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

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'process_lun_id')
    def test_connect_volume_with_multiple_portals(
            self, mock_process_lun_id, mock_discover_mpath_device,
            mock_get_iqn, mock_run_multipath, mock_iscsi_devices,
            mock_get_device_map, mock_devices, mock_exists, mock_scsi_wwn):
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
        devs = ['/dev/disk/by-path/ip-%s-iscsi-%s-lun-1' % (location1, iqn1),
                '/dev/disk/by-path/ip-%s-iscsi-%s-lun-2' % (dev_loc2, iqn2)]
        mock_devices.return_value = devs
        mock_iscsi_devices.return_value = devs
        mock_get_iqn.return_value = [iqn1, iqn2]
        mock_discover_mpath_device.return_value = (
            fake_multipath_dev, test_connector.FAKE_SCSI_WWN)
        mock_process_lun_id.return_value = [1, 2]

        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])
        expected_result = {'multipath_id': test_connector.FAKE_SCSI_WWN,
                           'path': fake_multipath_dev, 'type': 'block',
                           'scsi_wwn': test_connector.FAKE_SCSI_WWN}
        cmd_format = 'iscsiadm -m node -T %s -p %s --%s'
        expected_commands = [cmd_format % (iqn1, location1, 'login'),
                             cmd_format % (iqn2, location2, 'login')]
        self.assertEqual(expected_result, result)
        for command in expected_commands:
            self.assertIn(command, self.cmds)

        self.cmds = []
        self.connector_with_multipath.disconnect_volume(
            connection_properties['data'], result)
        expected_commands = [cmd_format % (iqn1, location1, 'logout'),
                             cmd_format % (iqn2, location2, 'logout')]
        for command in expected_commands:
            self.assertIn(command, self.cmds)

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_iscsiadm')
    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'process_lun_id')
    def test_connect_volume_with_multiple_portals_primary_error(
            self, mock_process_lun_id, mock_discover_mpath_device,
            mock_iscsiadm, mock_get_iqn, mock_run_multipath,
            mock_iscsi_devices, mock_get_multipath_device_map,
            mock_devices, mock_exists,
            mock_scsi_wwn):
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
        mock_iscsi_devices.return_value = [dev2]
        mock_get_iqn.return_value = [iqn2]
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

        mock_iscsiadm.reset_mock()
        self.connector_with_multipath.disconnect_volume(
            connection_properties['data'], result)

        props = connection_properties['data'].copy()
        props['target_portal'] = location1
        props['target_iqn'] = iqn1
        mock_iscsiadm.assert_any_call(props, ('--logout',),
                                      check_exit_code=[0, 21, 255])
        props['target_portal'] = location2
        props['target_iqn'] = iqn2
        mock_iscsiadm.assert_any_call(props, ('--logout',),
                                      check_exit_code=[0, 21, 255])

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    @mock.patch.object(base.BaseLinuxConnector, '_discover_mpath_device')
    def test_connect_volume_with_multipath_connecting(
            self, mock_discover_mpath_device, mock_run_multipath,
            mock_iscsi_devices, mock_devices,
            mock_connect, mock_portals, mock_exists, mock_scsi_wwn):
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
        mock_iscsi_devices.return_value = devs
        mock_portals.return_value = [[location1, iqn1], [location2, iqn1],
                                     [location2, iqn2]]
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
        self.assertEqual(expected_calls, mock_connect.call_args_list)

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    def test_connect_volume_multipath_failed_iscsi_login(
            self, mock_run_multipath,
            mock_iscsi_devices, mock_devices,
            mock_connect, mock_portals, mock_exists):
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
        mock_iscsi_devices.return_value = devs
        mock_portals.return_value = [[location1, iqn1], [location2, iqn1],
                                     [location2, iqn2]]

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
        ip_iqn1 = ['10.15.84.19:3260', 'iqn.1992-08.com.netapp:sn.33615311']
        ip_iqn2 = ['10.15.85.19:3260', 'iqn.1992-08.com.netapp:sn.33615311']
        expected = [ip_iqn1, ip_iqn2]
        self.assertEqual(expected, res)

    @mock.patch.object(os, 'walk')
    def test_get_iscsi_devices(self, walk_mock):
        paths = [('ip-10.0.0.1:3260-iscsi-iqn.2013-01.ro.'
                 'com.netapp:node.netapp02-lun-0')]
        walk_mock.return_value = [(['.'], ['by-path'], paths)]
        self.assertEqual(self.connector._get_iscsi_devices(), paths)

    @mock.patch.object(os, 'walk', return_value=[])
    def test_get_iscsi_devices_with_empty_dir(self, walk_mock):
        self.assertEqual(self.connector._get_iscsi_devices(), [])

    @mock.patch.object(os.path, 'realpath')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    def test_get_multipath_iqns(self, get_iscsi_mock, realpath_mock):
        paths = [('ip-10.0.0.1:3260-iscsi-iqn.2013-01.ro.'
                  'com.netapp:node.netapp02-lun-0')]
        devpath = '/dev/disk/by-path/%s' % paths[0]
        realpath_mock.return_value = devpath
        get_iscsi_mock.return_value = paths
        mpath_map = {devpath: paths[0]}
        self.assertEqual(self.connector._get_multipath_iqns([paths[0]],
                                                            mpath_map),
                         ['iqn.2013-01.ro.com.netapp:node.netapp02'])

    @mock.patch.object(iscsi.ISCSIConnector, '_run_multipath')
    def test_get_multipath_device_map(self, multipath_mock):
        multipath_mock.return_value = [
            "Mar 17 14:32:37 | sda: No fc_host device for 'host-1'\n"
            "mpathb (36e00000000010001) dm-4 IET ,VIRTUAL-DISK\n"
            "size=1.0G features='0' hwhandler='0' wp=rw\n"
            "|-+- policy='service-time 0' prio=0 status=active\n"
            "| `- 2:0:0:1 sda 8:0 active undef running\n"
            "`-+- policy='service-time 0' prio=0 status=enabled\n"
            "  `- 3:0:0:1 sdb 8:16 active undef running\n"]
        expected = {'/dev/sda': '/dev/mapper/mpathb',
                    '/dev/sdb': '/dev/mapper/mpathb'}
        self.assertEqual(expected, self.connector._get_multipath_device_map())

    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_device_map')
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume_multipath_iscsi(
            self, exists_mock, multipath_iqn_mock, disconnect_mock,
            get_all_devices_mock, get_iscsi_devices_mock,
            rescan_iscsi_mock, get_portals_mock,
            get_multipath_device_map_mock):
        iqn1 = 'iqn.2013-01.ro.com.netapp:node.netapp01'
        iqn2 = 'iqn.2013-01.ro.com.netapp:node.netapp02'
        iqns = [iqn1, iqn2]
        portal = '10.0.0.1:3260'
        dev = ('ip-%s-iscsi-%s-lun-0' % (portal, iqn1))

        get_portals_mock.return_value = [[portal, iqn1]]
        multipath_iqn_mock.return_value = iqns
        get_all_devices_mock.return_value = [dev, '/dev/mapper/md-1']
        get_multipath_device_map_mock.return_value = {dev: '/dev/mapper/md-3'}
        get_iscsi_devices_mock.return_value = []
        fake_property = {'target_portal': portal,
                         'target_iqn': iqn1}
        self.connector._disconnect_volume_multipath_iscsi(fake_property,
                                                          'fake/multipath')
        # Target in use by other mp devices, don't disconnect
        self.assertFalse(disconnect_mock.called)

    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_device_map')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume_multipath_iscsi_other_targets(
            self, exists_mock, multipath_iqn_mock, get_multipath_map_mock,
            disconnect_mock, get_all_devices_mock, get_iscsi_devices_mock,
            rescan_iscsi_mock, get_portals_mock):
        iqn1 = 'iqn.2010-10.org.openstack:target-1'
        iqn2 = 'iqn.2010-10.org.openstack:target-2'
        portal = '10.0.0.1:3260'
        dev2 = ('ip-%s-iscsi-%s-lun-0' % (portal, iqn2))

        # Multiple targets are discovered, but only block devices for target-1
        # is deleted and target-2 is in use.
        get_portals_mock.return_value = [[portal, iqn1], [portal, iqn2]]
        multipath_iqn_mock.return_value = [iqn2, iqn2]
        get_all_devices_mock.return_value = [dev2, '/dev/mapper/md-1']
        get_multipath_map_mock.return_value = {dev2: '/dev/mapper/md-3'}
        get_iscsi_devices_mock.return_value = [dev2]
        fake_property = {'target_portal': portal,
                         'target_iqn': iqn1}
        self.connector._disconnect_volume_multipath_iscsi(fake_property,
                                                          'fake/multipath')
        # Only target-1 should be disconneced.
        disconnect_mock.assert_called_once_with(fake_property)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices',
                       return_value=[])
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices',
                       return_value=[])
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume_multipath_iscsi_without_other_mp_devices(
            self, exists_mock, disconnect_mock, get_all_devices_mock,
            get_iscsi_devices_mock, rescan_iscsi_mock,
            get_portals_mock, get_multipath_device_map_mock):
        portal = '10.0.2.15:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name

        get_portals_mock.return_value = [[portal, iqn]]
        fake_property = {'target_portal': portal,
                         'target_iqn': iqn}
        self.connector._disconnect_volume_multipath_iscsi(fake_property,
                                                          'fake/multipath')
        # Target not in use by other mp devices, disconnect
        disconnect_mock.assert_called_once_with(fake_property)

    @mock.patch.object(iscsi.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(iscsi.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(iscsi.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(iscsi.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_disconnect_volume_multipath_iscsi_with_invalid_symlink(
            self, exists_mock, disconnect_mock, get_all_devices_mock,
            get_iscsi_devices_mock, rescan_iscsi_mock,
            get_portals_mock, get_multipath_device_map_mock):
        # Simulate a broken symlink by returning False for os.path.exists(dev)
        portal = '10.0.0.1:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        dev = ('ip-%s-iscsi-%s-lun-0' % (portal, iqn))

        get_portals_mock.return_value = [[portal, iqn]]
        get_all_devices_mock.return_value = [dev, '/dev/mapper/md-1']
        get_iscsi_devices_mock.return_value = []

        fake_property = {'target_portal': portal,
                         'target_iqn': iqn}
        self.connector._disconnect_volume_multipath_iscsi(fake_property,
                                                          'fake/multipath')
        # Target not in use by other mp devices, disconnect
        disconnect_mock.assert_called_once_with(fake_property)

    def test_iscsiadm_discover_parsing(self):
        # Ensure that parsing iscsiadm discover ignores cruft.

        targets = [
            ["192.168.204.82:3260,1",
             ("iqn.2010-10.org.openstack:volume-"
              "f9b12623-6ce3-4dac-a71f-09ad4249bdd3")],
            ["192.168.204.82:3261,1",
             ("iqn.2010-10.org.openstack:volume-"
              "f9b12623-6ce3-4dac-a71f-09ad4249bdd4")]]

        # This slight wonkiness brought to you by pep8, as the actual
        # example output runs about 97 chars wide.
        sample_input = """Loading iscsi modules: done
Starting iSCSI initiator service: done
Setting up iSCSI targets: unused
%s %s
%s %s
""" % (targets[0][0], targets[0][1], targets[1][0], targets[1][1])
        out = self.connector.\
            _get_target_portals_from_iscsiadm_output(sample_input)
        self.assertEqual(out, targets)

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
