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
import platform
import sys
import tempfile
import time

import glob
import json
import mock
from oslo_concurrency import processutils as putils
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import encodeutils
import requests
import six
import testtools

from os_brick import exception
from os_brick.i18n import _LE
from os_brick.initiator import connector
from os_brick.initiator import host_driver
from os_brick.initiator import linuxfc
from os_brick.initiator import linuxrbd
from os_brick.initiator import linuxscsi
from os_brick.initiator import linuxsheepdog
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.remotefs import remotefs
from os_brick.tests import base

LOG = logging.getLogger(__name__)

MY_IP = '10.0.0.1'
FAKE_SCSI_WWN = '1234567890'


class ConnectorUtilsTestCase(base.TestCase):

    @mock.patch.object(connector.ISCSIConnector, 'get_initiator',
                       return_value='fakeinitiator')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_wwpns',
                       return_value=None)
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_wwnns',
                       return_value=None)
    @mock.patch.object(platform, 'machine', mock.Mock(return_value='s390x'))
    @mock.patch('sys.platform', 'linux2')
    def _test_brick_get_connector_properties(self, multipath,
                                             enforce_multipath,
                                             multipath_result,
                                             mock_wwnns, mock_wwpns,
                                             mock_initiator,
                                             host='fakehost'):
        props_actual = connector.get_connector_properties('sudo',
                                                          MY_IP,
                                                          multipath,
                                                          enforce_multipath,
                                                          host=host)
        os_type = 'linux2'
        platform = 's390x'
        props = {'initiator': 'fakeinitiator',
                 'host': host,
                 'ip': MY_IP,
                 'multipath': multipath_result,
                 'os_type': os_type,
                 'platform': platform}
        self.assertEqual(props, props_actual)

    def test_brick_get_connector_properties_connectors_called(self):
        """Make sure every connector is called."""

        mock_list = []
        # Make sure every connector is called
        for item in connector.connector_list:
            patched = mock.MagicMock()
            patched.platform = platform.machine()
            patched.os_type = sys.platform
            patched.__name__ = item
            patched.get_connector_properties.return_value = {}
            patcher = mock.patch(item, new=patched)
            patcher.start()
            self.addCleanup(patcher.stop)
            mock_list.append(patched)

        connector.get_connector_properties('sudo',
                                           MY_IP,
                                           True, True)

        for item in mock_list:
            assert item.get_connector_properties.called

    def test_brick_get_connector_properties(self):
        self._test_brick_get_connector_properties(False, False, False)

    @mock.patch.object(priv_rootwrap, 'execute')
    def test_brick_get_connector_properties_multipath(self, mock_execute):
        self._test_brick_get_connector_properties(True, True, True)
        mock_execute.assert_called_once_with('multipathd', 'show', 'status',
                                             run_as_root=True,
                                             root_helper='sudo')

    @mock.patch.object(priv_rootwrap, 'execute',
                       side_effect=putils.ProcessExecutionError)
    def test_brick_get_connector_properties_fallback(self, mock_execute):
        self._test_brick_get_connector_properties(True, False, False)
        mock_execute.assert_called_once_with('multipathd', 'show', 'status',
                                             run_as_root=True,
                                             root_helper='sudo')

    @mock.patch.object(priv_rootwrap, 'execute',
                       side_effect=putils.ProcessExecutionError)
    def test_brick_get_connector_properties_raise(self, mock_execute):
        self.assertRaises(putils.ProcessExecutionError,
                          self._test_brick_get_connector_properties,
                          True, True, None)

    def test_brick_connector_properties_override_hostname(self):
        override_host = 'myhostname'
        self._test_brick_get_connector_properties(False, False, False,
                                                  host=override_host)


class ConnectorTestCase(base.TestCase):

    def setUp(self):
        super(ConnectorTestCase, self).setUp()
        self.cmds = []

    def fake_execute(self, *cmd, **kwargs):
        self.cmds.append(" ".join(cmd))
        return "", None

    def fake_connection(self):
        return {
            'driver_volume_type': 'fake',
            'data': {
                'volume_id': 'fake_volume_id',
                'target_portal': 'fake_location',
                'target_iqn': 'fake_iqn',
                'target_lun': 1,
            }
        }

    def test_connect_volume(self):
        self.connector = connector.FakeConnector(None)
        device_info = self.connector.connect_volume(self.fake_connection())
        self.assertIn('type', device_info)
        self.assertIn('path', device_info)

    def test_disconnect_volume(self):
        self.connector = connector.FakeConnector(None)

    def test_get_connector_properties(self):
        with mock.patch.object(priv_rootwrap, 'execute') as mock_exec:
            mock_exec.return_value = True
            multipath = True
            enforce_multipath = True
            props = connector.BaseLinuxConnector.get_connector_properties(
                'sudo', multipath=multipath,
                enforce_multipath=enforce_multipath)

            expected_props = {'multipath': True}
            self.assertEqual(expected_props, props)

            multipath = False
            enforce_multipath = True
            props = connector.BaseLinuxConnector.get_connector_properties(
                'sudo', multipath=multipath,
                enforce_multipath=enforce_multipath)

            expected_props = {'multipath': False}
            self.assertEqual(expected_props, props)

        with mock.patch.object(priv_rootwrap, 'execute',
                               side_effect=putils.ProcessExecutionError):
            multipath = True
            enforce_multipath = True
            self.assertRaises(
                putils.ProcessExecutionError,
                connector.BaseLinuxConnector.get_connector_properties,
                'sudo', multipath=multipath,
                enforce_multipath=enforce_multipath)

    def test_factory(self):
        obj = connector.InitiatorConnector.factory('iscsi', None)
        self.assertEqual(obj.__class__.__name__, "ISCSIConnector")

        obj = connector.InitiatorConnector.factory('fibre_channel', None)
        self.assertEqual(obj.__class__.__name__, "FibreChannelConnector")

        obj = connector.InitiatorConnector.factory('fibre_channel', None,
                                                   arch='s390x')
        self.assertEqual(obj.__class__.__name__, "FibreChannelConnectorS390X")

        obj = connector.InitiatorConnector.factory('aoe', None)
        self.assertEqual(obj.__class__.__name__, "AoEConnector")

        obj = connector.InitiatorConnector.factory(
            'nfs', None, nfs_mount_point_base='/mnt/test')
        self.assertEqual(obj.__class__.__name__, "RemoteFsConnector")

        obj = connector.InitiatorConnector.factory(
            'glusterfs', None, glusterfs_mount_point_base='/mnt/test')
        self.assertEqual(obj.__class__.__name__, "RemoteFsConnector")

        obj = connector.InitiatorConnector.factory(
            'scality', None, scality_mount_point_base='/mnt/test')
        self.assertEqual(obj.__class__.__name__, "RemoteFsConnector")

        obj = connector.InitiatorConnector.factory('local', None)
        self.assertEqual(obj.__class__.__name__, "LocalConnector")

        obj = connector.InitiatorConnector.factory('huaweisdshypervisor', None)
        self.assertEqual(obj.__class__.__name__, "HuaweiStorHyperConnector")

        obj = connector.InitiatorConnector.factory("scaleio", None)
        self.assertEqual("ScaleIOConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            'quobyte', None, quobyte_mount_point_base='/mnt/test')
        self.assertEqual(obj.__class__.__name__, "RemoteFsConnector")

        obj = connector.InitiatorConnector.factory("disco", None)
        self.assertEqual("DISCOConnector", obj.__class__.__name__)

        self.assertRaises(ValueError,
                          connector.InitiatorConnector.factory,
                          "bogus", None)

    def test_check_valid_device_with_wrong_path(self):
        self.connector = connector.FakeConnector(None)
        self.connector._execute = \
            lambda *args, **kwargs: ("", None)
        self.assertFalse(self.connector.check_valid_device('/d0v'))

    def test_check_valid_device(self):
        self.connector = connector.FakeConnector(None)
        self.connector._execute = \
            lambda *args, **kwargs: ("", "")
        self.assertTrue(self.connector.check_valid_device('/dev'))

    def test_check_valid_device_with_cmd_error(self):
        def raise_except(*args, **kwargs):
            raise putils.ProcessExecutionError
        self.connector = connector.FakeConnector(None)
        with mock.patch.object(self.connector, '_execute',
                               side_effect=putils.ProcessExecutionError):
            self.assertFalse(self.connector.check_valid_device('/dev'))


class ISCSIConnectorTestCase(ConnectorTestCase):

    def setUp(self):
        super(ISCSIConnectorTestCase, self).setUp()
        self.connector = connector.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=False)
        self.connector_with_multipath = connector.ISCSIConnector(
            None, execute=self.fake_execute, use_multipath=True)

        mock.patch.object(self.connector._linuxscsi, 'get_name_from_path',
                          return_value="/dev/sdb").start()
        self.addCleanup(mock.patch.stopall)
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
            props = connector.ISCSIConnector.get_connector_properties(
                'sudo', multipath=multipath,
                enforce_multipath=enforce_multipath)

            expected_props = {'initiator': self._fake_iqn}
            self.assertEqual(expected_props, props)

    @mock.patch.object(connector.ISCSIConnector, '_run_iscsiadm_bare')
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
    @mock.patch.object(connector.ISCSIConnector, '_get_potential_volume_paths')
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
        mock_multipath_device.return_value = FAKE_SCSI_WWN
        (result_path, result_mpath_id) = (
            self.connector_with_multipath._discover_mpath_device(
                FAKE_SCSI_WWN,
                connection_properties['data'],
                fake_raw_dev))
        result = {'path': result_path, 'multipath_id': result_mpath_id}
        expected_result = {'path': fake_multipath_dev,
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
            LOG.debug("self.cmds = %s", self.cmds)
            LOG.debug("expected = %s", expected_commands)

            self.assertEqual(expected_commands, self.cmds)

    @testtools.skipUnless(os.path.exists('/dev/disk/by-path'),
                          'Test requires /dev/disk/by-path')
    def test_connect_volume(self):
        self._test_connect_volume({}, [])

    @testtools.skipUnless(os.path.exists('/dev/disk/by-path'),
                          'Test requires /dev/disk/by-path')
    @mock.patch.object(connector.ISCSIConnector, '_get_transport')
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
    @mock.patch.object(connector.ISCSIConnector, '_run_iscsiadm')
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
    @mock.patch.object(connector.ISCSIConnector, '_run_iscsiadm_bare')
    @mock.patch.object(connector.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(connector.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(connector.BaseLinuxConnector, '_discover_mpath_device')
    def test_connect_volume_with_multipath(
            self, mock_discover_mpath_device, exists_mock,
            rescan_multipath_mock, rescan_iscsi_mock, connect_to_mock,
            portals_mock, iscsiadm_mock, mock_iscsi_wwn):
        mock_iscsi_wwn.return_value = FAKE_SCSI_WWN
        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        iqn = 'iqn.2010-10.org.openstack:%s' % name
        vol = {'id': 1, 'name': name}
        connection_properties = self.iscsi_connection(vol, location, iqn)
        mock_discover_mpath_device.return_value = (
            'iqn.2010-10.org.openstack:%s' % name, FAKE_SCSI_WWN)

        self.connector_with_multipath = \
            connector.ISCSIConnector(None, use_multipath=True)
        iscsiadm_mock.return_value = "%s %s" % (location, iqn)
        portals_mock.return_value = [[location, iqn]]

        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])
        expected_result = {'multipath_id': FAKE_SCSI_WWN,
                           'path': 'iqn.2010-10.org.openstack:volume-00000001',
                           'type': 'block',
                           'scsi_wwn': FAKE_SCSI_WWN}
        self.assertEqual(expected_result, result)

    @mock.patch.object(connector.ISCSIConnector,
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
        self.connector_with_multipath = connector.ISCSIConnector(
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
            'iscsiadm -m discoverydb -t sendtargets -p %s --op new' %
            location,
            'iscsiadm -m discoverydb -t sendtargets -p %s --discover' %
            location]
        self.assertEqual(expected_cmds, self.cmds)

        self.assertRaises(exception.TargetPortalNotFound,
                          self.connector_with_multipath.connect_volume,
                          connection_properties['data'])

    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(connector.ISCSIConnector, '_run_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(connector.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'process_lun_id')
    def test_connect_volume_with_multiple_portals(
            self, mock_process_lun_id, mock_discover_mpath_device,
            mock_get_iqn, mock_run_multipath, mock_iscsi_devices,
            mock_get_device_map, mock_devices, mock_exists, mock_scsi_wwn):
        mock_scsi_wwn.return_value = FAKE_SCSI_WWN
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
        mock_discover_mpath_device.return_value = (fake_multipath_dev,
                                                   FAKE_SCSI_WWN)
        mock_process_lun_id.return_value = [1, 2]

        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])
        expected_result = {'multipath_id': FAKE_SCSI_WWN,
                           'path': fake_multipath_dev, 'type': 'block',
                           'scsi_wwn': FAKE_SCSI_WWN}
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
    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_run_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(connector.ISCSIConnector, '_run_iscsiadm')
    @mock.patch.object(connector.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'process_lun_id')
    def test_connect_volume_with_multiple_portals_primary_error(
            self, mock_process_lun_id, mock_discover_mpath_device,
            mock_iscsiadm, mock_get_iqn, mock_run_multipath,
            mock_rescan_multipath, mock_iscsi_devices,
            mock_get_multipath_device_map, mock_devices, mock_exists,
            mock_scsi_wwn):
        mock_scsi_wwn.return_value = FAKE_SCSI_WWN
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

        mock_discover_mpath_device.return_value = (fake_multipath_dev,
                                                   FAKE_SCSI_WWN)
        mock_process_lun_id.return_value = [1, 2]

        props = connection_properties['data'].copy()
        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])

        expected_result = {'multipath_id': FAKE_SCSI_WWN,
                           'path': fake_multipath_dev, 'type': 'block',
                           'scsi_wwn': FAKE_SCSI_WWN}
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
    @mock.patch.object(connector.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(connector.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_run_multipath')
    @mock.patch.object(connector.BaseLinuxConnector, '_discover_mpath_device')
    def test_connect_volume_with_multipath_connecting(
            self, mock_discover_mpath_device, mock_run_multipath,
            mock_rescan_multipath, mock_iscsi_devices, mock_devices,
            mock_connect, mock_portals, mock_exists, mock_scsi_wwn):
        mock_scsi_wwn.return_value = FAKE_SCSI_WWN
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
        mock_discover_mpath_device.return_value = (fake_multipath_dev,
                                                   FAKE_SCSI_WWN)

        result = self.connector_with_multipath.connect_volume(
            connection_properties['data'])
        expected_result = {'multipath_id': FAKE_SCSI_WWN,
                           'path': fake_multipath_dev, 'type': 'block',
                           'scsi_wwn': FAKE_SCSI_WWN}
        props1 = connection_properties['data'].copy()
        props2 = connection_properties['data'].copy()
        locations = list(set([location1, location2]))  # order may change
        props1['target_portal'] = locations[0]
        props2['target_portal'] = locations[1]
        expected_calls = [mock.call(props1), mock.call(props2)]
        self.assertEqual(expected_result, result)
        self.assertEqual(expected_calls, mock_connect.call_args_list)

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(connector.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(connector.ISCSIConnector, '_connect_to_iscsi_portal')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_run_multipath')
    def test_connect_volume_multipath_failed_iscsi_login(
            self, mock_run_multipath, mock_rescan_multipath,
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

    @mock.patch.object(connector.ISCSIConnector, '_connect_to_iscsi_portal')
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
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
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

    @mock.patch.object(connector.ISCSIConnector, '_run_multipath')
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

    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_device_map')
    @mock.patch.object(connector.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(connector.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume_multipath_iscsi(
            self, exists_mock, multipath_iqn_mock, disconnect_mock,
            get_all_devices_mock, get_iscsi_devices_mock,
            rescan_multipath_mock, rescan_iscsi_mock, get_portals_mock,
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

    @mock.patch.object(connector.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(connector.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_device_map')
    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_iqns')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume_multipath_iscsi_other_targets(
            self, exists_mock, multipath_iqn_mock, get_multipath_map_mock,
            disconnect_mock, get_all_devices_mock, get_iscsi_devices_mock,
            rescan_multipath_mock, rescan_iscsi_mock, get_portals_mock):
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

    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(connector.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices',
                       return_value=[])
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices',
                       return_value=[])
    @mock.patch.object(connector.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume_multipath_iscsi_without_other_mp_devices(
            self, exists_mock, disconnect_mock, get_all_devices_mock,
            get_iscsi_devices_mock, rescan_multipath_mock, rescan_iscsi_mock,
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

    @mock.patch.object(connector.ISCSIConnector, '_get_multipath_device_map',
                       return_value={})
    @mock.patch.object(connector.ISCSIConnector,
                       '_get_target_portals_from_iscsiadm_output')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_iscsi')
    @mock.patch.object(connector.ISCSIConnector, '_rescan_multipath')
    @mock.patch.object(connector.ISCSIConnector, '_get_iscsi_devices')
    @mock.patch.object(host_driver.HostDriver, 'get_all_block_devices')
    @mock.patch.object(connector.ISCSIConnector,
                       '_disconnect_from_iscsi_portal')
    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_disconnect_volume_multipath_iscsi_with_invalid_symlink(
            self, exists_mock, disconnect_mock, get_all_devices_mock,
            get_iscsi_devices_mock, rescan_multipath_mock, rescan_iscsi_mock,
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
        with mock.patch.object(connector.LOG, 'debug',
                               side_effect=fake_debug) as debug_mock:
            self.connector._iscsiadm_update(iscsi_properties,
                                            'node.session.auth.password',
                                            'scrubme')

            # we don't care what the log message is, we just want to make sure
            # our stub method is called which asserts the password is scrubbed
            self.assertTrue(debug_mock.called)

    @mock.patch.object(connector.ISCSIConnector, 'get_volume_paths')
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
    @mock.patch.object(connector.ISCSIConnector, 'get_volume_paths')
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

    @mock.patch.object(connector.ISCSIConnector, '_discover_iscsi_portals')
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

    @mock.patch.object(connector.ISCSIConnector, '_discover_iscsi_portals')
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


class FibreChannelConnectorTestCase(ConnectorTestCase):
    def setUp(self):
        super(FibreChannelConnectorTestCase, self).setUp()
        self.connector = connector.FibreChannelConnector(
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

    def fake_get_fc_hbas_info(self):
        hbas = self.fake_get_fc_hbas()
        info = [{'port_name': hbas[0]['port_name'].replace('0x', ''),
                 'node_name': hbas[0]['node_name'].replace('0x', ''),
                 'host_device': hbas[0]['ClassDevice'],
                 'device_path': hbas[0]['ClassDevicePath']}]
        return info

    def fibrechan_connection(self, volume, location, wwn):
        return {'driver_volume_type': 'fibrechan',
                'data': {
                    'volume_id': volume['id'],
                    'target_portal': location,
                    'target_wwn': wwn,
                    'target_lun': 1,
                }}

    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    def test_get_connector_properties(self, mock_hbas):
        mock_hbas.return_value = self.fake_get_fc_hbas()
        multipath = True
        enforce_multipath = True
        props = connector.FibreChannelConnector.get_connector_properties(
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
        pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:05:00.3", pci_num)

        hba = {'device_path': "/sys/devices/pci0000:00/0000:00:03.0"
                              "/0000:05:00.3/0000:06:00.6/host2/fc_host/host2"}
        pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:06:00.6", pci_num)

        hba = {'device_path': "/sys/devices/pci0000:20/0000:20:03.0"
                              "/0000:21:00.2/net/ens2f2/ctlr_2/host3"
                              "/fc_host/host3"}
        pci_num = self.connector._get_pci_num(hba)
        self.assertEqual("0000:21:00.2", pci_num)

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
        volume_paths = self.connector.get_volume_paths(
            connection_info['data'])

        expected = ['/dev/disk/by-path/pci-0000:05:00.2'
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
    def test_connect_volume(self, get_device_info_mock,
                            get_scsi_wwn_mock,
                            remove_device_mock,
                            get_fc_hbas_info_mock,
                            get_fc_hbas_mock,
                            realpath_mock,
                            exists_mock,
                            wait_for_rw_mock):
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
        wwns = ['1234567890123456', six.text_type('1234567890123456'),
                ['1234567890123456', '1234567890123457']]
        for wwn in wwns:
            connection_info = self.fibrechan_connection(vol, location, wwn)
            dev_info = self.connector.connect_volume(connection_info['data'])
            exp_wwn = wwn[0] if isinstance(wwn, list) else wwn
            dev_str = ('/dev/disk/by-path/pci-0000:05:00.2-fc-0x%s-lun-1' %
                       exp_wwn)
            self.assertEqual(dev_info['type'], 'block')
            self.assertEqual(dev_info['path'], dev_str)
            self.assertTrue('multipath_id' not in dev_info)
            self.assertTrue('devices' not in dev_info)

            self.connector.disconnect_volume(connection_info['data'], dev_info)
            expected_commands = []
            self.assertEqual(expected_commands, self.cmds)

        # Should not work for anything other than string, unicode, and list
        connection_info = self.fibrechan_connection(vol, location, 123)
        self.assertRaises(exception.NoFibreChannelHostsFound,
                          self.connector.connect_volume,
                          connection_info['data'])

        get_fc_hbas_mock.side_effect = [[]]
        get_fc_hbas_info_mock.side_effect = [[]]
        self.assertRaises(exception.NoFibreChannelHostsFound,
                          self.connector.connect_volume,
                          connection_info['data'])

    def _test_connect_volume_multipath(self, get_device_info_mock,
                                       get_scsi_wwn_mock,
                                       remove_device_mock,
                                       get_fc_hbas_info_mock,
                                       get_fc_hbas_mock,
                                       realpath_mock,
                                       exists_mock,
                                       wait_for_rw_mock,
                                       find_mp_dev_mock,
                                       access_mode,
                                       should_wait_for_rw):
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
                                'id': 0, 'lun': 1}]}
        get_device_info_mock.return_value = devices['devices'][0]
        get_scsi_wwn_mock.return_value = wwn

        location = '10.0.2.15:3260'
        name = 'volume-00000001'
        vol = {'id': 1, 'name': name}
        initiator_wwn = ['1234567890123456', '1234567890123457']

        find_mp_dev_mock.return_value = '/dev/disk/by-id/dm-uuid-mpath-' + wwn

        connection_info = self.fibrechan_connection(vol, location,
                                                    initiator_wwn)
        connection_info['data']['access_mode'] = access_mode

        self.connector.connect_volume(connection_info['data'])

        self.assertEqual(should_wait_for_rw, wait_for_rw_mock.called)
        return connection_info

    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    def test_connect_volume_multipath_rw(self, get_device_info_mock,
                                         get_scsi_wwn_mock,
                                         remove_device_mock,
                                         get_fc_hbas_info_mock,
                                         get_fc_hbas_mock,
                                         realpath_mock,
                                         exists_mock,
                                         wait_for_rw_mock,
                                         find_mp_dev_mock):

        self._test_connect_volume_multipath(get_device_info_mock,
                                            get_scsi_wwn_mock,
                                            remove_device_mock,
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
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    def test_connect_volume_multipath_no_access_mode(self,
                                                     get_device_info_mock,
                                                     get_scsi_wwn_mock,
                                                     remove_device_mock,
                                                     get_fc_hbas_info_mock,
                                                     get_fc_hbas_mock,
                                                     realpath_mock,
                                                     exists_mock,
                                                     wait_for_rw_mock,
                                                     find_mp_dev_mock):

        self._test_connect_volume_multipath(get_device_info_mock,
                                            get_scsi_wwn_mock,
                                            remove_device_mock,
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
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    def test_connect_volume_multipath_ro(self, get_device_info_mock,
                                         get_scsi_wwn_mock,
                                         remove_device_mock,
                                         get_fc_hbas_info_mock,
                                         get_fc_hbas_mock,
                                         realpath_mock,
                                         exists_mock,
                                         wait_for_rw_mock,
                                         find_mp_dev_mock):

        self._test_connect_volume_multipath(get_device_info_mock,
                                            get_scsi_wwn_mock,
                                            remove_device_mock,
                                            get_fc_hbas_info_mock,
                                            get_fc_hbas_mock,
                                            realpath_mock,
                                            exists_mock,
                                            wait_for_rw_mock,
                                            find_mp_dev_mock,
                                            'ro',
                                            False)

    @mock.patch.object(connector.BaseLinuxConnector, '_discover_mpath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'find_multipath_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'wait_for_rw')
    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(os.path, 'realpath', return_value='/dev/sdb')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas')
    @mock.patch.object(linuxfc.LinuxFibreChannel, 'get_fc_hbas_info')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'remove_scsi_device')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_scsi_wwn')
    @mock.patch.object(linuxscsi.LinuxSCSI, 'get_device_info')
    def test_connect_volume_multipath_not_found(self,
                                                get_device_info_mock,
                                                get_scsi_wwn_mock,
                                                remove_device_mock,
                                                get_fc_hbas_info_mock,
                                                get_fc_hbas_mock,
                                                realpath_mock,
                                                exists_mock,
                                                wait_for_rw_mock,
                                                find_mp_dev_mock,
                                                discover_mp_dev_mock):
        discover_mp_dev_mock.return_value = ("/dev/disk/by-path/something",
                                             None)

        connection_info = self._test_connect_volume_multipath(
            get_device_info_mock, get_scsi_wwn_mock, remove_device_mock,
            get_fc_hbas_info_mock, get_fc_hbas_mock, realpath_mock,
            exists_mock, wait_for_rw_mock, find_mp_dev_mock,
            'rw', False)

        self.assertNotIn('multipathd_id', connection_info['data'])

    @mock.patch.object(connector.FibreChannelConnector, 'get_volume_paths')
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
    @mock.patch.object(connector.FibreChannelConnector, 'get_volume_paths')
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
        self.assertItemsEqual(expected, actual)


class FibreChannelConnectorS390XTestCase(ConnectorTestCase):

    def setUp(self):
        super(FibreChannelConnectorS390XTestCase, self).setUp()
        self.connector = connector.FibreChannelConnectorS390X(
            None, execute=self.fake_execute, use_multipath=False)
        self.assertIsNotNone(self.connector)
        self.assertIsNotNone(self.connector._linuxfc)
        self.assertEqual(self.connector._linuxfc.__class__.__name__,
                         "LinuxFibreChannelS390X")
        self.assertIsNotNone(self.connector._linuxscsi)

    @mock.patch.object(linuxfc.LinuxFibreChannelS390X, 'configure_scsi_device')
    def test_get_host_devices(self, mock_configure_scsi_device):
        lun = 2
        possible_devs = [(3, 5), ]
        devices = self.connector._get_host_devices(possible_devs, lun)
        mock_configure_scsi_device.assert_called_with(3, 5,
                                                      "0x0002000000000000")
        self.assertEqual(1, len(devices))
        device_path = "/dev/disk/by-path/ccw-3-zfcp-5:0x0002000000000000"
        self.assertEqual(devices[0], device_path)

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

    @mock.patch.object(connector.FibreChannelConnectorS390X,
                       '_get_possible_devices', return_value=[(3, 5), ])
    @mock.patch.object(linuxfc.LinuxFibreChannelS390X, 'get_fc_hbas_info',
                       return_value=[])
    @mock.patch.object(linuxfc.LinuxFibreChannelS390X,
                       'deconfigure_scsi_device')
    def test_remove_devices(self, mock_deconfigure_scsi_device,
                            mock_get_fc_hbas_info, mock_get_possible_devices):
        connection_properties = {'target_wwn': 5, 'target_lun': 2}
        self.connector._remove_devices(connection_properties, devices=None)
        mock_deconfigure_scsi_device.assert_called_with(3, 5,
                                                        "0x0002000000000000")
        mock_get_fc_hbas_info.assert_called_once_with()
        mock_get_possible_devices.assert_called_once_with([], 5)


class FakeFixedIntervalLoopingCall(object):
    def __init__(self, f=None, *args, **kw):
        self.args = args
        self.kw = kw
        self.f = f
        self._stop = False

    def stop(self):
        self._stop = True

    def wait(self):
        return self

    def start(self, interval, initial_delay=None):
        while not self._stop:
            try:
                self.f(*self.args, **self.kw)
            except loopingcall.LoopingCallDone:
                return self
            except Exception:
                LOG.exception(_LE('in fixed duration looping call'))
                raise


class AoEConnectorTestCase(ConnectorTestCase):
    """Test cases for AoE initiator class."""
    def setUp(self):
        super(AoEConnectorTestCase, self).setUp()
        self.connector = connector.AoEConnector('sudo')
        self.connection_properties = {'target_shelf': 'fake_shelf',
                                      'target_lun': 'fake_lun'}
        mock.patch.object(loopingcall, 'FixedIntervalLoopingCall',
                          FakeFixedIntervalLoopingCall).start()
        self.addCleanup(mock.patch.stopall)

    def test_get_search_path(self):
        expected = "/dev/etherd"
        actual_path = self.connector.get_search_path()
        self.assertEqual(expected, actual_path)

    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_get_volume_paths(self, mock_exists):
        expected = ["/dev/etherd/efake_shelf.fake_lun"]
        paths = self.connector.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, paths)

    def test_get_connector_properties(self):
        props = connector.AoEConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    @mock.patch.object(os.path, 'exists', side_effect=[True, True])
    def test_connect_volume(self, exists_mock):
        """Ensure that if path exist aoe-revalidate was called."""
        aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)
        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            self.connector.connect_volume(self.connection_properties)

    @mock.patch.object(os.path, 'exists', side_effect=[False, True])
    def test_connect_volume_without_path(self, exists_mock):
        """Ensure that if path doesn't exist aoe-discovery was called."""

        aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)
        expected_info = {
            'type': 'block',
            'device': aoe_device,
            'path': aoe_path,
        }

        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            volume_info = self.connector.connect_volume(
                self.connection_properties)

        self.assertDictMatch(volume_info, expected_info)

    @mock.patch.object(os.path, 'exists', return_value=False)
    def test_connect_volume_could_not_discover_path(self, exists_mock):
        _aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)

        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            self.assertRaises(exception.VolumeDeviceNotFound,
                              self.connector.connect_volume,
                              self.connection_properties)

    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_disconnect_volume(self, mock_exists):
        """Ensure that if path exist aoe-revaliadte was called."""
        aoe_device, aoe_path = self.connector._get_aoe_info(
            self.connection_properties)

        with mock.patch.object(self.connector, '_execute',
                               return_value=["", ""]):
            self.connector.disconnect_volume(self.connection_properties, {})

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.connection_properties)


class RemoteFsConnectorTestCase(ConnectorTestCase):
    """Test cases for Remote FS initiator class."""
    TEST_DEV = '172.18.194.100:/var/nfs'
    TEST_PATH = '/mnt/test/df0808229363aad55c27da50c38d6328'
    TEST_BASE = '/mnt/test'
    TEST_NAME = '9c592d52-ce47-4263-8c21-4ecf3c029cdb'

    def setUp(self):
        super(RemoteFsConnectorTestCase, self).setUp()
        self.connection_properties = {
            'export': self.TEST_DEV,
            'name': self.TEST_NAME}
        self.connector = connector.RemoteFsConnector(
            'nfs', root_helper='sudo',
            nfs_mount_point_base=self.TEST_BASE,
            nfs_mount_options='vers=3')

    @mock.patch('os_brick.remotefs.remotefs.ScalityRemoteFsClient')
    def test_init_with_scality(self, mock_scality_remotefs_client):
        connector.RemoteFsConnector('scality', root_helper='sudo')
        self.assertEqual(1, mock_scality_remotefs_client.call_count)

    def test_get_connector_properties(self):
        props = connector.RemoteFsConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        expected = self.TEST_BASE
        actual = self.connector.get_search_path()
        self.assertEqual(expected, actual)

    @mock.patch.object(remotefs.RemoteFsClient, 'mount')
    def test_get_volume_paths(self, mock_mount):
        path = ("%(path)s/%(name)s" % {'path': self.TEST_PATH,
                                       'name': self.TEST_NAME})
        expected = [path]
        actual = self.connector.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, actual)

    @mock.patch.object(remotefs.RemoteFsClient, 'mount')
    @mock.patch.object(remotefs.RemoteFsClient, 'get_mount_point',
                       return_value="something")
    def test_connect_volume(self, mount_point_mock, mount_mock):
        """Test the basic connect volume case."""
        self.connector.connect_volume(self.connection_properties)

    def test_disconnect_volume(self):
        """Nothing should happen here -- make sure it doesn't blow up."""
        self.connector.disconnect_volume(self.connection_properties, {})

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.connection_properties)


class LocalConnectorTestCase(ConnectorTestCase):

    def setUp(self):
        super(LocalConnectorTestCase, self).setUp()
        self.connection_properties = {'name': 'foo',
                                      'device_path': '/tmp/bar'}
        self.connector = connector.LocalConnector(None)

    def test_get_connector_properties(self):
        props = connector.LocalConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        actual = self.connector.get_search_path()
        self.assertIsNone(actual)

    def test_get_volume_paths(self):
        expected = [self.connection_properties['device_path']]
        actual = self.connector.get_volume_paths(
            self.connection_properties)
        self.assertEqual(expected, actual)

    def test_connect_volume(self):
        cprops = self.connection_properties
        dev_info = self.connector.connect_volume(cprops)
        self.assertEqual(dev_info['type'], 'local')
        self.assertEqual(dev_info['path'], cprops['device_path'])

    def test_connect_volume_with_invalid_connection_data(self):
        cprops = {}
        self.assertRaises(ValueError,
                          self.connector.connect_volume, cprops)

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.connection_properties)


class HuaweiStorHyperConnectorTestCase(ConnectorTestCase):
    """Test cases for StorHyper initiator class."""

    attached = False

    def setUp(self):
        super(HuaweiStorHyperConnectorTestCase, self).setUp()
        self.fake_sdscli_file = tempfile.mktemp()
        self.addCleanup(os.remove, self.fake_sdscli_file)
        newefile = open(self.fake_sdscli_file, 'w')
        newefile.write('test')
        newefile.close()

        self.connector = connector.HuaweiStorHyperConnector(
            None, execute=self.fake_execute)
        self.connector.cli_path = self.fake_sdscli_file
        self.connector.iscliexist = True

        self.connector_fail = connector.HuaweiStorHyperConnector(
            None, execute=self.fake_execute_fail)
        self.connector_fail.cli_path = self.fake_sdscli_file
        self.connector_fail.iscliexist = True

        self.connector_nocli = connector.HuaweiStorHyperConnector(
            None, execute=self.fake_execute_fail)
        self.connector_nocli.cli_path = self.fake_sdscli_file
        self.connector_nocli.iscliexist = False

        self.connection_properties = {
            'access_mode': 'rw',
            'qos_specs': None,
            'volume_id': 'volume-b2911673-863c-4380-a5f2-e1729eecfe3f'
        }

        self.device_info = {'type': 'block',
                            'path': '/dev/vdxxx'}
        HuaweiStorHyperConnectorTestCase.attached = False

    def fake_execute(self, *cmd, **kwargs):
        method = cmd[2]
        self.cmds.append(" ".join(cmd))
        if 'attach' == method:
            HuaweiStorHyperConnectorTestCase.attached = True
            return 'ret_code=0', None
        if 'querydev' == method:
            if HuaweiStorHyperConnectorTestCase.attached:
                return 'ret_code=0\ndev_addr=/dev/vdxxx', None
            else:
                return 'ret_code=1\ndev_addr=/dev/vdxxx', None
        if 'detach' == method:
            HuaweiStorHyperConnectorTestCase.attached = False
            return 'ret_code=0', None

    def fake_execute_fail(self, *cmd, **kwargs):
        method = cmd[2]
        self.cmds.append(" ".join(cmd))
        if 'attach' == method:
            HuaweiStorHyperConnectorTestCase.attached = False
            return 'ret_code=330151401', None
        if 'querydev' == method:
            if HuaweiStorHyperConnectorTestCase.attached:
                return 'ret_code=0\ndev_addr=/dev/vdxxx', None
            else:
                return 'ret_code=1\ndev_addr=/dev/vdxxx', None
        if 'detach' == method:
            HuaweiStorHyperConnectorTestCase.attached = True
            return 'ret_code=330155007', None

    def test_get_connector_properties(self):
        props = connector.HuaweiStorHyperConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        actual = self.connector.get_search_path()
        self.assertIsNone(actual)

    @mock.patch.object(connector.HuaweiStorHyperConnector,
                       '_query_attached_volume')
    def test_get_volume_paths(self, mock_query_attached):
        path = self.device_info['path']
        mock_query_attached.return_value = {'ret_code': 0,
                                            'dev_addr': path}

        expected = [path]
        actual = self.connector.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, actual)

    def test_connect_volume(self):
        """Test the basic connect volume case."""

        retval = self.connector.connect_volume(self.connection_properties)
        self.assertEqual(self.device_info, retval)

        expected_commands = [self.fake_sdscli_file + ' -c attach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c querydev'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f']
        LOG.debug("self.cmds = %s." % self.cmds)
        LOG.debug("expected = %s." % expected_commands)

        self.assertEqual(expected_commands, self.cmds)

    def test_disconnect_volume(self):
        """Test the basic disconnect volume case."""
        self.connector.connect_volume(self.connection_properties)
        self.assertEqual(True, HuaweiStorHyperConnectorTestCase.attached)
        self.connector.disconnect_volume(self.connection_properties,
                                         self.device_info)
        self.assertEqual(False, HuaweiStorHyperConnectorTestCase.attached)

        expected_commands = [self.fake_sdscli_file + ' -c attach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c querydev'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c detach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f']

        LOG.debug("self.cmds = %s." % self.cmds)
        LOG.debug("expected = %s." % expected_commands)

        self.assertEqual(expected_commands, self.cmds)

    def test_is_volume_connected(self):
        """Test if volume connected to host case."""
        self.connector.connect_volume(self.connection_properties)
        self.assertEqual(True, HuaweiStorHyperConnectorTestCase.attached)
        is_connected = self.connector.is_volume_connected(
            'volume-b2911673-863c-4380-a5f2-e1729eecfe3f')
        self.assertEqual(HuaweiStorHyperConnectorTestCase.attached,
                         is_connected)
        self.connector.disconnect_volume(self.connection_properties,
                                         self.device_info)
        self.assertEqual(False, HuaweiStorHyperConnectorTestCase.attached)
        is_connected = self.connector.is_volume_connected(
            'volume-b2911673-863c-4380-a5f2-e1729eecfe3f')
        self.assertEqual(HuaweiStorHyperConnectorTestCase.attached,
                         is_connected)

        expected_commands = [self.fake_sdscli_file + ' -c attach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c querydev'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c querydev'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c detach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c querydev'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f']

        LOG.debug("self.cmds = %s." % self.cmds)
        LOG.debug("expected = %s." % expected_commands)

        self.assertEqual(expected_commands, self.cmds)

    def test__analyze_output(self):
        cliout = 'ret_code=0\ndev_addr=/dev/vdxxx\nret_desc="success"'
        analyze_result = {'dev_addr': '/dev/vdxxx',
                          'ret_desc': '"success"',
                          'ret_code': '0'}
        result = self.connector._analyze_output(cliout)
        self.assertEqual(analyze_result, result)

    def test_connect_volume_fail(self):
        """Test the fail connect volume case."""
        self.assertRaises(exception.BrickException,
                          self.connector_fail.connect_volume,
                          self.connection_properties)
        expected_commands = [self.fake_sdscli_file + ' -c attach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f']
        LOG.debug("self.cmds = %s." % self.cmds)
        LOG.debug("expected = %s." % expected_commands)
        self.assertEqual(expected_commands, self.cmds)

    def test_disconnect_volume_fail(self):
        """Test the fail disconnect volume case."""
        self.connector.connect_volume(self.connection_properties)
        self.assertEqual(True, HuaweiStorHyperConnectorTestCase.attached)
        self.assertRaises(exception.BrickException,
                          self.connector_fail.disconnect_volume,
                          self.connection_properties,
                          self.device_info)

        expected_commands = [self.fake_sdscli_file + ' -c attach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c querydev'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c detach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f']

        LOG.debug("self.cmds = %s." % self.cmds)
        LOG.debug("expected = %s." % expected_commands)

        self.assertEqual(expected_commands, self.cmds)

    def test_connect_volume_nocli(self):
        """Test the fail connect volume case."""
        self.assertRaises(exception.BrickException,
                          self.connector_nocli.connect_volume,
                          self.connection_properties)

    def test_disconnect_volume_nocli(self):
        """Test the fail disconnect volume case."""
        self.connector.connect_volume(self.connection_properties)
        self.assertEqual(True, HuaweiStorHyperConnectorTestCase.attached)
        self.assertRaises(exception.BrickException,
                          self.connector_nocli.disconnect_volume,
                          self.connection_properties,
                          self.device_info)
        expected_commands = [self.fake_sdscli_file + ' -c attach'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f',
                             self.fake_sdscli_file + ' -c querydev'
                             ' -v volume-b2911673-863c-4380-a5f2-e1729eecfe3f']

        LOG.debug("self.cmds = %s." % self.cmds)
        LOG.debug("expected = %s." % expected_commands)

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.connection_properties)


class HGSTConnectorTestCase(ConnectorTestCase):
    """Test cases for HGST initiator class."""

    IP_OUTPUT = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet 169.254.169.254/32 scope link lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: em1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq master
    link/ether 00:25:90:d9:18:08 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::225:90ff:fed9:1808/64 scope link
       valid_lft forever preferred_lft forever
3: em2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state
    link/ether 00:25:90:d9:18:09 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.23/24 brd 192.168.0.255 scope global em2
       valid_lft forever preferred_lft forever
    inet6 fe80::225:90ff:fed9:1809/64 scope link
       valid_lft forever preferred_lft forever
    """

    DOMAIN_OUTPUT = """localhost"""

    DOMAIN_FAILED = """this.better.not.resolve.to.a.name.or.else"""

    SET_APPHOST_OUTPUT = """
VLVM_SET_APPHOSTS0000000395
Request Succeeded
    """

    def setUp(self):
        super(HGSTConnectorTestCase, self).setUp()
        self.connector = connector.HGSTConnector(
            None, execute=self._fake_exec)
        self._fail_set_apphosts = False
        self._fail_ip = False
        self._fail_domain_list = False

    def _fake_exec_set_apphosts(self, *cmd):
        if self._fail_set_apphosts:
            raise putils.ProcessExecutionError(None, None, 1)
        else:
            return self.SET_APPHOST_OUTPUT, ''

    def _fake_exec_ip(self, *cmd):
        if self._fail_ip:
            # Remove localhost so there is no IP match
            return self.IP_OUTPUT.replace("127.0.0.1", "x.x.x.x"), ''
        else:
            return self.IP_OUTPUT, ''

    def _fake_exec_domain_list(self, *cmd):
        if self._fail_domain_list:
            return self.DOMAIN_FAILED, ''
        else:
            return self.DOMAIN_OUTPUT, ''

    def _fake_exec(self, *cmd, **kwargs):
        self.cmdline = " ".join(cmd)
        if cmd[0] == "ip":
            return self._fake_exec_ip(*cmd)
        elif cmd[0] == "vgc-cluster":
            if cmd[1] == "domain-list":
                return self._fake_exec_domain_list(*cmd)
            elif cmd[1] == "space-set-apphosts":
                return self._fake_exec_set_apphosts(*cmd)
            else:
                return '', ''

    def test_factory(self):
        """Can we instantiate a HGSTConnector of the right kind?"""
        obj = connector.InitiatorConnector.factory('HGST', None)
        self.assertEqual("HGSTConnector", obj.__class__.__name__)

    def test_get_search_path(self):
        expected = "/dev"
        actual = self.connector.get_search_path()
        self.assertEqual(expected, actual)

    @mock.patch.object(os.path, 'exists', return_value=True)
    def test_get_volume_paths(self, mock_exists):

        cprops = {'name': 'space', 'noremovehost': 'stor1'}
        path = "/dev/%s" % cprops['name']
        expected = [path]
        actual = self.connector.get_volume_paths(cprops)
        self.assertEqual(expected, actual)

    def test_connect_volume(self):
        """Tests that a simple connection succeeds"""
        self._fail_set_apphosts = False
        self._fail_ip = False
        self._fail_domain_list = False
        cprops = {'name': 'space', 'noremovehost': 'stor1'}
        dev_info = self.connector.connect_volume(cprops)
        self.assertEqual('block', dev_info['type'])
        self.assertEqual('space', dev_info['device'])
        self.assertEqual('/dev/space', dev_info['path'])

    def test_get_connector_properties(self):
        props = connector.HGSTConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_connect_volume_nohost_fail(self):
        """This host should not be found, connect should fail."""
        self._fail_set_apphosts = False
        self._fail_ip = True
        self._fail_domain_list = False
        cprops = {'name': 'space', 'noremovehost': 'stor1'}
        self.assertRaises(exception.BrickException,
                          self.connector.connect_volume,
                          cprops)

    def test_connect_volume_nospace_fail(self):
        """The space command will fail, exception to be thrown"""
        self._fail_set_apphosts = True
        self._fail_ip = False
        self._fail_domain_list = False
        cprops = {'name': 'space', 'noremovehost': 'stor1'}
        self.assertRaises(exception.BrickException,
                          self.connector.connect_volume,
                          cprops)

    def test_disconnect_volume(self):
        """Simple disconnection should pass and disconnect me"""
        self._fail_set_apphosts = False
        self._fail_ip = False
        self._fail_domain_list = False
        self._cmdline = ""
        cprops = {'name': 'space', 'noremovehost': 'stor1'}
        self.connector.disconnect_volume(cprops, None)
        exp_cli = ("vgc-cluster space-set-apphosts -n space "
                   "-A localhost --action DELETE")
        self.assertEqual(exp_cli, self.cmdline)

    def test_disconnect_volume_nohost(self):
        """Should not run a setapphosts because localhost will"""
        """be the noremotehost"""
        self._fail_set_apphosts = False
        self._fail_ip = False
        self._fail_domain_list = False
        self._cmdline = ""
        cprops = {'name': 'space', 'noremovehost': 'localhost'}
        self.connector.disconnect_volume(cprops, None)
        # The last command should be the IP listing, not set apphosts
        exp_cli = ("ip addr list")
        self.assertEqual(exp_cli, self.cmdline)

    def test_disconnect_volume_fails(self):
        """The set-apphosts should fail, exception to be thrown"""
        self._fail_set_apphosts = True
        self._fail_ip = False
        self._fail_domain_list = False
        self._cmdline = ""
        cprops = {'name': 'space', 'noremovehost': 'stor1'}
        self.assertRaises(exception.BrickException,
                          self.connector.disconnect_volume,
                          cprops, None)

    def test_bad_connection_properties(self):
        """Send in connection_properties missing required fields"""
        # Invalid connection_properties
        self.assertRaises(exception.BrickException,
                          self.connector.connect_volume,
                          None)
        # Name required for connect_volume
        cprops = {'noremovehost': 'stor1'}
        self.assertRaises(exception.BrickException,
                          self.connector.connect_volume,
                          cprops)
        # Invalid connection_properties
        self.assertRaises(exception.BrickException,
                          self.connector.disconnect_volume,
                          None, None)
        # Name and noremovehost needed for disconnect_volume
        cprops = {'noremovehost': 'stor1'}
        self.assertRaises(exception.BrickException,
                          self.connector.disconnect_volume,
                          cprops, None)
        cprops = {'name': 'space'}
        self.assertRaises(exception.BrickException,
                          self.connector.disconnect_volume,
                          cprops, None)

    def test_extend_volume(self):
        cprops = {'name': 'space', 'noremovehost': 'stor1'}
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          cprops)


class RBDConnectorTestCase(ConnectorTestCase):

    def setUp(self):
        super(RBDConnectorTestCase, self).setUp()

        self.user = 'fake_user'
        self.pool = 'fake_pool'
        self.volume = 'fake_volume'

        self.connection_properties = {
            'auth_username': self.user,
            'name': '%s/%s' % (self.pool, self.volume),
        }

    def test_get_search_path(self):
        rbd = connector.RBDConnector(None)
        path = rbd.get_search_path()
        self.assertIsNone(path)

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    def test_get_volume_paths(self, mock_rados, mock_rbd):
        rbd = connector.RBDConnector(None)
        expected = []
        actual = rbd.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, actual)

    def test_get_connector_properties(self):
        props = connector.RBDConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    def test_connect_volume(self, mock_rados, mock_rbd):
        """Test the connect volume case."""
        rbd = connector.RBDConnector(None)
        device_info = rbd.connect_volume(self.connection_properties)

        # Ensure rados is instantiated correctly
        mock_rados.Rados.assert_called_once_with(
            rados_id=encodeutils.safe_encode(self.user),
            conffile='/etc/ceph/ceph.conf')

        # Ensure correct calls to connect to cluster
        self.assertEqual(1, mock_rados.Rados.return_value.connect.call_count)
        mock_rados.Rados.return_value.open_ioctx.assert_called_once_with(
            encodeutils.safe_encode(self.pool))

        # Ensure rbd image is instantiated correctly
        mock_rbd.Image.assert_called_once_with(
            mock_rados.Rados.return_value.open_ioctx.return_value,
            encodeutils.safe_encode(self.volume), read_only=False,
            snapshot=None)

        # Ensure expected object is returned correctly
        self.assertTrue(isinstance(device_info['path'],
                                   linuxrbd.RBDVolumeIOWrapper))

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    @mock.patch.object(linuxrbd.RBDVolumeIOWrapper, 'close')
    def test_disconnect_volume(self, volume_close, mock_rados, mock_rbd):
        """Test the disconnect volume case."""
        rbd = connector.RBDConnector(None)
        device_info = rbd.connect_volume(self.connection_properties)
        rbd.disconnect_volume(self.connection_properties, device_info)

        self.assertEqual(1, volume_close.call_count)

    def test_extend_volume(self):
        rbd = connector.RBDConnector(None)
        self.assertRaises(NotImplementedError,
                          rbd.extend_volume,
                          self.connection_properties)


class DRBDConnectorTestCase(ConnectorTestCase):

    RESOURCE_TEMPLATE = '''
        resource r0 {
            on host1 {
            }
            net {
                shared-secret "%(shared-secret)s";
            }
        }
'''

    def setUp(self):
        super(DRBDConnectorTestCase, self).setUp()

        self.connector = connector.DRBDConnector(
            None, execute=self._fake_exec)

        self.execs = []

    def _fake_exec(self, *cmd, **kwargs):
        self.execs.append(cmd)

        # out, err
        return ('', '')

    def test_get_connector_properties(self):
        props = connector.DRBDConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_connect_volume(self):
        """Test connect_volume."""

        cprop = {
            'provider_auth': 'my-secret',
            'config': self.RESOURCE_TEMPLATE,
            'name': 'my-precious',
            'device': '/dev/drbd951722',
            'data': {},
        }

        res = self.connector.connect_volume(cprop)

        self.assertEqual(cprop['device'], res['path'])
        self.assertEqual('adjust', self.execs[0][1])
        self.assertEqual(cprop['name'], self.execs[0][4])

    def test_disconnect_volume(self):
        """Test the disconnect volume case."""

        cprop = {
            'provider_auth': 'my-secret',
            'config': self.RESOURCE_TEMPLATE,
            'name': 'my-precious',
            'device': '/dev/drbd951722',
            'data': {},
        }
        dev_info = {}

        self.connector.disconnect_volume(cprop, dev_info)

        self.assertEqual('down', self.execs[0][1])

    def test_extend_volume(self):
        cprop = {'name': 'something'}
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          cprop)


class ScaleIOConnectorTestCase(ConnectorTestCase):
    """Test cases for ScaleIO connector"""
    # Fake volume information
    vol = {
        'id': 'vol1',
        'name': 'test_volume'
    }

    # Fake SDC GUID
    fake_guid = 'FAKE_GUID'

    def setUp(self):
        super(ScaleIOConnectorTestCase, self).setUp()

        self.fake_connection_properties = {
            'hostIP': MY_IP,
            'serverIP': MY_IP,
            'scaleIO_volname': self.vol['name'],
            'serverPort': 443,
            'serverUsername': 'test',
            'serverPassword': 'fake',
            'serverToken': 'fake_token',
            'iopsLimit': None,
            'bandwidthLimit': None
        }

        # Formatting string for REST API calls
        self.action_format = "instances/Volume::{}/action/{{}}".format(
            self.vol['id'])
        self.get_volume_api = 'types/Volume/instances/getByName::{}'.format(
            self.vol['name'])

        # Map of REST API calls to responses
        self.mock_calls = {
            self.get_volume_api:
                self.MockHTTPSResponse(json.dumps(self.vol['id'])),
            self.action_format.format('addMappedSdc'):
                self.MockHTTPSResponse(''),
            self.action_format.format('setMappedSdcLimits'):
                self.MockHTTPSResponse(''),
            self.action_format.format('removeMappedSdc'):
                self.MockHTTPSResponse(''),
        }

        # Default error REST response
        self.error_404 = self.MockHTTPSResponse(content=dict(
            errorCode=0,
            message='HTTP 404',
        ), status_code=404)

        # Patch the request and os calls to fake versions
        mock.patch.object(
            requests, 'get', self.handle_scaleio_request).start()
        mock.patch.object(
            requests, 'post', self.handle_scaleio_request).start()
        mock.patch.object(os.path, 'isdir', return_value=True).start()
        mock.patch.object(
            os, 'listdir', return_value=["emc-vol-{}".format(self.vol['id'])]
        ).start()
        self.addCleanup(mock.patch.stopall)

        # The actual ScaleIO connector
        self.connector = connector.ScaleIOConnector(
            'sudo', execute=self.fake_execute)

    class MockHTTPSResponse(requests.Response):
        """Mock HTTP Response

        Defines the https replies from the mocked calls to do_request()
        """
        def __init__(self, content, status_code=200):
            super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                  self).__init__()

            self._content = content
            self.encoding = 'UTF-8'
            self.status_code = status_code

        def json(self, **kwargs):
            if isinstance(self._content, six.string_types):
                return super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                             self).json(**kwargs)

            return self._content

        @property
        def text(self):
            if not isinstance(self._content, six.string_types):
                return json.dumps(self._content)

            self._content = self._content.encode('utf-8')
            return super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                         self).text

    def fake_execute(self, *cmd, **kwargs):
        """Fakes the rootwrap call"""
        return self.fake_guid, None

    def fake_missing_execute(self, *cmd, **kwargs):
        """Error when trying to call rootwrap drv_cfg"""
        raise putils.ProcessExecutionError("Test missing drv_cfg.")

    def handle_scaleio_request(self, url, *args, **kwargs):
        """Fake REST server"""
        api_call = url.split(':', 2)[2].split('/', 1)[1].replace('api/', '')

        if 'setMappedSdcLimits' in api_call:
            self.assertNotIn("iops_limit", kwargs['data'])
            if "iopsLimit" not in kwargs['data']:
                self.assertIn("bandwidthLimitInKbps",
                              kwargs['data'])
            elif "bandwidthLimitInKbps" not in kwargs['data']:
                self.assertIn("iopsLimit", kwargs['data'])
            else:
                self.assertIn("bandwidthLimitInKbps",
                              kwargs['data'])
                self.assertIn("iopsLimit", kwargs['data'])

        try:
            return self.mock_calls[api_call]
        except KeyError:
            return self.error_404

    def test_get_search_path(self):
        expected = "/dev/disk/by-id"
        actual = self.connector.get_search_path()
        self.assertEqual(expected, actual)

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(connector.ScaleIOConnector, '_wait_for_volume_path')
    def test_get_volume_paths(self, mock_wait_for_path, mock_exists):
        mock_wait_for_path.return_value = "emc-vol-vol1"
        expected = ['/dev/disk/by-id/emc-vol-vol1']
        actual = self.connector.get_volume_paths(
            self.fake_connection_properties)
        self.assertEqual(expected, actual)

    def test_get_connector_properties(self):
        props = connector.ScaleIOConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_connect_volume(self):
        """Successful connect to volume"""
        self.connector.connect_volume(self.fake_connection_properties)

    def test_connect_with_bandwidth_limit(self):
        """Successful connect to volume with bandwidth limit"""
        self.fake_connection_properties['bandwidthLimit'] = '500'
        self.test_connect_volume()

    def test_connect_with_iops_limit(self):
        """Successful connect to volume with iops limit"""
        self.fake_connection_properties['iopsLimit'] = '80'
        self.test_connect_volume()

    def test_connect_with_iops_and_bandwidth_limits(self):
        """Successful connect with iops and bandwidth limits"""
        self.fake_connection_properties['bandwidthLimit'] = '500'
        self.fake_connection_properties['iopsLimit'] = '80'
        self.test_connect_volume()

    def test_disconnect_volume(self):
        """Successful disconnect from volume"""
        self.connector.disconnect_volume(self.fake_connection_properties, None)

    def test_error_id(self):
        """Fail to connect with bad volume name"""
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            dict(errorCode='404', message='Test volume not found'), 404)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_no_volume_id(self):
        """Faile to connect with no volume id"""
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            'null', 200)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_bad_login(self):
        """Fail to connect with bad authentication"""
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            'null', 401)

        self.mock_calls['login'] = self.MockHTTPSResponse('null', 401)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_bad_drv_cfg(self):
        """Fail to connect with missing rootwrap executable"""
        self.connector.set_execute(self.fake_missing_execute)
        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_map_volume(self):
        """Fail to connect with REST API failure"""
        self.mock_calls[self.action_format.format(
            'addMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_NOT_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    @mock.patch('time.sleep')
    def test_error_path_not_found(self, sleep_mock):
        """Timeout waiting for volume to map to local file system"""
        mock.patch.object(
            os, 'listdir', return_value=["emc-vol-no-volume"]
        ).start()
        self.assertRaises(exception.BrickException, self.test_connect_volume)
        self.assertTrue(sleep_mock.called)

    def test_map_volume_already_mapped(self):
        """Ignore REST API failure for volume already mapped"""
        self.mock_calls[self.action_format.format(
            'addMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_ALREADY_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.test_connect_volume()

    def test_error_disconnect_volume(self):
        """Fail to disconnect with REST API failure"""
        self.mock_calls[self.action_format.format(
            'removeMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_ALREADY_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.assertRaises(exception.BrickException,
                          self.test_disconnect_volume)

    def test_disconnect_volume_not_mapped(self):
        """Ignore REST API failure for volume not mapped"""
        self.mock_calls[self.action_format.format(
            'removeMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_NOT_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.test_disconnect_volume()

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.fake_connection_properties)


class DISCOConnectorTestCase(ConnectorTestCase):
    """Test cases for DISCO connector."""

    # Fake volume information
    volume = {
        'name': 'a-disco-volume',
        'disco_id': '1234567'
        }

    # Conf for test
    conf = {
        'ip': MY_IP,
        'port': 9898
        }

    def setUp(self):
        super(DISCOConnectorTestCase, self).setUp()

        self.fake_connection_properties = {
            'name': self.volume['name'],
            'disco_id': self.volume['disco_id'],
            'conf': {
                'server_ip': self.conf['ip'],
                'server_port': self.conf['port']}
            }

        self.fake_volume_status = {'attached': True,
                                   'detached': False}
        self.fake_request_status = {'success': None,
                                    'fail': 'ERROR'}
        self.volume_status = 'detached'
        self.request_status = 'success'

        # Patch the request and os calls to fake versions
        mock.patch.object(connector.DISCOConnector,
                          '_send_disco_vol_cmd',
                          self.perform_disco_request).start()
        mock.patch.object(os.path,
                          'exists', self.is_volume_attached).start()
        mock.patch.object(glob,
                          'glob', self.list_disco_volume).start()
        self.addCleanup(mock.patch.stopall)

        # The actual DISCO connector
        self.connector = connector.DISCOConnector(
            'sudo', execute=self.fake_execute)

    def perform_disco_request(self, *cmd, **kwargs):
        """Fake the socket call."""
        return self.fake_request_status[self.request_status]

    def is_volume_attached(self, *cmd, **kwargs):
        """Fake volume detection check."""
        return self.fake_volume_status[self.volume_status]

    def list_disco_volume(self, *cmd, **kwargs):
        """Fake the glob call."""
        path_dir = self.connector.get_search_path()
        volume_id = self.volume['disco_id']
        volume_items = [path_dir, '/', self.connector.DISCO_PREFIX, volume_id]
        volume_path = ''.join(volume_items)
        return [volume_path]

    def test_get_connector_properties(self):
        props = connector.DISCOConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        """DISCO volumes should be under /dev."""
        expected = "/dev"
        actual = self.connector.get_search_path()
        self.assertEqual(expected, actual)

    def test_get_volume_paths(self):
        """Test to get all the path for a specific volume."""
        expected = ['/dev/dms1234567']
        self.volume_status = 'attached'
        actual = self.connector.get_volume_paths(
            self.fake_connection_properties)
        self.assertEqual(expected, actual)

    def test_connect_volume(self):
        """Attach a volume."""
        self.connector.connect_volume(self.fake_connection_properties)

    def test_connect_volume_already_attached(self):
        """Make sure that we don't issue the request."""
        self.request_status = 'fail'
        self.volume_status = 'attached'
        self.test_connect_volume()

    def test_connect_volume_request_fail(self):
        """Fail the attach request."""
        self.volume_status = 'detached'
        self.request_status = 'fail'
        self.assertRaises(exception.BrickException,
                          self.test_connect_volume)

    def test_disconnect_volume(self):
        """Detach a volume."""
        self.connector.disconnect_volume(self.fake_connection_properties, None)

    def test_disconnect_volume_attached(self):
        """Detach a volume attached."""
        self.request_status = 'success'
        self.volume_status = 'attached'
        self.test_disconnect_volume()

    def test_disconnect_volume_already_detached(self):
        """Ensure that we don't issue the request."""
        self.request_status = 'fail'
        self.volume_status = 'detached'
        self.test_disconnect_volume()

    def test_disconnect_volume_request_fail(self):
        """Fail the detach request."""
        self.volume_status = 'attached'
        self.request_status = 'fail'
        self.assertRaises(exception.BrickException,
                          self.test_disconnect_volume)

    def test_get_all_available_volumes(self):
        """Test to get all the available DISCO volumes."""
        expected = ['/dev/dms1234567']
        actual = self.connector.get_all_available_volumes(None)
        self.assertItemsEqual(expected, actual)

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.fake_connection_properties)


class SheepdogConnectorTestCase(ConnectorTestCase):

    def setUp(self):
        super(SheepdogConnectorTestCase, self).setUp()

        self.hosts = ['fake_hosts']
        self.ports = ['fake_ports']
        self.volume = 'fake_volume'

        self.connection_properties = {
            'hosts': self.hosts,
            'name': self.volume,
            'ports': self.ports,
        }

    def test_get_connector_properties(self):
        props = connector.SheepdogConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        sheepdog = connector.SheepdogConnector(None)
        path = sheepdog.get_search_path()
        self.assertIsNone(path)

    def test_get_volume_paths(self):
        sheepdog = connector.SheepdogConnector(None)
        expected = []
        actual = sheepdog.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, actual)

    def test_connect_volume(self):
        """Test the connect volume case."""
        sheepdog = connector.SheepdogConnector(None)
        device_info = sheepdog.connect_volume(self.connection_properties)

        # Ensure expected object is returned correctly
        self.assertTrue(isinstance(device_info['path'],
                                   linuxsheepdog.SheepdogVolumeIOWrapper))

    @mock.patch.object(linuxsheepdog.SheepdogVolumeIOWrapper, 'close')
    def test_disconnect_volume(self, volume_close):
        """Test the disconnect volume case."""
        sheepdog = connector.SheepdogConnector(None)
        device_info = sheepdog.connect_volume(self.connection_properties)
        sheepdog.disconnect_volume(self.connection_properties, device_info)

        self.assertEqual(1, volume_close.call_count)

    def test_disconnect_volume_with_invalid_handle(self):
        """Test the disconnect volume case with invalid handle."""
        sheepdog = connector.SheepdogConnector(None)
        device_info = {'path': 'fake_handle'}
        self.assertRaises(exception.InvalidIOHandleObject,
                          sheepdog.disconnect_volume,
                          self.connection_properties,
                          device_info)

    def test_extend_volume(self):
        sheepdog = connector.SheepdogConnector(None)
        self.assertRaises(NotImplementedError,
                          sheepdog.extend_volume,
                          self.connection_properties)
