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

import platform
import sys

import mock
from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator import connector
from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import fake
from os_brick.initiator.connectors import iscsi
from os_brick.initiator import linuxfc
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests import base as test_base

MY_IP = '10.0.0.1'
FAKE_SCSI_WWN = '1234567890'


class ConnectorUtilsTestCase(test_base.TestCase):

    @mock.patch.object(iscsi.ISCSIConnector, 'get_initiator',
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
                 'platform': platform,
                 'do_local_attach': False}
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


class ConnectorTestCase(test_base.TestCase):

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
        self.connector = fake.FakeConnector(None)
        device_info = self.connector.connect_volume(self.fake_connection())
        self.assertIn('type', device_info)
        self.assertIn('path', device_info)

    def test_disconnect_volume(self):
        self.connector = fake.FakeConnector(None)

    def test_get_connector_properties(self):
        with mock.patch.object(priv_rootwrap, 'execute') as mock_exec:
            mock_exec.return_value = True
            multipath = True
            enforce_multipath = True
            props = base.BaseLinuxConnector.get_connector_properties(
                'sudo', multipath=multipath,
                enforce_multipath=enforce_multipath)

            expected_props = {'multipath': True}
            self.assertEqual(expected_props, props)

            multipath = False
            enforce_multipath = True
            props = base.BaseLinuxConnector.get_connector_properties(
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
                base.BaseLinuxConnector.get_connector_properties,
                'sudo', multipath=multipath,
                enforce_multipath=enforce_multipath)

    def test_factory(self):
        obj = connector.InitiatorConnector.factory('iscsi', None)
        self.assertEqual("ISCSIConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory('iscsi', None,
                                                   arch='ppc64le')
        self.assertEqual("ISCSIConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory('fibre_channel', None,
                                                   arch='x86_64')
        self.assertEqual("FibreChannelConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory('fibre_channel', None,
                                                   arch='s390x')
        self.assertEqual("FibreChannelConnectorS390X", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory('aoe', None, arch='x86_64')
        self.assertEqual("AoEConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            'nfs', None, nfs_mount_point_base='/mnt/test')
        self.assertEqual("RemoteFsConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            'glusterfs', None, glusterfs_mount_point_base='/mnt/test',
            arch='x86_64')
        self.assertEqual("RemoteFsConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            'scality', None, scality_mount_point_base='/mnt/test',
            arch='x86_64')
        self.assertEqual("RemoteFsConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory('local', None)
        self.assertEqual("LocalConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory('gpfs', None)
        self.assertEqual("GPFSConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            'huaweisdshypervisor', None, arch='x86_64')
        self.assertEqual("HuaweiStorHyperConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            "scaleio", None, arch='x86_64')
        self.assertEqual("ScaleIOConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            'quobyte', None, quobyte_mount_point_base='/mnt/test',
            arch='x86_64')
        self.assertEqual("RemoteFsConnector", obj.__class__.__name__)

        obj = connector.InitiatorConnector.factory(
            "disco", None, arch='x86_64')
        self.assertEqual("DISCOConnector", obj.__class__.__name__)

        self.assertRaises(exception.InvalidConnectorProtocol,
                          connector.InitiatorConnector.factory,
                          "bogus", None)

    def test_check_valid_device_with_wrong_path(self):
        self.connector = fake.FakeConnector(None)
        self.connector._execute = \
            lambda *args, **kwargs: ("", None)
        self.assertFalse(self.connector.check_valid_device('/d0v'))

    def test_check_valid_device(self):
        self.connector = fake.FakeConnector(None)
        self.connector._execute = \
            lambda *args, **kwargs: ("", "")
        self.assertTrue(self.connector.check_valid_device('/dev'))

    def test_check_valid_device_with_cmd_error(self):
        def raise_except(*args, **kwargs):
            raise putils.ProcessExecutionError
        self.connector = fake.FakeConnector(None)
        with mock.patch.object(self.connector, '_execute',
                               side_effect=putils.ProcessExecutionError):
            self.assertFalse(self.connector.check_valid_device('/dev'))
