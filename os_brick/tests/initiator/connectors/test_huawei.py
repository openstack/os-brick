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
import tempfile
from unittest import mock

from os_brick import exception
from os_brick.initiator.connectors import huawei
from os_brick.tests.initiator import test_connector


class HuaweiStorHyperConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for StorHyper initiator class."""

    attached = False

    def setUp(self):
        super(HuaweiStorHyperConnectorTestCase, self).setUp()
        self.fake_sdscli_file = tempfile.mktemp()
        self.addCleanup(os.remove, self.fake_sdscli_file)
        newefile = open(self.fake_sdscli_file, 'w')
        newefile.write('test')
        newefile.close()

        self.connector = huawei.HuaweiStorHyperConnector(
            None, execute=self.fake_execute)
        self.connector.cli_path = self.fake_sdscli_file
        self.connector.iscliexist = True

        self.connector_fail = huawei.HuaweiStorHyperConnector(
            None, execute=self.fake_execute_fail)
        self.connector_fail.cli_path = self.fake_sdscli_file
        self.connector_fail.iscliexist = True

        self.connector_nocli = huawei.HuaweiStorHyperConnector(
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
        props = huawei.HuaweiStorHyperConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_get_search_path(self):
        actual = self.connector.get_search_path()
        self.assertIsNone(actual)

    @mock.patch.object(huawei.HuaweiStorHyperConnector,
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
        self.assertEqual(expected_commands, self.cmds)

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.connection_properties)
