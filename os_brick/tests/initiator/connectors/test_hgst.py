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

from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator import connector
from os_brick.initiator.connectors import hgst
from os_brick.tests.initiator import test_connector


class HGSTConnectorTestCase(test_connector.ConnectorTestCase):
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
        self.connector = hgst.HGSTConnector(
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
        obj = connector.InitiatorConnector.factory('HGST', None, arch='x86_64')
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
        props = hgst.HGSTConnector.get_connector_properties(
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
