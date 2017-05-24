# Copyright (c) 2017 Veritas Technologies LLC
# All Rights Reserved.
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

import json

from oslo_concurrency import processutils

from os_brick import exception
from os_brick.initiator.connectors import vrtshyperscale
from os_brick.tests.initiator import test_connector

DEVICE_NAME = '{8ee71c33-dcd0-4267-8f2b-e0742ecabe9f}'
DEVICE_PATH = '/dev/8ee71c33-dcd0-4267-8f2b-e0742ec'


class HyperScaleConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for Veritas HyperScale os-brick connector."""

    def _fake_execute_success(self, *cmd, **kwargs):
        """Mock successful execution of hscli"""
        result_json = ""
        err = 0
        args = json.loads(cmd[1])
        if args['operation'] == 'connect_volume':
            result = {}
            payload = {}
            payload['vsa_ip'] = '192.0.2.2'
            payload['refl_factor'] = '2'
            payload['refl_targets'] = '192.0.2.3,192.0.2.4'
            result['payload'] = payload
            result_json = json.dumps(result)
        return (result_json, err)

    def _fake_execute_hscli_missing(self, *cmd, **kwargs):
        """Mock attempt to execute missing hscli"""
        raise processutils.ProcessExecutionError()
        return ("", 0)

    def _fake_execute_hscli_err(self, *cmd, **kwargs):
        """Mock hscli returning error"""
        result_json = ""
        err = 'fake_hscli_error_msg'
        return (result_json, err)

    def _fake_execute_hscli_res_inval(self, *cmd, **kwargs):
        """Mock hscli returning unexpected values"""
        result_json = ""
        err = 0
        result = {}
        payload = {}
        payload['unexpected'] = 'junk'
        result['payload'] = payload
        result_json = json.dumps(result)
        return (result_json, err)

    def test_connect_volume_normal(self):
        """Test results of successful connect_volume()"""
        connector = vrtshyperscale.HyperScaleConnector(
            'sudo', execute=self._fake_execute_success)
        fake_connection_properties = {
            'name': DEVICE_NAME
        }
        device_info = connector.connect_volume(fake_connection_properties)

        self.assertEqual('192.0.2.2', device_info['vsa_ip'])
        self.assertEqual('2', device_info['refl_factor'])
        self.assertEqual('192.0.2.3,192.0.2.4', device_info['refl_targets'])
        self.assertEqual(DEVICE_PATH, device_info['path'])

    def test_connect_volume_arg_missing(self):
        """Test connect_volume with missing missing arguments"""
        connector = vrtshyperscale.HyperScaleConnector(
            'sudo', execute=self._fake_execute_success)
        fake_connection_properties = {}
        self.assertRaises(exception.BrickException,
                          connector.connect_volume,
                          fake_connection_properties)

    def test_connect_volume_hscli_missing(self):
        """Test connect_volume that can't call hscli"""
        connector = vrtshyperscale.HyperScaleConnector(
            'sudo', execute=self._fake_execute_hscli_missing)
        fake_connection_properties = {
            'name': DEVICE_NAME
        }
        self.assertRaises(exception.BrickException,
                          connector.connect_volume,
                          fake_connection_properties)

    def test_connect_volume_hscli_err(self):
        """Test connect_volume when hscli returns an error"""
        connector = vrtshyperscale.HyperScaleConnector(
            'sudo', execute=self._fake_execute_hscli_err)
        fake_connection_properties = {
            'name': DEVICE_NAME
        }
        self.assertRaises(exception.BrickException,
                          connector.connect_volume,
                          fake_connection_properties)

    def test_connect_volume_hscli_res_inval(self):
        """Test connect_volume if hscli returns an invalid result"""
        connector = vrtshyperscale.HyperScaleConnector(
            'sudo', execute=self._fake_execute_hscli_res_inval)
        fake_connection_properties = {
            'name': DEVICE_NAME
        }
        self.assertRaises(exception.BrickException,
                          connector.connect_volume,
                          fake_connection_properties)

    def test_disconnect_volume_normal(self):
        """Test successful disconnect_volume call"""
        connector = vrtshyperscale.HyperScaleConnector(
            'sudo', execute=self._fake_execute_success)
        fake_connection_properties = {
            'name': DEVICE_NAME
        }
        fake_device_info = {}
        connector.disconnect_volume(fake_connection_properties,
                                    fake_device_info)

    def test_disconnect_volume_arg_missing(self):
        """Test disconnect_volume with missing arguments"""
        connector = vrtshyperscale.HyperScaleConnector(
            'sudo', execute=self._fake_execute_success)
        fake_connection_properties = {}
        fake_device_info = {}
        self.assertRaises(exception.BrickException,
                          connector.disconnect_volume,
                          fake_connection_properties,
                          fake_device_info)
