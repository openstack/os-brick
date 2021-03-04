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
import json
import os
from unittest import mock

import requests

from os_brick import exception
from os_brick.initiator.connectors import scaleio
from os_brick.tests.initiator import test_connector


class ScaleIOConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for ScaleIO connector."""

    # Fake volume information
    vol = {
        'id': 'vol1',
        'name': 'test_volume',
        'provider_id': 'vol1'
    }

    # Fake SDC GUID
    fake_guid = '013a5304-d053-4b30-a34f-ee3ad983236d'

    def setUp(self):
        super(ScaleIOConnectorTestCase, self).setUp()

        self.fake_connection_properties = {
            'hostIP': test_connector.MY_IP,
            'serverIP': test_connector.MY_IP,
            'scaleIO_volname': self.vol['name'],
            'scaleIO_volume_id': self.vol['provider_id'],
            'serverPort': 443,
            'serverUsername': 'test',
            'config_group': 'test',
            'failed_over': False,
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
        self.mock_object(requests, 'get', self.handle_scaleio_request)
        self.mock_object(requests, 'post', self.handle_scaleio_request)
        self.mock_object(os.path, 'isdir', return_value=True)
        self.mock_object(os, 'listdir',
                         return_value=["emc-vol-{}".format(self.vol['id'])])

        # Patch scaleio privileged calls
        self.get_password_mock = self.mock_object(scaleio.priv_scaleio,
                                                  'get_connector_password',
                                                  return_value='fake_password')
        self.get_guid_mock = self.mock_object(scaleio.priv_scaleio, 'get_guid',
                                              return_value=self.fake_guid)
        self.rescan_vols_mock = self.mock_object(scaleio.priv_scaleio,
                                                 'rescan_vols')

        # The actual ScaleIO connector
        self.connector = scaleio.ScaleIOConnector(
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
            if isinstance(self._content, str):
                return super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                             self).json(**kwargs)

            return self._content

        @property
        def text(self):
            if not isinstance(self._content, str):
                return json.dumps(self._content)

            self._content = self._content.encode('utf-8')
            return super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                         self).text

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
    @mock.patch.object(scaleio.ScaleIOConnector, '_wait_for_volume_path')
    def test_get_volume_paths(self, mock_wait_for_path, mock_exists):
        mock_wait_for_path.return_value = "emc-vol-vol1"
        expected = ['/dev/disk/by-id/emc-vol-vol1']
        actual = self.connector.get_volume_paths(
            self.fake_connection_properties)
        self.assertEqual(expected, actual)

    def test_get_connector_properties(self):
        props = scaleio.ScaleIOConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_connect_volume(self):
        """Successful connect to volume"""
        self.connector.connect_volume(self.fake_connection_properties)
        self.get_guid_mock.assert_called_once_with(
            self.connector.GET_GUID_OP_CODE)
        self.get_password_mock.assert_called_once()

    def test_connect_volume_old_connection_properties(self):
        """Successful connect to volume"""
        connection_properties = {
            'hostIP': test_connector.MY_IP,
            'serverIP': test_connector.MY_IP,
            'scaleIO_volname': self.vol['name'],
            'scaleIO_volume_id': self.vol['provider_id'],
            'serverPort': 443,
            'serverUsername': 'test',
            'serverPassword': 'fake',
            'serverToken': 'fake_token',
            'iopsLimit': None,
            'bandwidthLimit': None
        }

        self.connector.connect_volume(connection_properties)
        self.get_guid_mock.assert_called_once_with(
            self.connector.GET_GUID_OP_CODE)
        self.get_password_mock.assert_not_called()

    def test_connect_volume_without_volume_id(self):
        """Successful connect to volume without a Volume Id"""
        connection_properties = dict(self.fake_connection_properties)
        connection_properties.pop('scaleIO_volume_id')

        self.connector.connect_volume(connection_properties)
        self.get_guid_mock.assert_called_once_with(
            self.connector.GET_GUID_OP_CODE)

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
        self.get_guid_mock.assert_called_once_with(
            self.connector.GET_GUID_OP_CODE)

    def test_disconnect_volume_without_volume_id(self):
        """Successful disconnect from volume without a Volume Id"""
        connection_properties = dict(self.fake_connection_properties)
        connection_properties.pop('scaleIO_volume_id')

        self.connector.disconnect_volume(connection_properties, None)
        self.get_guid_mock.assert_called_once_with(
            self.connector.GET_GUID_OP_CODE)

    def test_error_id(self):
        """Fail to connect with bad volume name"""
        self.fake_connection_properties['scaleIO_volume_id'] = 'bad_id'
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            dict(errorCode='404', message='Test volume not found'), 404)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_no_volume_id(self):
        """Faile to connect with no volume id"""
        self.fake_connection_properties['scaleIO_volume_id'] = None
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            'null', 200)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_bad_login(self):
        """Fail to connect with bad authentication"""
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            'null', 401)

        self.mock_calls['login'] = self.MockHTTPSResponse('null', 401)
        self.mock_calls[self.action_format.format(
            'addMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=401, message='bad login'), 401)
        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_map_volume(self):
        """Fail to connect with REST API failure"""
        self.mock_calls[self.action_format.format(
            'addMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_NOT_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    @mock.patch('os_brick.utils._time_sleep')
    def test_error_path_not_found(self, sleep_mock):
        """Timeout waiting for volume to map to local file system"""
        self.mock_object(os, 'listdir', return_value=["emc-vol-no-volume"])
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

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(scaleio.ScaleIOConnector, '_find_volume_path')
    @mock.patch.object(scaleio.ScaleIOConnector, 'get_device_size')
    def test_extend_volume(self,
                           mock_device_size,
                           mock_find_volume_path,
                           mock_exists):
        mock_device_size.return_value = 16
        mock_find_volume_path.return_value = "emc-vol-vol1"
        extended_size = self.connector.extend_volume(
            self.fake_connection_properties)
        self.assertEqual(extended_size,
                         mock_device_size.return_value)
        self.rescan_vols_mock.assert_called_once_with(
            self.connector.RESCAN_VOLS_OP_CODE)

    def test_connection_properties_without_failed_over(self):
        """Handle connection properties with 'failed_over' missing"""
        connection_properties = dict(self.fake_connection_properties)
        connection_properties.pop('failed_over')

        self.connector.connect_volume(connection_properties)
        self.get_password_mock.assert_called_once_with(
            scaleio.CONNECTOR_CONF_PATH,
            connection_properties['config_group'],
            False)
