#    Copyright (c) 2015 - 2017 StorPool
#    All Rights Reserved.
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

import copy
from unittest import mock


from os_brick import exception
from os_brick.initiator.connectors import storpool as connector
from os_brick.tests.initiator import test_connector


def volumeNameExt(vid):
    return 'os--volume--{id}'.format(id=vid)


def faulty_api(req):
    faulty_api.real_fn(req)
    if faulty_api.fail_count > 0:
        faulty_api.fail_count -= 1
        raise MockApiError("busy",
                           "'os--volume--sp-vol-1' is open at client 19")


class MockApiError(Exception):
    def __init__(self, name, desc):
        super(MockApiError, self).__init__()
        self.name = name
        self.desc = desc


class MockVolumeInfo(object):
    def __init__(self, global_id):
        self.globalId = global_id


class MockStorPoolADB(object):
    def __init__(self, log):
        pass

    def api(self):
        pass

    def config(self):
        return {"SP_OURID": 1}

    def volumeName(self, vid):
        return volumeNameExt(vid)


spopenstack = mock.Mock()
spopenstack.AttachDB = MockStorPoolADB
connector.spopenstack = spopenstack

spapi = mock.Mock()
spapi.ApiError = MockApiError
connector.spapi = spapi


class StorPoolConnectorTestCase(test_connector.ConnectorTestCase):
    def volumeName(self, vid):
        return volumeNameExt(vid)

    def get_fake_size(self):
        return self.fakeSize

    def execute(self, *cmd, **kwargs):
        if cmd[0] == 'blockdev':
            self.assertEqual(len(cmd), 3)
            self.assertEqual(cmd[1], '--getsize64')
            self.assertEqual(cmd[2], '/dev/storpool/' +
                             self.volumeName(self.fakeProp['volume']))
            return (str(self.get_fake_size()) + '\n', None)
        raise Exception("Unrecognized command passed to " +
                        type(self).__name__ + ".execute(): " +
                        str.join(", ", map(lambda s: "'" + s + "'", cmd)))

    def setUp(self):
        super(StorPoolConnectorTestCase, self).setUp()

        self.fakeProp = {
            'volume': 'sp-vol-1',
            'client_id': 1,
            'access_mode': 'rw'
        }
        self.fakeDeviceInfo = {
            'path': '/dev/storpool/' + 'os--volume--' + 'sp-vol-1'
        }
        self.fakeGlobalId = 'OneNiceGlobalId'
        self.api_calls_retry_max = 10
        self.fakeConnection = None
        self.fakeSize = 1024 * 1024 * 1024
        self.reassign_wait_data = {'reassign': [
            {'volume': volumeNameExt(self.fakeProp['volume']),
             'detach': [1], 'force': False}]}

        self.connector = connector.StorPoolConnector(
            None, execute=self.execute)
        self.adb = self.connector._attach

    def test_raise_if_spopenstack_missing(self):
        with mock.patch.object(connector, 'spopenstack', None):
            self.assertRaises(exception.BrickException,
                              connector.StorPoolConnector, "")

    def test_raise_if_sp_ourid_missing(self):
        with mock.patch.object(spopenstack.AttachDB, 'config', lambda x: {}):
            self.assertRaises(exception.BrickException,
                              connector.StorPoolConnector, "")

    def test_connect_volume(self):
        volume_name = volumeNameExt(self.fakeProp['volume'])
        api = mock.MagicMock(spec=['volumesReassignWait', 'volumeInfo'])
        api.volumesReassignWait = mock.MagicMock(spec=['__call__'])
        volume_info = MockVolumeInfo(self.fakeGlobalId)
        api.volumeInfo = mock.Mock(return_value=volume_info)

        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api

            conn = self.connector.connect_volume(self.fakeProp)
            self.assertIn('type', conn)
            self.assertIn('path', conn)
            self.assertEqual(conn['path'],
                             '/dev/storpool-byid/' + self.fakeGlobalId)
            self.assertEqual(len(api.volumesReassignWait.mock_calls), 1)
            self.assertEqual(api.volumesReassignWait.mock_calls[0], mock.call(
                {'reassign': [{'volume': 'os--volume--sp-vol-1', 'rw': [1]}]}))
            self.assertEqual(len(api.volumeInfo.mock_calls), 1)
            self.assertEqual(api.volumeInfo.mock_calls[0],
                             mock.call(volume_name))

            self.assertEqual(self.connector.get_search_path(), '/dev/storpool')

            paths = self.connector.get_volume_paths(self.fakeProp)
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0],
                             "/dev/storpool/" +
                             self.volumeName(self.fakeProp['volume']))
            self.fakeConnection = conn

    def test_disconnect_volume(self):
        if self.fakeConnection is None:
            self.test_connect_volume()

        api = mock.MagicMock(spec=['volumesReassignWait'])
        api.volumesReassignWait = mock.MagicMock(spec=['__call__'])

        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api

            self.connector.disconnect_volume(self.fakeProp,
                                             self.fakeDeviceInfo)
            self.assertEqual(api.volumesReassignWait.mock_calls[0],
                             (mock.call(self.reassign_wait_data)))

            api.volumesReassignWait = mock.MagicMock(spec=['__call__'])
            fake_device_info = copy.deepcopy(self.fakeDeviceInfo)
            fake_device_info["path"] = \
                "/dev/storpool-byid/" \
                "byid-paths-map-to-volumes-with-a-tilde-prefix"
            rwd = copy.deepcopy(self.reassign_wait_data)
            rwd['reassign'][0]["volume"] =\
                "~byid-paths-map-to-"\
                "volumes-with-a-tilde-prefix"
            self.connector.disconnect_volume(self.fakeProp, fake_device_info)
            self.assertEqual(api.volumesReassignWait.mock_calls[0],
                             (mock.call(rwd)))

            fake_device_info = copy.deepcopy(self.fakeDeviceInfo)
            del fake_device_info["path"]
            fake_prop = copy.deepcopy(self.fakeProp)
            fake_prop["device_path"] = \
                "/dev/storpool-byid/" \
                "byid-paths-map-to-volumes-with-a-tilde-prefix"
            rwd = copy.deepcopy(self.reassign_wait_data)
            rwd['reassign'][0]["volume"] =\
                "~byid-paths-map-to-"\
                "volumes-with-a-tilde-prefix"
            self.connector.disconnect_volume(fake_prop, fake_device_info)
            self.assertEqual(api.volumesReassignWait.mock_calls[0],
                             (mock.call(rwd)))

            fake_device_info = copy.deepcopy(self.fakeDeviceInfo)
            fake_device_info["path"] = "/dev/invalid"
            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              fake_device_info)

            fake_device_info = copy.deepcopy(self.fakeDeviceInfo)
            del fake_device_info["path"]
            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              fake_device_info)

            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              None)

    def test_connect_exceptions(self):
        """Raise exceptions on missing connection information"""
        api = mock.MagicMock(spec=['volumesReassignWait', 'volumeInfo'])
        api.volumesReassignWait = mock.MagicMock(spec=['__call__'])
        api.volumeInfo = mock.MagicMock(spec=['__call__'])

        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api

            for key in ['volume', 'client_id', 'access_mode']:
                fake_prop = copy.deepcopy(self.fakeProp)
                del fake_prop[key]
                self.assertRaises(exception.BrickException,
                                  self.connector.connect_volume, fake_prop)

            fake_prop = copy.deepcopy(self.fakeProp)
            del fake_prop['client_id']
            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, fake_prop,
                              self.fakeDeviceInfo)

            fake_device_info = copy.deepcopy(self.fakeDeviceInfo)
            del fake_device_info['path']
            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              fake_device_info)

    def test_sp_ourid_exceptions(self):
        """Raise exceptions on missing SP_OURID"""
        with mock.patch.object(self.connector._attach, 'config')\
                as fake_config:
            fake_config.return_value = {}

            self.assertRaises(exception.BrickException,
                              self.connector.connect_volume, self.fakeProp)

            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              self.fakeDeviceInfo)

    def test_sp_api_exceptions(self):
        """Handle SP API exceptions"""
        api = mock.MagicMock(spec=['volumesReassignWait', 'volumeInfo'])
        api.volumesReassignWait = mock.MagicMock(spec=['__call__'])
        # The generic exception should bypass the SP API exception handling
        api.volumesReassignWait.side_effect = Exception()
        api.volumeInfo = mock.MagicMock(spec=['__call__'])

        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api

            self.assertRaises(exception.BrickException,
                              self.connector.connect_volume, self.fakeProp)

            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              self.fakeDeviceInfo)

        api.volumesReassignWait.side_effect = ""
        api.volumeInfo = Exception()

        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api

            self.assertRaises(exception.BrickException,
                              self.connector.connect_volume, self.fakeProp)

            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              self.fakeDeviceInfo)

        # Test the retry logic
        def init_mock_api(retries):
            faulty_api.fail_count = retries
            faulty_api.real_fn = mock.MagicMock(spec=['__call__'])
            api.volumesReassignWait = faulty_api
            api.volumeInfo = mock.MagicMock(spec=['__call__'])

        init_mock_api(self.api_calls_retry_max - 1)
        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api

            self.connector.disconnect_volume(self.fakeProp,
                                             self.fakeDeviceInfo)
            self.assertEqual(self.api_calls_retry_max,
                             len(faulty_api.real_fn.mock_calls))
            for mock_call in faulty_api.real_fn.mock_calls:
                self.assertEqual(mock_call, mock.call(self.reassign_wait_data))

        init_mock_api(self.api_calls_retry_max)
        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api
            rwd = copy.deepcopy(self.reassign_wait_data)

            self.connector.disconnect_volume(self.fakeProp,
                                             self.fakeDeviceInfo)
            self.assertEqual(self.api_calls_retry_max + 1,
                             len(faulty_api.real_fn.mock_calls))
            for mock_call in faulty_api.real_fn.mock_calls[:-1]:
                self.assertEqual(mock_call, mock.call(rwd))
            rwd['reassign'][0]['force'] = True
            self.assertEqual(faulty_api.real_fn.mock_calls[-1], mock.call(rwd))

        init_mock_api(self.api_calls_retry_max + 1)
        with mock.patch.object(
                self.adb, attribute='api', spec=['__call__']
        ) as fake_api:
            fake_api.return_value = api
            rwd = copy.deepcopy(self.reassign_wait_data)

            self.assertRaises(exception.BrickException,
                              self.connector.disconnect_volume, self.fakeProp,
                              self.fakeDeviceInfo)
            self.assertEqual(self.api_calls_retry_max + 1,
                             len(faulty_api.real_fn.mock_calls))
            for mock_call in faulty_api.real_fn.mock_calls[:-1]:
                self.assertEqual(mock_call, mock.call(rwd))
            rwd['reassign'][0]['force'] = True
            self.assertEqual(faulty_api.real_fn.mock_calls[-1], mock.call(rwd))

    def test_extend_volume(self):
        if self.fakeConnection is None:
            self.test_connect_volume()

        self.fakeSize += 1024 * 1024 * 1024

        size_list = [self.fakeSize, self.fakeSize - 1, self.fakeSize - 2]

        vdata = mock.MagicMock(spec=['size'])
        vdata.size = self.fakeSize
        vdata_list = [[vdata]]

        def fake_volume_list(name):
            self.assertEqual(
                name,
                self.adb.volumeName(self.fakeProp['volume'])
            )
            return vdata_list.pop()

        api = mock.MagicMock(spec=['volumeList'])
        api.volumeList = mock.MagicMock(spec=['__call__'])

        with mock.patch.object(
            self.adb, attribute='api', spec=['__call__']
        ) as fake_api, mock.patch.object(
            self, attribute='get_fake_size', spec=['__call__']
        ) as fake_size, mock.patch('time.sleep') as fake_sleep:
            fake_api.return_value = api
            api.volumeList.side_effect = fake_volume_list

            fake_size.side_effect = size_list.pop

            newSize = self.connector.extend_volume(self.fakeProp)

            self.assertEqual(fake_api.call_count, 1)
            self.assertEqual(api.volumeList.call_count, 1)
            self.assertListEqual(vdata_list, [])

            self.assertEqual(fake_size.call_count, 3)
            self.assertListEqual(size_list, [])

            self.assertEqual(fake_sleep.call_count, 2)

        self.assertEqual(newSize, self.fakeSize)
