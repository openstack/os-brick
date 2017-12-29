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

import mock


from os_brick import exception
from os_brick.initiator.connectors import storpool as connector
from os_brick.tests.initiator import test_connector


def volumeNameExt(vid):
    return 'os--volume--{id}'.format(id=vid)


class MockStorPoolADB(object):
    def __init__(self, log):
        self.requests = {}
        self.attached = {}

    def api(self):
        pass

    def add(self, req_id, req):
        if req_id in self.requests:
            raise Exception('Duplicate MockStorPool request added')
        self.requests[req_id] = req

    def remove(self, req_id):
        req = self.requests.get(req_id, None)
        if req is None:
            raise Exception('Unknown MockStorPool request removed')
        elif req['volume'] in self.attached:
            raise Exception('Removing attached MockStorPool volume')
        del self.requests[req_id]

    def sync(self, req_id, detached):
        req = self.requests.get(req_id, None)
        if req is None:
            raise Exception('Unknown MockStorPool request synced')
        volume = req.get('volume', None)
        if volume is None:
            raise Exception('MockStorPool request without volume')

        if detached is None:
            if volume in self.attached:
                raise Exception('Duplicate MockStorPool request synced')
            self.attached[volume] = req
        else:
            if volume != detached:
                raise Exception(
                    'Mismatched volumes on a MockStorPool request removal')
            elif detached not in self.attached:
                raise Exception('MockStorPool request not attached yet')
            del self.attached[detached]

    def volumeName(self, vid):
        return volumeNameExt(vid)


spopenstack = mock.Mock()
spopenstack.AttachDB = MockStorPoolADB
connector.spopenstack = spopenstack


class StorPoolConnectorTestCase(test_connector.ConnectorTestCase):
    def volumeName(self, vid):
        return volumeNameExt(vid)

    def execute(self, *cmd, **kwargs):
        if cmd[0] == 'blockdev':
            self.assertEqual(len(cmd), 3)
            self.assertEqual(cmd[1], '--getsize64')
            self.assertEqual(cmd[2], '/dev/storpool/' +
                             self.volumeName(self.fakeProp['volume']))
            return (str(self.fakeSize), None)
        raise Exception("Unrecognized command passed to " +
                        type(self).__name__ + ".execute(): " +
                        str.join(", ", map(lambda s: "'" + s + "'", cmd)))

    def setUp(self):
        super(StorPoolConnectorTestCase, self).setUp()

        self.fakeProp = {
            'volume': 'sp-vol-1',
            'client_id': 1,
            'access_mode': 'rw',
        }
        self.fakeConnection = None
        self.fakeSize = 1024 * 1024 * 1024

        self.connector = connector.StorPoolConnector(
            None, execute=self.execute)
        self.adb = self.connector._attach

    def test_connect_volume(self):
        self.assertNotIn(self.volumeName(self.fakeProp['volume']),
                         self.adb.attached)
        conn = self.connector.connect_volume(self.fakeProp)
        self.assertIn('type', conn)
        self.assertIn('path', conn)
        self.assertIn(self.volumeName(self.fakeProp['volume']),
                      self.adb.attached)

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
        self.assertIn(self.volumeName(self.fakeProp['volume']),
                      self.adb.attached)
        self.connector.disconnect_volume(self.fakeProp, None)
        self.assertNotIn(self.volumeName(self.fakeProp['volume']),
                         self.adb.attached)

    def test_connect_exceptions(self):
        """Raise exceptions on missing connection information"""
        fake = self.fakeProp
        for key in fake.keys():
            c = dict(fake)
            del c[key]
            self.assertRaises(exception.BrickException,
                              self.connector.connect_volume, c)
            if key != 'access_mode':
                self.assertRaises(exception.BrickException,
                                  self.connector.disconnect_volume, c, None)

    def test_extend_volume(self):
        if self.fakeConnection is None:
            self.test_connect_volume()

        self.fakeSize += 1024 * 1024 * 1024
        newSize = self.connector.extend_volume(self.fakeProp)
        self.assertEqual(newSize, self.fakeSize)
