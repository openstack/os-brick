#    Copyright (c) 2015 - 2024 StorPool
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
import json
import os
from unittest import mock


from os_brick import exception
from os_brick.initiator import storpool_utils
from os_brick.tests import base

STORPOOL_CONF_INI_NO_HOSTNAME = """\
SP_API_HTTP_HOST=127.0.0.1
SP_API_HTTP_PORT=81
SP_AUTH_TOKEN=1234567890123456789

[another-node]
SP_OURID=2
"""

STORPOOL_CONF_INI = STORPOOL_CONF_INI_NO_HOSTNAME + """\
[this-node]
SP_OURID=1
"""

STORPOOL_CONF_INI_SELECTOR = "full"

ANOTHER_CONF_INI = """\
SP_API_HTTP_HOST=127.0.100.1
SP_API_HTTP_PORT=8080
"""

SP_CONF = {
    'SP_API_HTTP_HOST': '127.0.100.1',
    'SP_API_HTTP_PORT': '8080',
    'SP_AUTH_TOKEN': '1234567890123456789',
    'SP_OURID': '1'
}


def faulty_api(req):
    faulty_api.real_fn(req)
    if faulty_api.fail_count > 0:
        faulty_api.fail_count -= 1
        raise storpool_utils.StorPoolAPIError(
            500,
            {
                'error': {
                    'name': 'busy',
                    'descr': "'os--volume--sp-vol-1' is open at client 19"
                }
            })


def _fake_open(path):
    data = ""
    if path.name == '/etc/storpool.conf':
        if STORPOOL_CONF_INI_SELECTOR == 'full':
            data = STORPOOL_CONF_INI
        if STORPOOL_CONF_INI_SELECTOR == 'no-hostname':
            data = STORPOOL_CONF_INI_NO_HOSTNAME
    elif path.name == '/etc/storpool.conf.d/another.conf':
        data = ANOTHER_CONF_INI
    else:
        raise Exception(f"Called open with an unexpected path: {path}")

    open_mock = mock.Mock()
    open_mock.read = lambda: data
    ctx_mock = mock.Mock()
    ctx_mock.__enter__ = mock.Mock(return_value=open_mock)
    ctx_mock.__exit__ = mock.Mock()
    return ctx_mock


def _fake_node():
    return 'this-node'


class FakePath:
    def __init__(self, name, exists, is_file, dir_contents = None):
        self.name = name
        self.exists = exists
        self.is_a_file = is_file
        self.dir_contents = dir_contents

    def is_file(self):
        return self.exists and self.is_a_file

    def is_dir(self):
        return self.exists and not self.is_a_file

    def iterdir(self):
        if self.dir_contents is None:
            raise Exception(
                f"Called iterdir() on a non-directory: {self.name}")
        return self.dir_contents

    def __str__(self):
        return self.name


@mock.patch('builtins.open', _fake_open)
@mock.patch('platform.node', _fake_node)
class StorPoolConfTestCase(base.TestCase):
    def setUp(self):
        super(StorPoolConfTestCase, self).setUp()

        self.mock_path = mock.Mock()
        self.fs_tree = [
            FakePath('/etc/storpool.conf', True, True),
            FakePath('/etc/storpool.conf.d', True, False, [])
        ]

    def test_subconf_overrides_main(self):
        self.fs_tree[1] = FakePath('/etc/storpool.conf.d', True, False, [
            FakePath('/etc/storpool.conf.d/another.conf', True, True)
        ])
        self._fs_init(self.fs_tree, 'full')

        with mock.patch('pathlib.Path', self.mock_path):
            conf = storpool_utils.get_conf()

        self.assertEqual(SP_CONF, conf)

    def test_only_storpool_conf(self):
        self._fs_init(self.fs_tree, 'full')

        sp_conf_expected = copy.deepcopy(SP_CONF)
        sp_conf_expected['SP_API_HTTP_HOST'] = '127.0.0.1'
        sp_conf_expected['SP_API_HTTP_PORT'] = '81'

        with mock.patch('pathlib.Path', self.mock_path):
            conf = storpool_utils.get_conf()

        self.assertEqual(sp_conf_expected, conf)

    def test_env_overrides_main(self):
        self._fs_init(self.fs_tree, 'full')

        overrides_expected = {
            'SP_API_HTTP_HOST': '192.168.0.10',
            'SP_API_HTTP_PORT': '8123'
        }

        sp_conf_expected = copy.deepcopy(SP_CONF)
        sp_conf_expected.update(overrides_expected)

        with (mock.patch('pathlib.Path', self.mock_path),
              mock.patch.dict(os.environ, overrides_expected)):
            conf = storpool_utils.get_conf()

        self.assertEqual(sp_conf_expected, conf)

    def test_raise_if_no_storpool_conf(self):
        self.fs_tree[0] = FakePath('/etc/storpool.conf', False, True)
        self._fs_init(self.fs_tree, 'full')

        with mock.patch('pathlib.Path', self.mock_path):
            self.assertRaises(exception.BrickException,
                              storpool_utils.get_conf)

    def _fs_init(self, fs, storpool_conf_type):
        global STORPOOL_CONF_INI_SELECTOR
        STORPOOL_CONF_INI_SELECTOR = storpool_conf_type
        self.mock_path.side_effect = fs


class StorPoolAPITestCase(base.TestCase):
    def setUp(self):
        super(StorPoolAPITestCase, self).setUp()
        self.api = storpool_utils.StorPoolAPI(
            '127.0.0.1', '81', '1234567890123456789')

    def test_api_ok(self):
        with mock.patch('http.client.HTTPConnection') as connection_mock:
            resp = mock.Mock()
            c_mock = connection_mock.return_value
            c_mock.getresponse = mock.Mock(return_value=resp)

            resp.status = 200
            resp.read = lambda: '{ "data": [{ "name": "test-volume" }] }'

            self.assertEqual(self.api.volumes_list(),
                             [{'name': 'test-volume'}])

    def test_api_exceptions(self):
        with mock.patch('http.client.HTTPConnection') as connection_mock:
            resp = mock.Mock()
            c_mock = connection_mock.return_value
            c_mock.getresponse = mock.Mock(return_value=resp)

            resp.status = 200
            resp.read = lambda: '{}'
            self.assertRaises(KeyError, self.api.volumes_list)

            resp.read = lambda: '{/}'
            self.assertRaises(json.JSONDecodeError, self.api.volumes_list)

            resp.read = lambda: '{ "error": { "transient": true } }'
            self.assertRaises(storpool_utils.StorPoolAPIError,
                              self.api.volumes_list)

    def test_api_handle_transient(self):
        with mock.patch('http.client.HTTPConnection') as connection_mock:
            resp = mock.Mock()
            resp.status = 500
            resp.read = lambda: '{ "error": { "transient": true } }'

            resp1 = mock.Mock()
            resp1.status = 200
            resp1.read = lambda: '{ "data": [{ "name": "test-volume" }] }'

            c_mock = connection_mock.return_value
            c_mock.getresponse = mock.Mock(side_effect=[resp, resp, resp1])

            self.assertEqual(self.api.volumes_list(),
                             [{'name': 'test-volume'}])
