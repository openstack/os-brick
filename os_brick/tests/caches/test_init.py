# Copyright (c) 2013 The Johns Hopkins University/Applied Physics Laboratory
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
from unittest import mock

from os_brick import caches
from os_brick import exception
from os_brick.tests import base


class CacheManagerTestCase(base.TestCase):
    def setUp(self):
        super(CacheManagerTestCase, self).setUp()
        self.connection_info = {
            "data": {
                "device_path": "/dev/disk/by-path/"
                "ip-192.0.2.0:3260-iscsi-iqn.2010-10.org.openstack"
                ":volume-fake_uuid-lun-1",
            },
        }
        self.root_helper = None

    @mock.patch('os_brick.executor.Executor._execute')
    def test_init_invalid_device_path(self, moc_exec):
        conn_info_invalid = {
            'data': {
            }
        }
        self.assertRaises(
            exception.VolumeLocalCacheNotSupported,
            caches.CacheManager,
            root_helper=None,
            connection_info=conn_info_invalid
        )

    @mock.patch('os_brick.caches.CacheManager._get_engine')
    def test_init_cacheable(self, moc_get_engine):
        moc_get_engine.return_value = None
        conn_info_cacheable = {
            'data': {
                'device_path': '/dev/sdd',
                'cacheable': True
            }
        }
        conn_info_non_cacheable = {
            'data': {
                'device_path': '/dev/sdd',
            }
        }
        mgr_cacheable = caches.CacheManager(
            root_helper=None,
            connection_info=conn_info_cacheable)
        mgr_non_cacheable = caches.CacheManager(
            root_helper=None,
            connection_info=conn_info_non_cacheable)
        self.assertTrue(mgr_cacheable.cacheable)
        self.assertFalse(mgr_non_cacheable.cacheable)

    @mock.patch('os_brick.caches.opencas.OpenCASEngine.is_engine_ready')
    def test_get_engine(self, moc_get_engine):
        conn_info = {
            'data': {
                'device_path': '/dev/sdd',
                'cacheable': True
            }
        }
        mgr = caches.CacheManager(root_helper=None,
                                  cache_name='opencas',
                                  connection_info=conn_info)
        self.assertIsNotNone(mgr.engine)

        self.assertRaises(
            exception.Invalid,
            caches.CacheManager,
            root_helper=None,
            connection_info=conn_info
        )

    @mock.patch('os_brick.caches.opencas.OpenCASEngine.is_engine_ready')
    @mock.patch('os_brick.caches.opencas.OpenCASEngine.attach_volume')
    def test_attach_volume(self, moc_attach, moc_eng_ready):
        conn_info = {
            'data': {
                'device_path': '/dev/sdd',
            }
        }
        moc_attach.return_value = '/dev/cas1-1'
        moc_eng_ready.return_value = True

        mgr = caches.CacheManager(root_helper=None,
                                  cache_name='opencas',
                                  connection_info=conn_info)
        self.assertEqual('/dev/sdd', mgr.attach_volume())

        conn_info['data']['cacheable'] = True
        mgr = caches.CacheManager(root_helper=None,
                                  cache_name='opencas',
                                  connection_info=conn_info)
        self.assertEqual('/dev/cas1-1', mgr.attach_volume())

    @mock.patch('os_brick.caches.opencas.OpenCASEngine.is_engine_ready')
    @mock.patch('os_brick.caches.opencas.OpenCASEngine.detach_volume')
    def test_detach_volume(self, moc_detach, moc_eng_ready):
        conn_info = {
            'data': {
                'device_path': '/dev/sdd',
            }
        }
        moc_detach.return_value = '/dev/sdd'
        moc_eng_ready.return_value = True

        # cacheable == False
        mgr = caches.CacheManager(root_helper=None,
                                  cache_name='opencas',
                                  connection_info=conn_info)
        self.assertEqual('/dev/sdd', mgr.attach_volume())

        # cacheable == True
        conn_info['data']['cacheable'] = True
        mgr = caches.CacheManager(root_helper=None,
                                  cache_name='opencas',
                                  connection_info=conn_info)
        self.assertEqual('/dev/sdd', mgr.detach_volume())
