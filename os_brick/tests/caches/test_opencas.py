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

from oslo_concurrency import processutils as putils

from os_brick.caches import opencas
from os_brick import exception
from os_brick.tests import base


class OpenCASEngineTestCase(base.TestCase):
    def setUp(self):
        super(OpenCASEngineTestCase, self).setUp()
        self.connection_info = {
            "data": {
                "device_path": "/dev/disk/by-path/"
                "ip-192.0.2.0:3260-iscsi-iqn.2010-10.org.openstack"
                ":volume-fake_uuid-lun-1",
            },
        }
        self.root_helper = None

    @mock.patch('os_brick.executor.Executor._execute')
    def test_os_execute_exception(self, mock_execute):
        raise_err = [
            putils.ProcessExecutionError(exit_code=1),
            mock.DEFAULT,
        ]
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)

        mock_execute.side_effect = raise_err
        self.assertRaises(putils.ProcessExecutionError,
                          engine.os_execute, 'cmd', 'param')
        mock_execute.side_effect = raise_err
        self.assertRaises(putils.ProcessExecutionError,
                          engine.is_engine_ready)
        mock_execute.side_effect = raise_err
        self.assertRaises(putils.ProcessExecutionError,
                          engine._get_mapped_casdev, 'path')
        mock_execute.side_effect = raise_err
        self.assertRaises(putils.ProcessExecutionError,
                          engine._get_mapped_coredev, 'path')
        mock_execute.side_effect = raise_err
        self.assertRaises(putils.ProcessExecutionError,
                          engine._map_casdisk, 'path')
        mock_execute.side_effect = raise_err
        self.assertRaises(putils.ProcessExecutionError,
                          engine._unmap_casdisk, 'path')

    @mock.patch('os_brick.executor.Executor._execute')
    def test_is_engine_ready(self, moc_exec):
        out_ready = """type  id  disk  status  write policy  device
        cache  1  /dev/nvme0n1  Running  wt  -"""
        out_not_ready = 'type  id  disk  status  write policy  device'
        err = ''
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)

        moc_exec.return_value = (out_ready, err)
        ret = engine.is_engine_ready()
        self.assertTrue(ret)

        moc_exec.return_value = (out_not_ready, err)
        ret = engine.is_engine_ready()
        self.assertFalse(ret)

        moc_exec.assert_has_calls([
            mock.call('casadm', '-L', run_as_root=True, root_helper=None)
        ])

    @mock.patch('os_brick.executor.Executor._execute')
    def test_get_mapped_casdev(self, moc_exec):
        out_ready = """type  id  disk  status  write policy  device
        cache  1  /dev/nvme0n1  Running  wt  -
        └core  1  /dev/sdd      Active   -   /dev/cas1-1"""
        err = ''
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)

        moc_exec.return_value = (out_ready, err)
        ret1 = engine._get_mapped_casdev('/dev/sdd')
        self.assertEqual('/dev/cas1-1', ret1)

    @mock.patch('os_brick.executor.Executor._execute')
    def test_get_mapped_coredev(self, moc_exec):
        out_ready = """type  id  disk  status  write policy  device
        cache  1  /dev/nvme0n1  Running  wt  -
        └core  1  /dev/sdd      Active   -   /dev/cas1-1"""
        err = ''
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)

        moc_exec.return_value = (out_ready, err)
        ret1, ret2 = engine._get_mapped_coredev('/dev/cas1-1')
        self.assertEqual('1', ret1)
        self.assertEqual('/dev/sdd', ret2)

    @mock.patch('os_brick.executor.Executor._execute')
    @mock.patch('os_brick.caches.opencas.OpenCASEngine._get_mapped_casdev')
    def test_map_casdisk(self, moc_get_mapped_casdev, moc_exec):
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)

        moc_get_mapped_casdev.return_value = ''
        moc_exec.return_value = ('', '')
        engine._map_casdisk('/dev/sdd')
        moc_exec.assert_has_calls([
            mock.call('casadm', '-A', '-i', 1, '-d', '/dev/sdd',
                      run_as_root=True, root_helper=None)
        ])

    @mock.patch('os_brick.executor.Executor._execute')
    def test_unmap_casdisk(self, moc_exec):
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)

        moc_exec.return_value = ('', '')
        engine._unmap_casdisk('1')

        moc_exec.assert_has_calls([
            mock.call('casadm', '-R', '-f', '-i', 1, '-j', '1',
                      run_as_root=True, root_helper=None)
        ])

    @mock.patch('os_brick.caches.opencas.OpenCASEngine._map_casdisk')
    def test_attach_volume(self, moc_map):
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)
        moc_map.return_value = ''

        args = {'no_dev_path': 'path'}
        self.assertRaises(exception.VolumePathsNotFound,
                          engine.attach_volume, **args)
        self.assertRaises(exception.VolumePathsNotFound, engine.attach_volume)

        # No exception if dev_path set correctly
        args = {'dev_path': 'path'}
        engine.attach_volume(**args)

    @mock.patch('os_brick.executor.Executor._execute')
    def test_detach_volume(self, moc_exec):
        out_ready = """type  id  disk  status  write policy  device
        cache  1  /dev/nvme0n1  Running  wt  -
        └core  1  /dev/sdd      Active   -   /dev/cas1-1"""
        err = ''
        engine = opencas.OpenCASEngine(root_helper=None, opencas_cache_id=1)

        moc_exec.return_value = (out_ready, err)

        args = {'no_dev_path': 'path'}
        self.assertRaises(exception.VolumePathsNotFound,
                          engine.detach_volume, **args)
        self.assertRaises(exception.VolumePathsNotFound, engine.detach_volume)
        # No exception if dev_path set correctly
        args = {'dev_path': '/dev/cas1-1'}
        engine.detach_volume(**args)
