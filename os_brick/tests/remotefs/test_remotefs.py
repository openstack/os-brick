# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os
import tempfile
from unittest import mock

from oslo_concurrency import processutils as putils
import six

from os_brick import exception
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.remotefs import remotefs
from os_brick.tests import base


class RemoteFsClientTestCase(base.TestCase):

    def setUp(self):
        super(RemoteFsClientTestCase, self).setUp()
        self.mock_execute = self.mock_object(priv_rootwrap, 'execute',
                                             return_value=None)

    @mock.patch.object(remotefs.RemoteFsClient, '_read_mounts',
                       return_value=[])
    def test_cifs(self, mock_read_mounts):
        client = remotefs.RemoteFsClient("cifs", root_helper='true',
                                         smbfs_mount_point_base='/mnt')
        share = '10.0.0.1:/qwe'
        mount_point = client.get_mount_point(share)
        client.mount(share)
        calls = [mock.call('mkdir', '-p', mount_point, check_exit_code=0),
                 mock.call('mount', '-t', 'cifs', share, mount_point,
                           run_as_root=True, root_helper='true',
                           check_exit_code=0)]
        self.mock_execute.assert_has_calls(calls)

    @mock.patch.object(remotefs.RemoteFsClient, '_read_mounts',
                       return_value=[])
    def test_nfs(self, mock_read_mounts):
        client = remotefs.RemoteFsClient("nfs", root_helper='true',
                                         nfs_mount_point_base='/mnt')
        share = '10.0.0.1:/qwe'
        mount_point = client.get_mount_point(share)
        client.mount(share)
        calls = [mock.call('mkdir', '-p', mount_point, check_exit_code=0),
                 mock.call('mount', '-t', 'nfs', '-o', 'vers=4,minorversion=1',
                           share, mount_point, check_exit_code=0,
                           run_as_root=True, root_helper='true')]
        self.mock_execute.assert_has_calls(calls)

    def test_read_mounts(self):
        mounts = """device1 mnt_point1 ext4 rw,seclabel,relatime 0 0
                    device2 mnt_point2 ext4 rw,seclabel,relatime 0 0"""
        mockopen = mock.mock_open(read_data=mounts)
        mockopen.return_value.__iter__ = lambda self: iter(self.readline, '')
        with mock.patch.object(six.moves.builtins, "open", mockopen,
                               create=True):
            client = remotefs.RemoteFsClient("cifs", root_helper='true',
                                             smbfs_mount_point_base='/mnt')
            ret = client._read_mounts()
        self.assertEqual(ret, {'mnt_point1': 'device1',
                               'mnt_point2': 'device2'})

    @mock.patch.object(priv_rootwrap, 'execute')
    @mock.patch.object(remotefs.RemoteFsClient, '_do_mount')
    def test_mount_already_mounted(self, mock_do_mount, mock_execute):
        share = "10.0.0.1:/share"
        client = remotefs.RemoteFsClient("cifs", root_helper='true',
                                         smbfs_mount_point_base='/mnt')
        mounts = {client.get_mount_point(share): 'some_dev'}
        with mock.patch.object(client, '_read_mounts',
                               return_value=mounts):
            client.mount(share)
            self.assertEqual(mock_do_mount.call_count, 0)
            self.assertEqual(mock_execute.call_count, 0)

    @mock.patch.object(priv_rootwrap, 'execute')
    def test_mount_race(self, mock_execute):
        err_msg = 'mount.nfs: /var/asdf is already mounted'
        mock_execute.side_effect = putils.ProcessExecutionError(stderr=err_msg)
        mounts = {'192.0.2.20:/share': '/var/asdf/'}
        client = remotefs.RemoteFsClient("nfs", root_helper='true',
                                         nfs_mount_point_base='/var/asdf')

        with mock.patch.object(client, '_read_mounts',
                               return_value=mounts):
            client._do_mount('nfs', '192.0.2.20:/share', '/var/asdf')

    @mock.patch.object(priv_rootwrap, 'execute')
    def test_mount_failure(self, mock_execute):
        err_msg = 'mount.nfs: nfs broke'
        mock_execute.side_effect = putils.ProcessExecutionError(stderr=err_msg)
        client = remotefs.RemoteFsClient("nfs", root_helper='true',
                                         nfs_mount_point_base='/var/asdf')
        self.assertRaises(putils.ProcessExecutionError,
                          client._do_mount,
                          'nfs', '192.0.2.20:/share', '/var/asdf')

    def _test_no_mount_point(self, fs_type):
        self.assertRaises(exception.InvalidParameterValue,
                          remotefs.RemoteFsClient,
                          fs_type, root_helper='true')

    def test_no_mount_point_nfs(self):
        self._test_no_mount_point('nfs')

    def test_no_mount_point_cifs(self):
        self._test_no_mount_point('cifs')

    def test_no_mount_point_glusterfs(self):
        self._test_no_mount_point('glusterfs')

    def test_no_mount_point_vzstorage(self):
        self._test_no_mount_point('vzstorage')

    def test_no_mount_point_quobyte(self):
        self._test_no_mount_point('quobyte')

    def test_invalid_fs(self):
        self.assertRaises(exception.ProtocolNotSupported,
                          remotefs.RemoteFsClient,
                          'my_fs', root_helper='true')

    def test_init_sets_mount_base(self):
        client = remotefs.RemoteFsClient("cifs", root_helper='true',
                                         smbfs_mount_point_base='/fake',
                                         cifs_mount_point_base='/fake2')
        # Tests that although the FS type is "cifs", the config option
        # starts with "smbfs_"
        self.assertEqual('/fake', client._mount_base)

    @mock.patch('os_brick.remotefs.remotefs.RemoteFsClient._check_nfs_options')
    def test_init_nfs_calls_check_nfs_options(self, mock_check_nfs_options):
        remotefs.RemoteFsClient("nfs", root_helper='true',
                                nfs_mount_point_base='/fake')
        mock_check_nfs_options.assert_called_once_with()


class VZStorageRemoteFSClientTestVase(RemoteFsClientTestCase):
    @mock.patch.object(remotefs.RemoteFsClient, '_read_mounts',
                       return_value=[])
    def test_vzstorage_by_cluster_name(self, mock_read_mounts):
        client = remotefs.VZStorageRemoteFSClient(
            "vzstorage", root_helper='true', vzstorage_mount_point_base='/mnt')
        share = 'qwe'
        cluster_name = share
        mount_point = client.get_mount_point(share)
        client.mount(share)
        calls = [mock.call('mkdir', '-p', mount_point, check_exit_code=0),
                 mock.call('pstorage-mount', '-c', cluster_name, mount_point,
                           root_helper='true', check_exit_code=0,
                           run_as_root=True)]
        self.mock_execute.assert_has_calls(calls)

    @mock.patch.object(remotefs.RemoteFsClient, '_read_mounts',
                       return_value=[])
    def test_vzstorage_with_auth(self, mock_read_mounts):
        client = remotefs.VZStorageRemoteFSClient(
            "vzstorage", root_helper='true', vzstorage_mount_point_base='/mnt')
        cluster_name = 'qwe'
        password = '123456'
        share = '%s:%s' % (cluster_name, password)
        mount_point = client.get_mount_point(share)
        client.mount(share)
        calls = [mock.call('mkdir', '-p', mount_point, check_exit_code=0),
                 mock.call('pstorage', '-c', cluster_name, 'auth-node', '-P',
                           process_input=password, root_helper='true',
                           run_as_root=True),
                 mock.call('pstorage-mount', '-c', cluster_name, mount_point,
                           root_helper='true', check_exit_code=0,
                           run_as_root=True)]
        self.mock_execute.assert_has_calls(calls)

    @mock.patch('os.path.exists', return_value=False)
    @mock.patch.object(remotefs.RemoteFsClient, '_read_mounts',
                       return_value=[])
    def test_vzstorage_with_mds_list(self, mock_read_mounts, mock_exists):
        client = remotefs.VZStorageRemoteFSClient(
            "vzstorage", root_helper='true', vzstorage_mount_point_base='/mnt')
        cluster_name = 'qwe'
        mds_list = ['10.0.0.1', '10.0.0.2']
        share = '%s:/%s' % (','.join(mds_list), cluster_name)
        mount_point = client.get_mount_point(share)
        vz_conf_dir = os.path.join('/etc/pstorage/clusters/', cluster_name)

        tmp_dir = '/tmp/fake_dir/'

        with mock.patch.object(tempfile, 'mkdtemp',
                               return_value=tmp_dir):
            mock_open = mock.mock_open()
            with mock.patch.object(six.moves.builtins, "open",
                                   mock_open, create=True):
                client.mount(share)

                write_calls = [mock.call(tmp_dir + 'bs_list', 'w'),
                               mock.call().__enter__(),
                               mock.call().write('10.0.0.1\n'),
                               mock.call().write('10.0.0.2\n'),
                               mock.call().__exit__(None, None, None)]

                mock_open.assert_has_calls(write_calls)
        calls = [mock.call('mkdir', '-p', mount_point, check_exit_code=0),
                 mock.call('cp', '-rf', tmp_dir, vz_conf_dir,
                           run_as_root=True, root_helper='true'),
                 mock.call('chown', '-R', 'root:root', vz_conf_dir,
                           run_as_root=True, root_helper='true'),
                 mock.call('pstorage-mount', '-c', cluster_name, mount_point,
                           root_helper='true', check_exit_code=0,
                           run_as_root=True)]
        self.mock_execute.assert_has_calls(calls)

    @mock.patch.object(remotefs.RemoteFsClient, '_read_mounts',
                       return_value=[])
    def test_vzstorage_invalid_share(self, mock_read_mounts):
        client = remotefs.VZStorageRemoteFSClient(
            "vzstorage", root_helper='true', vzstorage_mount_point_base='/mnt')
        self.assertRaises(exception.BrickException, client.mount, ':')


class ScalityRemoteFsClientTestCase(base.TestCase):
    def test_no_mount_point_scality(self):
        self.assertRaises(exception.InvalidParameterValue,
                          remotefs.ScalityRemoteFsClient,
                          'scality', root_helper='true')

    def test_get_mount_point(self):
        fsclient = remotefs.ScalityRemoteFsClient(
            'scality', root_helper='true', scality_mount_point_base='/fake')
        self.assertEqual('/fake/path/00', fsclient.get_mount_point('path'))

    @mock.patch('oslo_concurrency.processutils.execute', return_value=None)
    @mock.patch('os_brick.remotefs.remotefs.RemoteFsClient._do_mount')
    def test_mount(self, mock_do_mount, mock_execute):
        fsclient = remotefs.ScalityRemoteFsClient(
            'scality', root_helper='true', scality_mount_point_base='/fake',
            execute=putils.execute)
        with mock.patch.object(fsclient, '_read_mounts', return_value={}):
            fsclient.mount('fake')

        mock_execute.assert_called_once_with(
            'mkdir', '-p', '/fake', check_exit_code=0)
        mock_do_mount.assert_called_once_with(
            'sofs', '/etc/sfused.conf', '/fake')
