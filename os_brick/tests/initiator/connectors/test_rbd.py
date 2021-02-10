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
from unittest import mock

import ddt

from os_brick import exception
from os_brick.initiator.connectors import rbd
from os_brick.initiator import linuxrbd
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests.initiator.connectors import test_base_rbd
from os_brick.tests.initiator import test_connector
from os_brick import utils


@ddt.ddt
class RBDConnectorTestCase(test_base_rbd.RBDConnectorTestMixin,
                           test_connector.ConnectorTestCase):

    def test_get_search_path(self):
        rbd_connector = rbd.RBDConnector(None)
        path = rbd_connector.get_search_path()
        self.assertIsNone(path)

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    def test_get_volume_paths(self, mock_rados, mock_rbd):
        rbd_connector = rbd.RBDConnector(None)
        expected = []
        actual = rbd_connector.get_volume_paths(self.connection_properties)
        self.assertEqual(expected, actual)

    def test_get_connector_properties(self):
        props = rbd.RBDConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {'do_local_attach': False}
        self.assertEqual(expected_props, props)

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    @mock.patch.object(rbd.RBDConnector, '_create_ceph_conf')
    @mock.patch('os.path.exists')
    def test_connect_volume(self, mock_path, mock_conf, mock_rados, mock_rbd):
        """Test the connect volume case."""
        rbd_connector = rbd.RBDConnector(None)
        mock_path.return_value = False
        mock_conf.return_value = "/tmp/fake_dir/fake_ceph.conf"
        device_info = rbd_connector.connect_volume(self.connection_properties)

        # Ensure rados is instantiated correctly
        mock_rados.Rados.assert_called_once_with(
            clustername=self.clustername,
            rados_id=utils.convert_str(self.user),
            conffile='/tmp/fake_dir/fake_ceph.conf')

        # Ensure correct calls to connect to cluster
        self.assertEqual(1, mock_rados.Rados.return_value.connect.call_count)
        mock_rados.Rados.return_value.open_ioctx.assert_called_once_with(
            utils.convert_str(self.pool))

        # Ensure rbd image is instantiated correctly
        mock_rbd.Image.assert_called_once_with(
            mock_rados.Rados.return_value.open_ioctx.return_value,
            utils.convert_str(self.volume), read_only=False,
            snapshot=None)

        # Ensure expected object is returned correctly
        self.assertIsInstance(device_info['path'],
                              linuxrbd.RBDVolumeIOWrapper)

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    @mock.patch.object(rbd.RBDConnector, '_create_ceph_conf')
    @mock.patch('os.path.exists')
    def test_provided_keyring(self, mock_path, mock_conf, mock_rados,
                              mock_rbd):
        conn = rbd.RBDConnector(None)
        mock_path.return_value = False
        mock_conf.return_value = "/tmp/fake_dir/fake_ceph.conf"
        self.connection_properties['keyring'] = self.keyring
        conn.connect_volume(self.connection_properties)
        mock_conf.assert_called_once_with(self.hosts, self.ports,
                                          self.clustername, self.user,
                                          self.keyring)

    def test_keyring_is_none(self):
        conn = rbd.RBDConnector(None)
        keyring = None
        keyring_data = "[client.cinder]\n  key = test\n"
        mockopen = mock.mock_open(read_data=keyring_data)
        mockopen.return_value.__exit__ = mock.Mock()
        with mock.patch('os_brick.initiator.connectors.rbd.open', mockopen,
                        create=True):
            self.assertEqual(
                conn._check_or_get_keyring_contents(keyring, 'cluster',
                                                    'user'), keyring_data)
            self.assertEqual(
                conn._check_or_get_keyring_contents(keyring, 'cluster',
                                                    None), '')

    def test_keyring_raise_error(self):
        conn = rbd.RBDConnector(None)
        keyring = None
        mockopen = mock.mock_open()
        mockopen.return_value = ""
        with mock.patch('os_brick.initiator.connectors.rbd.open', mockopen,
                        create=True) as mock_keyring_file:
            mock_keyring_file.side_effect = IOError
            self.assertRaises(exception.BrickException,
                              conn._check_or_get_keyring_contents, keyring,
                              'cluster', 'user')

    @mock.patch('os_brick.initiator.connectors.rbd.tempfile.mkstemp')
    def test_create_ceph_conf(self, mock_mkstemp):
        mockopen = mock.mock_open()
        fd = mock.sentinel.fd
        tmpfile = mock.sentinel.tmpfile
        mock_mkstemp.return_value = (fd, tmpfile)

        with mock.patch('os.fdopen', mockopen, create=True):
            rbd_connector = rbd.RBDConnector(None)
            conf_path = rbd_connector._create_ceph_conf(
                self.hosts, self.ports, self.clustername, self.user,
                self.keyring)
        self.assertEqual(conf_path, tmpfile)
        mock_mkstemp.assert_called_once_with(prefix='brickrbd_')
        # Bug #1865754 - make sure generated config file has a '[global]'
        # section
        _, args, _ = mockopen().writelines.mock_calls[0]
        self.assertIn('[global]', args[0])

    @mock.patch('os_brick.privileged.rbd.root_create_ceph_conf')
    def test_create_non_openstack_config(self, mock_priv_create):
        res = rbd.RBDConnector.create_non_openstack_config(
            self.connection_properties)
        mock_priv_create.assert_called_once_with(self.hosts, self.ports,
                                                 self.clustername, self.user,
                                                 self.keyring)
        self.assertIs(mock_priv_create.return_value, res)

    @mock.patch('os_brick.privileged.rbd.root_create_ceph_conf')
    def test_create_non_openstack_config_in_openstack(self, mock_priv_create):
        connection_properties = self.connection_properties.copy()
        del connection_properties['keyring']
        res = rbd.RBDConnector.create_non_openstack_config(
            connection_properties)
        mock_priv_create.assert_not_called()
        self.assertIsNone(res)

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_connect_local_volume(self, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image',
                'auth_username': 'fake_user',
                'hosts': ['192.168.10.2'],
                'ports': ['6789']}
        device_info = rbd_connector.connect_volume(conn)
        execute_call1 = mock.call('which', 'rbd')
        cmd = ['rbd', 'map', 'image', '--pool', 'pool', '--id', 'fake_user',
               '--mon_host', '192.168.10.2:6789']
        execute_call2 = mock.call(*cmd, root_helper=None, run_as_root=True)
        mock_execute.assert_has_calls([execute_call1, execute_call2])
        expected_info = {'path': '/dev/rbd/pool/image',
                         'type': 'block'}
        self.assertEqual(expected_info, device_info)

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    @mock.patch('os.path.exists')
    @mock.patch('os.path.islink')
    @mock.patch('os.path.realpath')
    def test_connect_local_volume_dev_exist(self, mock_realpath, mock_islink,
                                            mock_exists, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image',
                'auth_username': 'fake_user',
                'hosts': ['192.168.10.2'],
                'ports': ['6789']}
        mock_realpath.return_value = '/dev/rbd0'
        mock_islink.return_value = True
        mock_exists.return_value = True
        device_info = rbd_connector.connect_volume(conn)
        execute_call1 = mock.call('which', 'rbd')
        cmd = ['rbd', 'map', 'image', '--pool', 'pool', '--id', 'fake_user',
               '--mon_host', '192.168.10.2:6789']
        execute_call2 = mock.call(*cmd, root_helper=None, run_as_root=True)
        mock_execute.assert_has_calls([execute_call1])
        self.assertNotIn(execute_call2, mock_execute.mock_calls)
        expected_info = {'path': '/dev/rbd/pool/image',
                         'type': 'block'}
        self.assertEqual(expected_info, device_info)

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_connect_local_volume_without_mons(self, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image',
                'auth_username': 'fake_user'}
        device_info = rbd_connector.connect_volume(conn)
        execute_call1 = mock.call('which', 'rbd')
        cmd = ['rbd', 'map', 'image', '--pool', 'pool', '--id', 'fake_user']
        execute_call2 = mock.call(*cmd, root_helper=None, run_as_root=True)
        mock_execute.assert_has_calls([execute_call1, execute_call2])
        expected_info = {'path': '/dev/rbd/pool/image',
                         'type': 'block'}
        self.assertEqual(expected_info, device_info)

    @mock.patch('os_brick.initiator.connectors.rbd.'
                'RBDConnector._local_attach_volume')
    def test_connect_volume_local(self, mock_local_attach):
        connector = rbd.RBDConnector(None, do_local_attach=True)
        res = connector.connect_volume(self.connection_properties)
        mock_local_attach.assert_called_once_with(self.connection_properties)
        self.assertIs(mock_local_attach.return_value, res)

    @mock.patch.object(rbd.RBDConnector, '_get_rbd_args')
    @mock.patch.object(rbd.RBDConnector, 'create_non_openstack_config')
    @mock.patch.object(rbd.RBDConnector, '_execute')
    def test__local_attach_volume_non_openstack(self, mock_execute,
                                                mock_rbd_cfg, mock_args):
        mock_args.return_value = [mock.sentinel.rbd_args]

        connector = rbd.RBDConnector(None, do_local_attach=True)
        res = connector._local_attach_volume(self.connection_properties)

        mock_rbd_cfg.assert_called_once_with(self.connection_properties)
        mock_args.assert_called_once_with(self.connection_properties,
                                          mock_rbd_cfg.return_value)
        self.assertEqual(2, mock_execute.call_count)
        mock_execute.assert_has_calls([
            mock.call('which', 'rbd'),
            mock.call('rbd', 'map', 'fake_volume', '--pool', 'fake_pool',
                      mock.sentinel.rbd_args,
                      root_helper=connector._root_helper, run_as_root=True)
        ])

        expected = {'path': '/dev/rbd/fake_pool/fake_volume',
                    'type': 'block',
                    'conf': mock_rbd_cfg.return_value}
        self.assertEqual(expected, res)

    @mock.patch('os_brick.privileged.rbd.delete_if_exists')
    @mock.patch.object(rbd.RBDConnector, '_get_rbd_args')
    @mock.patch.object(rbd.RBDConnector, 'create_non_openstack_config')
    @mock.patch.object(rbd.RBDConnector, '_execute')
    def test__local_attach_volume_fail_non_openstack(self, mock_execute,
                                                     mock_rbd_cfg, mock_args,
                                                     mock_delete):
        mock_args.return_value = [mock.sentinel.rbd_args]
        mock_execute.side_effect = [None, ValueError]

        connector = rbd.RBDConnector(None, do_local_attach=True)
        self.assertRaises(ValueError, connector._local_attach_volume,
                          self.connection_properties)

        mock_rbd_cfg.assert_called_once_with(self.connection_properties)
        mock_args.assert_called_once_with(self.connection_properties,
                                          mock_rbd_cfg.return_value)
        self.assertEqual(2, mock_execute.call_count)
        mock_execute.assert_has_calls([
            mock.call('which', 'rbd'),
            mock.call('rbd', 'map', 'fake_volume', '--pool', 'fake_pool',
                      mock.sentinel.rbd_args,
                      root_helper=connector._root_helper, run_as_root=True)
        ])

        mock_delete.assert_called_once_with(mock_rbd_cfg.return_value)

    @mock.patch('os_brick.initiator.linuxrbd.rbd')
    @mock.patch('os_brick.initiator.linuxrbd.rados')
    @mock.patch.object(linuxrbd.RBDVolumeIOWrapper, 'close')
    def test_disconnect_volume(self, volume_close, mock_rados, mock_rbd):
        """Test the disconnect volume case."""
        rbd_connector = rbd.RBDConnector(None)
        device_info = rbd_connector.connect_volume(self.connection_properties)
        rbd_connector.disconnect_volume(
            self.connection_properties, device_info)

        self.assertEqual(1, volume_close.call_count)

    @ddt.data(
        """
        [{"id":"0","pool":"pool","device":"/dev/rbd0","name":"image"},
         {"id":"1","pool":"pool","device":"/dev/rdb1","name":"image_2"}]
        """,  # new-style output (ceph 13.2.0+)
        """
        {"0":{"pool":"pool","device":"/dev/rbd0","name":"image"},
         "1":{"pool":"pool","device":"/dev/rdb1","name":"image_2"}}
        """,  # old-style output
    )
    @mock.patch('os_brick.privileged.rbd.delete_if_exists')
    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_disconnect_local_volume(self, rbd_map_out, mock_execute,
                                     mock_delete):
        """Test the disconnect volume case with local attach."""
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image',
                'auth_username': 'fake_user',
                'hosts': ['192.168.10.2'],
                'ports': ['6789']}
        mock_execute.side_effect = [(rbd_map_out, None), (None, None)]
        show_cmd = ['rbd', 'showmapped', '--format=json', '--id', 'fake_user',
                    '--mon_host', '192.168.10.2:6789']
        unmap_cmd = ['rbd', 'unmap', '/dev/rbd0', '--id', 'fake_user',
                     '--mon_host', '192.168.10.2:6789']

        rbd_connector.disconnect_volume(conn, None)

        # Assert that showmapped is used before we unmap the root device
        mock_execute.assert_has_calls([
            mock.call(*show_cmd, root_helper=None, run_as_root=True),
            mock.call(*unmap_cmd, root_helper=None, run_as_root=True)])

        mock_delete.assert_not_called()

    @mock.patch('os_brick.privileged.rbd.delete_if_exists')
    @mock.patch.object(rbd.RBDConnector, '_find_root_device')
    @mock.patch.object(rbd.RBDConnector, '_execute')
    def test_disconnect_local_volume_non_openstack(self, mock_execute,
                                                   mock_find, mock_delete):
        connector = rbd.RBDConnector(None, do_local_attach=True)
        mock_find.return_value = '/dev/rbd0'

        connector.disconnect_volume(self.connection_properties,
                                    {'conf': mock.sentinel.conf})

        mock_find.assert_called_once_with(self.connection_properties,
                                          mock.sentinel.conf)

        mock_execute.assert_called_once_with(
            'rbd', 'unmap', '/dev/rbd0', '--id', 'fake_user', '--mon_host',
            '192.168.10.2:6789', '--conf', mock.sentinel.conf,
            root_helper=connector._root_helper, run_as_root=True)
        mock_delete.assert_called_once_with(mock.sentinel.conf)

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_disconnect_local_volume_no_mapping(self, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/not_mapped',
                'auth_username': 'fake_user',
                'hosts': ['192.168.10.2'],
                'ports': ['6789']}
        mock_execute.return_value = ("""
{"0":{"pool":"pool","device":"/dev/rbd0","name":"pool-image"},
 "1":{"pool":"pool","device":"/dev/rdb1","name":"pool-image_2"}}""", None)
        show_cmd = ['rbd', 'showmapped', '--format=json', '--id', 'fake_user',
                    '--mon_host', '192.168.10.2:6789']
        rbd_connector.disconnect_volume(conn, None)

        # Assert that only showmapped is called when no mappings are found
        mock_execute.called_once_with(*show_cmd, root_helper=None,
                                      run_as_root=True)

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_disconnect_local_volume_no_mappings(self, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image',
                'auth_username': 'fake_user',
                'hosts': ['192.168.10.2'],
                'ports': ['6789']}
        mock_execute.return_value = ("{}", None)
        show_cmd = ['rbd', 'showmapped', '--format=json', '--id', 'fake_user',
                    '--mon_host', '192.168.10.2:6789']
        rbd_connector.disconnect_volume(conn, None)

        # Assert that only showmapped is called when no mappings are found
        mock_execute.called_once_with(*show_cmd, root_helper=None,
                                      run_as_root=True)

    @mock.patch('oslo_utils.fileutils.delete_if_exists')
    @mock.patch.object(rbd.RBDConnector, '_get_rbd_handle')
    def test_extend_volume_handle(self, mock_handle, mock_delete):
        connector = rbd.RBDConnector(None)
        res = connector.extend_volume(self.connection_properties)

        mock_handle.assert_called_once_with(self.connection_properties)
        mock_handle.return_value.seek.assert_called_once_with(0, 2)
        mock_handle.return_value.tell.assert_called_once_with()
        self.assertIs(mock_handle().tell(), res)
        mock_delete.assert_called_once_with(mock_handle().rbd_conf)
        mock_handle.return_value.close.assert_called_once_with()

    @mock.patch('oslo_utils.fileutils.delete_if_exists')
    @mock.patch.object(rbd.RBDConnector, '_get_rbd_handle')
    def test_extend_volume_handle_fail(self, mock_handle, mock_delete):
        mock_handle.return_value.seek.side_effect = ValueError
        connector = rbd.RBDConnector(None)

        self.assertRaises(ValueError, connector.extend_volume,
                          self.connection_properties)

        mock_handle.assert_called_once_with(self.connection_properties)
        mock_handle.return_value.seek.assert_called_once_with(0, 2)
        mock_handle().tell.assert_not_called()
        mock_delete.assert_called_once_with(mock_handle.return_value.rbd_conf)
        mock_handle.return_value.close.assert_called_once_with()

    @mock.patch.object(rbd, 'open')
    @mock.patch('os_brick.privileged.rbd.delete_if_exists')
    @mock.patch.object(rbd.RBDConnector, '_find_root_device')
    @mock.patch.object(rbd.RBDConnector, 'create_non_openstack_config')
    def test_extend_volume_block(self, mock_config, mock_find, mock_delete,
                                 mock_open):
        mock_find.return_value = '/dev/rbd1'
        file_handle = mock_open.return_value.__enter__.return_value
        file_handle.read.return_value = '123456789'
        connector = rbd.RBDConnector(None, do_local_attach=True)

        res = connector.extend_volume(self.connection_properties)

        mock_config.assert_called_once_with(self.connection_properties)
        mock_find.assert_called_once_with(self.connection_properties,
                                          mock_config.return_value)
        mock_delete.assert_called_once_with(mock_config.return_value)
        mock_open.assert_called_once_with('/sys/devices/rbd/1/size')
        file_handle.read.assert_called_once_with()
        self.assertEqual(123456789, res)

    @mock.patch.object(rbd, 'open')
    @mock.patch('os_brick.privileged.rbd.delete_if_exists')
    @mock.patch.object(rbd.RBDConnector, '_find_root_device')
    @mock.patch.object(rbd.RBDConnector, 'create_non_openstack_config')
    def test_extend_volume_no_device_local(self, mock_config, mock_find,
                                           mock_delete, mock_open):
        mock_find.return_value = None
        connector = rbd.RBDConnector(None, do_local_attach=True)
        self.assertRaises(exception.BrickException, connector.extend_volume,
                          self.connection_properties)

        mock_config.assert_called_once_with(self.connection_properties)
        mock_find.assert_called_once_with(self.connection_properties,
                                          mock_config.return_value)
        mock_delete.assert_called_once_with(mock_config.return_value)
        mock_open.assert_not_called()

    @mock.patch.object(rbd.RBDConnector, '_get_rbd_args')
    @mock.patch.object(rbd.RBDConnector, '_execute')
    def test_find_root_device(self, mock_execute, mock_args):
        mock_args.return_value = [mock.sentinel.rbd_args]
        mock_execute.return_value = (
            '{"0":{"pool":"pool","device":"/dev/rdb0","name":"image"},'
            '"1":{"pool":"pool","device":"/dev/rbd1","name":"fake_volume"}}',
            'stderr')

        connector = rbd.RBDConnector(None)
        res = connector._find_root_device(self.connection_properties,
                                          mock.sentinel.conf)

        mock_args.assert_called_once_with(self.connection_properties,
                                          mock.sentinel.conf)
        mock_execute.assert_called_once_with(
            'rbd', 'showmapped', '--format=json', mock.sentinel.rbd_args,
            root_helper=connector._root_helper, run_as_root=True)
        self.assertEqual('/dev/rbd1', res)

    @mock.patch.object(rbd.RBDConnector, '_check_valid_device')
    @mock.patch('os_brick.privileged.rbd.check_valid_path')
    @mock.patch.object(rbd, 'open')
    def test_check_valid_device_handle_no_path(self, mock_open, check_path,
                                               check_device):
        connector = rbd.RBDConnector(None)
        res = connector.check_valid_device(None)

        self.assertFalse(res)
        mock_open.assert_not_called()
        check_path.assert_not_called()
        check_device.assert_not_called()

    @ddt.data(True, False)
    @mock.patch.object(rbd.RBDConnector, '_check_valid_device')
    @mock.patch('os_brick.privileged.rbd.check_valid_path')
    @mock.patch.object(rbd, 'open')
    def test_check_valid_device_handle(self, run_as_root, mock_open,
                                       check_path, check_device):
        connector = rbd.RBDConnector(None)
        res = connector.check_valid_device(mock.sentinel.handle,
                                           run_as_root=run_as_root)
        check_device.assert_called_once_with(mock.sentinel.handle)
        self.assertIs(check_device.return_value, res)
        mock_open.assert_not_called()
        check_path.assert_not_called()

    @mock.patch.object(rbd.RBDConnector, '_check_valid_device')
    @mock.patch('os_brick.privileged.rbd.check_valid_path')
    @mock.patch.object(rbd, 'open')
    def test_check_valid_device_block_root(self, mock_open, check_path,
                                           check_device):
        connector = rbd.RBDConnector(None)
        path = '/dev/rbd0'
        res = connector.check_valid_device(path, run_as_root=True)

        check_path.assert_called_once_with(path)
        self.assertEqual(check_path.return_value, res)
        mock_open.assert_not_called()
        check_device.assert_not_called()

    @mock.patch.object(rbd.RBDConnector, '_check_valid_device')
    @mock.patch('os_brick.privileged.rbd.check_valid_path')
    @mock.patch.object(rbd, 'open')
    def test_check_valid_device_block_non_root(self, mock_open, check_path,
                                               check_device):
        connector = rbd.RBDConnector(None)
        path = '/dev/rbd0'
        res = connector.check_valid_device(path, run_as_root=False)

        mock_open.assert_called_once_with(path, 'rb')
        check_device.assert_called_once_with(mock_open().__enter__())
        self.assertIs(check_device.return_value, res)
        check_path.assert_not_called()
