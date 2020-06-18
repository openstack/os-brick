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
from os_brick.tests.initiator import test_connector
from os_brick import utils


@ddt.ddt
class RBDConnectorTestCase(test_connector.ConnectorTestCase):

    def setUp(self):
        super(RBDConnectorTestCase, self).setUp()

        self.user = 'fake_user'
        self.pool = 'fake_pool'
        self.volume = 'fake_volume'
        self.clustername = 'fake_ceph'
        self.hosts = ['192.168.10.2']
        self.ports = ['6789']
        self.keyring = "[client.cinder]\n  key = test\n"

        self.connection_properties = {
            'auth_username': self.user,
            'name': '%s/%s' % (self.pool, self.volume),
            'cluster_name': self.clustername,
            'hosts': self.hosts,
            'ports': self.ports,
            'keyring': self.keyring,
        }

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

    @ddt.data((['192.168.1.1', '192.168.1.2'],
               ['192.168.1.1', '192.168.1.2']),
              (['3ffe:1900:4545:3:200:f8ff:fe21:67cf',
                'fe80:0:0:0:200:f8ff:fe21:67cf'],
               ['[3ffe:1900:4545:3:200:f8ff:fe21:67cf]',
                '[fe80:0:0:0:200:f8ff:fe21:67cf]']),
              (['foobar', 'fizzbuzz'], ['foobar', 'fizzbuzz']),
              (['192.168.1.1',
                '3ffe:1900:4545:3:200:f8ff:fe21:67cf',
                'hello, world!'],
               ['192.168.1.1',
                '[3ffe:1900:4545:3:200:f8ff:fe21:67cf]',
                'hello, world!']))
    @ddt.unpack
    def test_sanitize_mon_host(self, hosts_in, hosts_out):
        conn = rbd.RBDConnector(None)
        self.assertEqual(hosts_out, conn._sanitize_mon_hosts(hosts_in))

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
        self.assertFalse(execute_call2 in mock_execute.mock_calls)
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

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_connect_local_volume_without_auth(self, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image',
                'hosts': ['192.168.10.2'],
                'ports': ['6789']}
        self.assertRaises(exception.BrickException,
                          rbd_connector.connect_volume,
                          conn)

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
    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_disconnect_local_volume(self, rbd_map_out, mock_execute):
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

    def test_extend_volume(self):
        rbd_connector = rbd.RBDConnector(None)
        self.assertRaises(NotImplementedError,
                          rbd_connector.extend_volume,
                          self.connection_properties)
