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
import ddt
import mock

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

        self.connection_properties = {
            'auth_username': self.user,
            'name': '%s/%s' % (self.pool, self.volume),
            'cluster_name': self.clustername,
            'hosts': self.hosts,
            'ports': self.ports,
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
                self.hosts, self.ports, self.clustername, self.user)
        self.assertEqual(conf_path, tmpfile)
        mock_mkstemp.assert_called_once_with(prefix='brickrbd_')

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_connect_local_volume(self, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image'}
        device_info = rbd_connector.connect_volume(conn)
        execute_call1 = mock.call('which', 'rbd')
        cmd = ['rbd', 'map', 'image', '--pool', 'pool']
        execute_call2 = mock.call(*cmd, root_helper=None, run_as_root=True)
        mock_execute.assert_has_calls([execute_call1, execute_call2])
        expected_info = {'path': '/dev/rbd/pool/image',
                         'type': 'block'}
        self.assertEqual(expected_info, device_info)

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

    @mock.patch.object(priv_rootwrap, 'execute', return_value=None)
    def test_disconnect_local_volume(self, mock_execute):
        rbd_connector = rbd.RBDConnector(None, do_local_attach=True)
        conn = {'name': 'pool/image'}
        rbd_connector.disconnect_volume(conn, None)

        dev_name = '/dev/rbd/pool/image'
        cmd = ['rbd', 'unmap', dev_name]
        mock_execute.assert_called_once_with(*cmd, root_helper=None,
                                             run_as_root=True)

    def test_extend_volume(self):
        rbd_connector = rbd.RBDConnector(None)
        self.assertRaises(NotImplementedError,
                          rbd_connector.extend_volume,
                          self.connection_properties)
