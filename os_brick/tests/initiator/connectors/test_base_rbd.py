# Copyright 2020 Cloudbase Solutions Srl
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

import ddt

from os_brick.initiator.connectors import base_rbd
from os_brick.tests import base


# Both Linux and Windows tests are using those mocks.
class RBDConnectorTestMixin(object):
    def setUp(self):
        super(RBDConnectorTestMixin, self).setUp()

        self.user = 'fake_user'
        self.pool = 'fake_pool'
        self.volume = 'fake_volume'
        self.clustername = 'fake_ceph'
        self.hosts = ['192.168.10.2']
        self.ports = ['6789']
        self.keyring = "[client.cinder]\n  key = test\n"
        self.image_name = '%s/%s' % (self.pool, self.volume)

        self.connection_properties = {
            'auth_username': self.user,
            'name': self.image_name,
            'cluster_name': self.clustername,
            'hosts': self.hosts,
            'ports': self.ports,
            'keyring': self.keyring,
        }


@ddt.ddt
class TestRBDConnectorMixin(RBDConnectorTestMixin, base.TestCase):
    def setUp(self):
        super(TestRBDConnectorMixin, self).setUp()

        self._conn = base_rbd.RBDConnectorMixin()

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
        self.assertEqual(hosts_out, self._conn._sanitize_mon_hosts(hosts_in))

    def test_get_rbd_args(self):
        res = self._conn._get_rbd_args(self.connection_properties, None)
        expected = ['--id', self.user,
                    '--mon_host', self.hosts[0] + ':' + self.ports[0]]
        self.assertEqual(expected, res)

    def test_get_rbd_args_with_conf(self):
        res = self._conn._get_rbd_args(self.connection_properties,
                                       mock.sentinel.conf_path)
        expected = ['--id', self.user,
                    '--mon_host', self.hosts[0] + ':' + self.ports[0],
                    '--conf', mock.sentinel.conf_path]
        self.assertEqual(expected, res)
