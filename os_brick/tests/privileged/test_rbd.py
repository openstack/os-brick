# Copyright (c) 2020, Red Hat, Inc.
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

import os_brick.privileged as privsep_brick
import os_brick.privileged.rbd as privsep_rbd
from os_brick.tests import base


class PrivRBDTestCase(base.TestCase):
    def setUp(self):
        super(PrivRBDTestCase, self).setUp()

        # Disable privsep server/client mode
        privsep_brick.default.set_client_mode(False)
        self.addCleanup(privsep_brick.default.set_client_mode, True)

    @mock.patch('oslo_utils.importutils.import_class')
    def test__get_rbd_class(self, mock_import):
        self.assertIsNone(privsep_rbd.RBDConnector)
        self.assertIs(privsep_rbd._get_rbd_class, privsep_rbd.get_rbd_class)

        self.addCleanup(setattr, privsep_rbd, 'RBDConnector', None)
        self.addCleanup(setattr, privsep_rbd, 'get_rbd_class',
                        privsep_rbd._get_rbd_class)

        privsep_rbd._get_rbd_class()

        mock_import.assert_called_once_with(
            'os_brick.initiator.connectors.rbd.RBDConnector')
        self.assertEqual(mock_import.return_value, privsep_rbd.RBDConnector)
        self.assertIsNot(privsep_rbd._get_rbd_class, privsep_rbd.get_rbd_class)

    @mock.patch.object(privsep_rbd, 'get_rbd_class')
    @mock.patch('oslo_utils.fileutils.delete_if_exists')
    def test_delete_if_exists(self, mock_delete, mock_get_class):
        res = privsep_rbd.delete_if_exists(mock.sentinel.path)

        mock_get_class.assert_not_called()
        mock_delete.assert_called_once_with(mock.sentinel.path)
        self.assertIs(mock_delete.return_value, res)

    @mock.patch.object(privsep_rbd, 'get_rbd_class')
    @mock.patch.object(privsep_rbd, 'RBDConnector')
    def test_root_create_ceph_conf(self, mock_connector, mock_get_class):
        s = mock.sentinel
        res = privsep_rbd.root_create_ceph_conf(s.monitor_ips,
                                                s.monitor_ports,
                                                s.cluster_name, s.user,
                                                s.keyring)

        mock_get_class.assert_called_once_with()
        mock_connector._create_ceph_conf.assert_called_once_with(
            s.monitor_ips, s.monitor_ports, s.cluster_name, s.user, s.keyring)
        self.assertIs(mock_connector._create_ceph_conf.return_value, res)

    @mock.patch.object(privsep_rbd, 'get_rbd_class')
    @mock.patch.object(privsep_rbd, 'open')
    @mock.patch.object(privsep_rbd, 'RBDConnector')
    def test_check_valid_path(self, mock_connector, mock_open, mock_get_class):
        res = privsep_rbd.check_valid_path(mock.sentinel.path)

        mock_get_class.assert_called_once_with()
        mock_open.assert_called_once_with(mock.sentinel.path, 'rb')
        mock_connector._check_valid_device.assert_called_once_with(
            mock_open.return_value.__enter__.return_value)
        self.assertEqual(mock_connector._check_valid_device.return_value, res)
