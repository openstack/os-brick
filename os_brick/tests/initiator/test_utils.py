# Copyright 2018 Red Hat, Inc.
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

from os_brick.initiator import utils
from os_brick.tests import base


class InitiatorUtilsTestCase(base.TestCase):

    @mock.patch('os.name', 'nt')
    def test_check_manual_scan_windows(self):
        self.assertFalse(utils.check_manual_scan())

    @mock.patch('os.name', 'posix')
    @mock.patch('oslo_concurrency.processutils.execute')
    def test_check_manual_scan_supported(self, mock_exec):
        self.assertTrue(utils.check_manual_scan())
        mock_exec.assert_called_once_with('grep', '-F', 'node.session.scan',
                                          '/sbin/iscsiadm')

    @mock.patch('os.name', 'posix')
    @mock.patch('oslo_concurrency.processutils.execute',
                side_effect=utils.putils.ProcessExecutionError)
    def test_check_manual_scan_not_supported(self, mock_exec):
        self.assertFalse(utils.check_manual_scan())
        mock_exec.assert_called_once_with('grep', '-F', 'node.session.scan',
                                          '/sbin/iscsiadm')

    @mock.patch('oslo_concurrency.lockutils.lock')
    def test_guard_connection_manual_scan_support(self, mock_lock):
        utils.ISCSI_SUPPORTS_MANUAL_SCAN = True
        # We confirm that shared_targets is ignored
        with utils.guard_connection({'shared_targets': True}):
            mock_lock.assert_not_called()

    @mock.patch('oslo_concurrency.lockutils.lock')
    def test_guard_connection_manual_scan_unsupported_not_shared(self,
                                                                 mock_lock):
        utils.ISCSI_SUPPORTS_MANUAL_SCAN = False
        with utils.guard_connection({'shared_targets': False}):
            mock_lock.assert_not_called()

    @mock.patch('oslo_concurrency.lockutils.lock')
    def test_guard_connection_manual_scan_unsupported_hared(self, mock_lock):
        utils.ISCSI_SUPPORTS_MANUAL_SCAN = False
        with utils.guard_connection({'service_uuid': mock.sentinel.uuid,
                                     'shared_targets': True}):
            mock_lock.assert_called_once_with(mock.sentinel.uuid, 'os-brick-',
                                              external=True)
