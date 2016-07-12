# encoding=utf8
# (c) Copyright 2015 Hewlett-Packard Development Company, L.P.
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

# import time

import mock
from oslo_concurrency import processutils as putils
import six
import testtools

from os_brick import executor as brick_executor
from os_brick.privileged import rootwrap
from os_brick.tests import base


class TestExecutor(base.TestCase):
    def test_default_execute(self):
        executor = brick_executor.Executor(root_helper=None)
        self.assertEqual(rootwrap.execute, executor._Executor__execute)

    def test_none_execute(self):
        executor = brick_executor.Executor(root_helper=None, execute=None)
        self.assertEqual(rootwrap.execute, executor._Executor__execute)

    def test_fake_execute(self):
        mock_execute = mock.Mock()
        executor = brick_executor.Executor(root_helper=None,
                                           execute=mock_execute)
        self.assertEqual(mock_execute, executor._Executor__execute)

    @mock.patch('sys.stdin', encoding='UTF-8')
    @mock.patch('os_brick.executor.priv_rootwrap.execute')
    def test_execute_non_safe_str_exception(self, execute_mock, stdin_mock):
        execute_mock.side_effect = putils.ProcessExecutionError(
            stdout='España', stderr='Zürich')

        executor = brick_executor.Executor(root_helper=None)
        exc = self.assertRaises(putils.ProcessExecutionError,
                                executor._execute)
        self.assertEqual(u'Espa\xf1a', exc.stdout)
        self.assertEqual(u'Z\xfcrich', exc.stderr)

    @mock.patch('sys.stdin', encoding='UTF-8')
    @mock.patch('os_brick.executor.priv_rootwrap.execute')
    def test_execute_non_safe_str(self, execute_mock, stdin_mock):
        execute_mock.return_value = ('España', 'Zürich')

        executor = brick_executor.Executor(root_helper=None)
        stdout, stderr = executor._execute()
        self.assertEqual(u'Espa\xf1a', stdout)
        self.assertEqual(u'Z\xfcrich', stderr)

    @testtools.skipUnless(six.PY3, 'Specific test for Python 3')
    @mock.patch('sys.stdin', encoding='UTF-8')
    @mock.patch('os_brick.executor.priv_rootwrap.execute')
    def test_execute_non_safe_bytes_exception(self, execute_mock, stdin_mock):
        execute_mock.side_effect = putils.ProcessExecutionError(
            stdout=six.binary_type('España', 'utf-8'),
            stderr=six.binary_type('Zürich', 'utf-8'))

        executor = brick_executor.Executor(root_helper=None)
        exc = self.assertRaises(putils.ProcessExecutionError,
                                executor._execute)
        self.assertEqual(u'Espa\xf1a', exc.stdout)
        self.assertEqual(u'Z\xfcrich', exc.stderr)

    @testtools.skipUnless(six.PY3, 'Specific test for Python 3')
    @mock.patch('sys.stdin', encoding='UTF-8')
    @mock.patch('os_brick.executor.priv_rootwrap.execute')
    def test_execute_non_safe_bytes(self, execute_mock, stdin_mock):
        execute_mock.return_value = (six.binary_type('España', 'utf-8'),
                                     six.binary_type('Zürich', 'utf-8'))

        executor = brick_executor.Executor(root_helper=None)
        stdout, stderr = executor._execute()
        self.assertEqual(u'Espa\xf1a', stdout)
        self.assertEqual(u'Z\xfcrich', stderr)
