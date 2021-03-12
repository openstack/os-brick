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

import threading
from unittest import mock

from oslo_concurrency import processutils as putils
from oslo_context import context as context_utils

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
        self.assertEqual('Espa\xf1a', exc.stdout)
        self.assertEqual('Z\xfcrich', exc.stderr)

    @mock.patch('sys.stdin', encoding='UTF-8')
    @mock.patch('os_brick.executor.priv_rootwrap.execute')
    def test_execute_non_safe_str(self, execute_mock, stdin_mock):
        execute_mock.return_value = ('España', 'Zürich')

        executor = brick_executor.Executor(root_helper=None)
        stdout, stderr = executor._execute()
        self.assertEqual('Espa\xf1a', stdout)
        self.assertEqual('Z\xfcrich', stderr)

    @mock.patch('sys.stdin', encoding='UTF-8')
    @mock.patch('os_brick.executor.priv_rootwrap.execute')
    def test_execute_non_safe_bytes_exception(self, execute_mock, stdin_mock):
        execute_mock.side_effect = putils.ProcessExecutionError(
            stdout=bytes('España', 'utf-8'),
            stderr=bytes('Zürich', 'utf-8'))

        executor = brick_executor.Executor(root_helper=None)
        exc = self.assertRaises(putils.ProcessExecutionError,
                                executor._execute)
        self.assertEqual('Espa\xf1a', exc.stdout)
        self.assertEqual('Z\xfcrich', exc.stderr)

    @mock.patch('sys.stdin', encoding='UTF-8')
    @mock.patch('os_brick.executor.priv_rootwrap.execute')
    def test_execute_non_safe_bytes(self, execute_mock, stdin_mock):
        execute_mock.return_value = (bytes('España', 'utf-8'),
                                     bytes('Zürich', 'utf-8'))

        executor = brick_executor.Executor(root_helper=None)
        stdout, stderr = executor._execute()
        self.assertEqual('Espa\xf1a', stdout)
        self.assertEqual('Z\xfcrich', stderr)


class TestThread(base.TestCase):
    def _store_context(self, result):
        """Stores current thread's context in result list."""
        result.append(context_utils.get_current())

    def _run_threads(self, threads):
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def _do_test(self, thread_class, expected, result=None):
        if result is None:
            result = []
        threads = [thread_class(target=self._store_context, args=[result])
                   for i in range(3)]
        self._run_threads(threads)
        self.assertEqual([expected] * len(threads), result)

    def test_normal_thread(self):
        """Test normal threads don't inherit parent's context."""
        context = context_utils.RequestContext()
        context.update_store()
        self._do_test(threading.Thread, None)

    def test_no_context(self, result=None):
        """Test when parent has no context."""
        context_utils._request_store.context = None
        self._do_test(brick_executor.Thread, None, result)

    def test_with_context(self, result=None):
        """Test that our class actually inherits the context."""
        context = context_utils.RequestContext()
        context.update_store()
        self._do_test(brick_executor.Thread, context, result)

    def _run_test(self, test_method, test_args, result):
        """Run one of the normal tests and store the result.

        Meant to be run in a different thread, thus the need to store the
        result, because by the time the join call completes the test's stack
        is no longer available and the exception will have been lost.
        """
        try:
            test_method(test_args)
            result.append(True)
        except Exception:
            result.append(False)
            raise

    def test_no_cross_mix(self):
        """Test there's no shared global context between threads."""
        result = []
        contexts = [[], [], []]
        threads = [threading.Thread(target=self._run_test,
                                    args=[self.test_with_context,
                                          contexts[0],
                                          result]),
                   threading.Thread(target=self._run_test,
                                    args=[self.test_no_context,
                                          contexts[1],
                                          result]),
                   threading.Thread(target=self._run_test,
                                    args=[self.test_with_context,
                                          contexts[2],
                                          result])]
        self._run_threads(threads)
        # Check that all tests run without raising an exception
        self.assertEqual([True, True, True], result)
        # Check that the context were not shared
        self.assertNotEqual(contexts[0], contexts[2])
