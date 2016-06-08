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

from os_brick import executor as brick_executor
from os_brick.privileged import rootwrap
from os_brick.tests import base


class TestExecutor(base.TestCase):
    def test_default_execute(self):
        executor = brick_executor.Executor(root_helper=None)
        self.assertEqual(rootwrap.execute, executor._execute)

    def test_none_execute(self):
        executor = brick_executor.Executor(root_helper=None, execute=None)
        self.assertEqual(rootwrap.execute, executor._execute)

    def test_fake_execute(self):
        mock_execute = mock.Mock()
        executor = brick_executor.Executor(root_helper=None,
                                           execute=mock_execute)
        self.assertEqual(mock_execute, executor._execute)
