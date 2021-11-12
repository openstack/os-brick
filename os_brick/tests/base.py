# Copyright 2010-2011 OpenStack Foundation
# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
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

import logging
import os
from unittest import mock

import fixtures
from oslo_concurrency import lockutils
from oslo_config import fixture as config_fixture
from oslo_utils import strutils
import testtools


class TestCase(testtools.TestCase):
    """Test case base class for all unit tests."""

    SENTINEL = object()

    def setUp(self):
        """Run before each test method to initialize test environment."""
        super(TestCase, self).setUp()

        test_timeout = os.environ.get('OS_TEST_TIMEOUT', 0)
        try:
            test_timeout = int(test_timeout)
        except ValueError:
            # If timeout value is invalid do not set a timeout.
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=True))
        self.useFixture(fixtures.NestedTempfile())
        self.useFixture(fixtures.TempHomeDir())

        environ_enabled = (lambda var_name:
                           strutils.bool_from_string(os.environ.get(var_name)))
        if environ_enabled('OS_STDOUT_CAPTURE'):
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if environ_enabled('OS_STDERR_CAPTURE'):
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))
        if environ_enabled('OS_LOG_CAPTURE'):
            log_format = '%(levelname)s [%(name)s] %(message)s'
            if environ_enabled('OS_DEBUG'):
                level = logging.DEBUG
            else:
                level = logging.INFO
            self.useFixture(fixtures.LoggerFixture(nuke_handlers=False,
                                                   format=log_format,
                                                   level=level))
        # Protect against any case where someone doesn't remember to patch a
        # retry decorated call
        patcher = mock.patch('os_brick.utils._time_sleep')
        patcher.start()
        self.addCleanup(patcher.stop)

        # At runtime this would be set by the library user: Cinder, Nova, etc.
        self.useFixture(fixtures.NestedTempfile())
        lock_path = self.useFixture(fixtures.TempDir()).path
        self.fixture = self.useFixture(config_fixture.Config(lockutils.CONF))
        self.fixture.config(lock_path=lock_path, group='oslo_concurrency')
        lockutils.set_defaults(lock_path)

    def _common_cleanup(self):
        """Runs after each test method to tear down test environment."""

        # Stop any timers
        for x in self.injected:
            try:
                x.stop()
            except AssertionError:
                pass

        # Delete attributes that don't start with _ so they don't pin
        # memory around unnecessarily for the duration of the test
        # suite
        for key in [k for k in self.__dict__.keys() if k[0] != '_']:
            del self.__dict__[key]

    def log_level(self, level):
        """Set logging level to the specified value."""
        log_root = logging.getLogger(None).logger
        log_root.setLevel(level)

    def mock_object(self, obj, attr_name, new_attr=SENTINEL, **kwargs):
        """Use python mock to mock an object attribute

        Mocks the specified objects attribute with the given value.
        Automatically performs 'addCleanup' for the mock.
        """
        args = [obj, attr_name]
        if new_attr is not self.SENTINEL:
            args.append(new_attr)
        patcher = mock.patch.object(*args, **kwargs)
        mocked = patcher.start()
        self.addCleanup(patcher.stop)
        return mocked

    def patch(self, path, *args, **kwargs):
        """Use python mock to mock a path with automatic cleanup."""
        patcher = mock.patch(path, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result
