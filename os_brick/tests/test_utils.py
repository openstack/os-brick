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

import time

import mock
from oslo_log import log as logging

from os_brick import exception
from os_brick.tests import base
from os_brick import utils


LOG = logging.getLogger(__name__)


class WrongException(exception.BrickException):
    pass


class TestRetryDecorator(base.TestCase):

    def test_no_retry_required(self):
        self.counter = 0

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exceptions=exception.VolumeDeviceNotFound,
                         interval=2,
                         retries=3,
                         backoff_rate=2)
            def succeeds():
                self.counter += 1
                return 'success'

            ret = succeeds()
            self.assertFalse(mock_sleep.called)
            self.assertEqual(ret, 'success')
            self.assertEqual(self.counter, 1)

    def test_retries_once(self):
        self.counter = 0
        interval = 2
        backoff_rate = 2
        retries = 3

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.VolumeDeviceNotFound,
                         interval,
                         retries,
                         backoff_rate)
            def fails_once():
                self.counter += 1
                if self.counter < 2:
                    raise exception.VolumeDeviceNotFound(device='fake')
                else:
                    return 'success'

            ret = fails_once()
            self.assertEqual(ret, 'success')
            self.assertEqual(self.counter, 2)
            self.assertEqual(mock_sleep.call_count, 1)
            mock_sleep.assert_called_with(interval * backoff_rate)

    def test_limit_is_reached(self):
        self.counter = 0
        retries = 3
        interval = 2
        backoff_rate = 4

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exception.VolumeDeviceNotFound,
                         interval,
                         retries,
                         backoff_rate)
            def always_fails():
                self.counter += 1
                raise exception.VolumeDeviceNotFound(device='fake')

            self.assertRaises(exception.VolumeDeviceNotFound,
                              always_fails)
            self.assertEqual(retries, self.counter)

            expected_sleep_arg = []

            for i in range(retries):
                if i > 0:
                    interval *= backoff_rate
                    expected_sleep_arg.append(float(interval))

            mock_sleep.assert_has_calls(
                list(map(mock.call, expected_sleep_arg)))

    def test_wrong_exception_no_retry(self):

        with mock.patch.object(time, 'sleep') as mock_sleep:
            @utils.retry(exceptions=exception.VolumeDeviceNotFound)
            def raise_unexpected_error():
                raise WrongException("wrong exception")

            self.assertRaises(WrongException, raise_unexpected_error)
            self.assertFalse(mock_sleep.called)
