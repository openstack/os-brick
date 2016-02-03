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
#
"""Utilities and helper functions."""

from oslo_log import log as logging
import retrying
import six

from os_brick.i18n import _


LOG = logging.getLogger(__name__)


def retry(exceptions, interval=1, retries=3, backoff_rate=2):

    def _retry_on_exception(e):
        return isinstance(e, exceptions)

    def _backoff_sleep(previous_attempt_number, delay_since_first_attempt_ms):
        exp = backoff_rate ** previous_attempt_number
        wait_for = max(0, interval * exp)
        LOG.debug("Sleeping for %s seconds", wait_for)
        return wait_for * 1000.0

    def _print_stop(previous_attempt_number, delay_since_first_attempt_ms):
        delay_since_first_attempt = delay_since_first_attempt_ms / 1000.0
        LOG.debug("Failed attempt %s", previous_attempt_number)
        LOG.debug("Have been at this for %s seconds",
                  delay_since_first_attempt)
        return previous_attempt_number == retries

    if retries < 1:
        raise ValueError(_('Retries must be greater than or '
                         'equal to 1 (received: %s). ') % retries)

    def _decorator(f):

        @six.wraps(f)
        def _wrapper(*args, **kwargs):
            r = retrying.Retrying(retry_on_exception=_retry_on_exception,
                                  wait_func=_backoff_sleep,
                                  stop_func=_print_stop)
            return r.call(f, *args, **kwargs)

        return _wrapper

    return _decorator


def platform_matches(current_platform, connector_platform):
    curr_p = current_platform.upper()
    conn_p = connector_platform.upper()
    if conn_p == 'ALL':
        return True

    # Add tests against families of platforms
    if curr_p == conn_p:
        return True

    return False


def os_matches(current_os, connector_os):
    curr_os = current_os.upper()
    conn_os = connector_os.upper()
    if conn_os == 'ALL':
        return True

    # add tests against OSs
    if (conn_os == curr_os or
       conn_os in curr_os):
        return True

    return False


def merge_dict(dict1, dict2):
    """Try to safely merge 2 dictionaries."""
    if type(dict1) is not dict:
        raise Exception("dict1 is not a dictionary")
    if type(dict2) is not dict:
        raise Exception("dict2 is not a dictionary")

    dict3 = dict1.copy()
    dict3.update(dict2)
    return dict3
