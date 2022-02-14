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

import functools
import inspect
import logging as py_logging
import time
from typing import Callable, Tuple, Type, Union   # noqa: H301

from oslo_concurrency import processutils
from oslo_log import log as logging
from oslo_utils import strutils

from os_brick.i18n import _
from os_brick.privileged import nvmeof as priv_nvme

_time_sleep = time.sleep


def _sleep(secs: float) -> None:
    """Helper class to make it easier to work around tenacity's sleep calls.

    Apparently we are all idiots for wanting to test our code here [0], so this
    is a hack to be able to get retries to not actually sleep.

    [0] https://github.com/jd/tenacity/issues/25
    """
    _time_sleep(secs)


time.sleep = _sleep

import tenacity  # noqa


LOG = logging.getLogger(__name__)


class retry_if_exit_code(tenacity.retry_if_exception):
    """Retry on ProcessExecutionError specific exit codes."""
    def __init__(self, codes: Union[int, Tuple[int, ...]]):
        self.codes = (codes,) if isinstance(codes, int) else codes
        super(retry_if_exit_code, self).__init__(self._check_exit_code)

    def _check_exit_code(self, exc: Type[Exception]) -> bool:
        return (bool(exc) and
                isinstance(exc, processutils.ProcessExecutionError) and
                exc.exit_code in self.codes)


def retry(retry_param: Union[None,
                             Type[Exception],
                             Tuple[Type[Exception], ...],
                             int,
                             Tuple[int, ...]],
          interval: float = 1,
          retries: int = 3,
          backoff_rate: float = 2,
          retry: Callable = tenacity.retry_if_exception_type) -> Callable:

    if retries < 1:
        raise ValueError(_('Retries must be greater than or '
                         'equal to 1 (received: %s). ') % retries)

    def _decorator(f):

        @functools.wraps(f)
        def _wrapper(*args, **kwargs):
            r = tenacity.Retrying(
                before_sleep=tenacity.before_sleep_log(LOG, logging.DEBUG),
                after=tenacity.after_log(LOG, logging.DEBUG),
                stop=tenacity.stop_after_attempt(retries),
                reraise=True,
                retry=retry(retry_param),
                wait=tenacity.wait_exponential(
                    multiplier=interval, min=0, exp_base=backoff_rate))
            return r(f, *args, **kwargs)

        return _wrapper

    return _decorator


def platform_matches(current_platform: str, connector_platform: str) -> bool:
    curr_p = current_platform.upper()
    conn_p = connector_platform.upper()
    if conn_p == 'ALL':
        return True

    # Add tests against families of platforms
    if curr_p == conn_p:
        return True

    return False


def os_matches(current_os: str, connector_os: str) -> bool:
    curr_os = current_os.upper()
    conn_os = connector_os.upper()
    if conn_os == 'ALL':
        return True

    # add tests against OSs
    if (conn_os == curr_os or
       conn_os in curr_os):
        return True

    return False


def merge_dict(dict1: dict, dict2: dict) -> dict:
    """Try to safely merge 2 dictionaries."""
    if type(dict1) is not dict:
        raise Exception("dict1 is not a dictionary")
    if type(dict2) is not dict:
        raise Exception("dict2 is not a dictionary")

    dict3 = dict1.copy()
    dict3.update(dict2)
    return dict3


def trace(f: Callable) -> Callable:
    """Trace calls to the decorated function.

    This decorator should always be defined as the outermost decorator so it
    is defined last. This is important so it does not interfere
    with other decorators.

    Using this decorator on a function will cause its execution to be logged at
    `DEBUG` level with arguments, return values, and exceptions.

    :returns: a function decorator
    """

    func_name = f.__name__

    @functools.wraps(f)
    def trace_logging_wrapper(*args, **kwargs):
        if len(args) > 0:
            maybe_self = args[0]
        else:
            maybe_self = kwargs.get('self', None)

        if maybe_self and hasattr(maybe_self, '__module__'):
            logger = logging.getLogger(maybe_self.__module__)
        else:
            logger = LOG

        # NOTE(ameade): Don't bother going any further if DEBUG log level
        # is not enabled for the logger.
        if not logger.isEnabledFor(py_logging.DEBUG):
            return f(*args, **kwargs)

        all_args = inspect.getcallargs(f, *args, **kwargs)
        logger.debug('==> %(func)s: call %(all_args)r',
                     {'func': func_name,
                      # NOTE(mriedem): We have to stringify the dict first
                      # and don't use mask_dict_password because it results in
                      # an infinite recursion failure.
                      'all_args': strutils.mask_password(
                          str(all_args))})

        start_time = time.time() * 1000
        try:
            result = f(*args, **kwargs)
        except Exception as exc:
            total_time = int(round(time.time() * 1000)) - start_time
            logger.debug('<== %(func)s: exception (%(time)dms) %(exc)r',
                         {'func': func_name,
                          'time': total_time,
                          'exc': exc})
            raise
        total_time = int(round(time.time() * 1000)) - start_time

        if isinstance(result, dict):
            mask_result = strutils.mask_dict_password(result)
        elif isinstance(result, str):
            mask_result = strutils.mask_password(result)
        else:
            mask_result = result

        logger.debug('<== %(func)s: return (%(time)dms) %(result)r',
                     {'func': func_name,
                      'time': total_time,
                      'result': mask_result})
        return result
    return trace_logging_wrapper


def convert_str(text: Union[bytes, str]) -> str:
    """Convert to native string.

    Convert bytes and Unicode strings to native strings:

    * convert to Unicode on Python 3: decode bytes from UTF-8
    """
    if isinstance(text, bytes):
        return text.decode('utf-8')
    else:
        return text


def get_host_nqn():
    try:
        with open('/etc/nvme/hostnqn', 'r') as f:
            host_nqn = f.read().strip()
    except IOError:
        host_nqn = priv_nvme.create_hostnqn()
    except Exception:
        host_nqn = None
    return host_nqn
