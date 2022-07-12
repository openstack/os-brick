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
import os
import time
from typing import Any, Callable, Tuple, Type, Union   # noqa: H301

from oslo_concurrency import processutils
from oslo_log import log as logging
from oslo_utils import strutils

from os_brick.i18n import _
from os_brick.privileged import nvmeof as priv_nvme
from os_brick.privileged import rootwrap as priv_rootwrap


CUSTOM_LINK_PREFIX = '/dev/disk/by-id/os-brick'

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


def _symlink_name_from_device_path(device_path):
    """Generate symlink absolute path for encrypted devices.

    The symlink's basename will contain the original device name so we can
    reconstruct it afterwards on disconnect.

    Being able to restore the original device name may be important for some
    connectors, because the system may have multiple devices for the same
    connection information (for example if a controller came back to life after
    having network issues and an auto scan presented the device) and if we
    reuse an existing symlink created by udev we wouldn't know which one was
    actually used.

    The symlink will be created under the /dev/disk/by-id directory and will
    prefix the name with os-brick- and then continue with the full device path
    that was passed (replacing '/' with '+')
    """
    # Convert / into + that is unlikely used by devices or symlinks (cryptsetup
    # is not happy if we use · in the symlink)
    encoded_device = device_path.replace('/', '+')
    return CUSTOM_LINK_PREFIX + encoded_device


def _device_path_from_symlink(symlink):
    """Get the original encrypted device path from the device symlink.

    This is the reverse operation of the one performed by the
    _symlink_name_from_device_path method.
    """
    if (symlink and isinstance(symlink, str)
            and symlink.startswith(CUSTOM_LINK_PREFIX)):
        ending = symlink[len(CUSTOM_LINK_PREFIX):]
        return ending.replace('+', '/')
    return symlink


def connect_volume_prepare_result(
        func: Callable[[Any, dict], dict]) -> Callable[[Any, dict], dict]:
    """Decorator to prepare the result of connect_volume for encrypted volumes.

    WARNING: This decorator must be **before** any connect_volume locking
             because it may call disconnect_volume.

    Encryptor drivers expect a symlink that they "own", so that they can modify
    it as they want.

    The current flow is like this:

    - connect_volume connector call
    - libvirt config is generated by Nova using returned path
    - connect_volume encryptor call  => Replaces the original path

    For encrypted volumes the decorator modifies the "path" value for the
    returned dictionary.

    Unencrypted volumes will be left unchanged.

    There are special connectors that return a file descriptor instead of a
    path depending on the parameters.  In those cases the result will also be
    left untouched.

    If a connector relies on the path that has been used they can use the
    connect_volume_undo_prepare_result decorator to get the value changed back
    the original path.
    """
    @functools.wraps(func)
    def change_encrypted(self, connection_properties):
        res = func(self, connection_properties)
        # Decode if path is bytes, otherwise leave it as it is
        device_path = convert_str(res['path'])
        # There are connectors that sometimes return file descriptors (rbd)
        if (connection_properties.get('encrypted') and
                isinstance(device_path, str)):
            symlink = _symlink_name_from_device_path(device_path)
            try:
                priv_rootwrap.link_root(os.path.realpath(device_path),
                                        symlink,
                                        force=True)
                res['path'] = symlink
            except Exception as exc:
                LOG.debug('Failed to create symlink, cleaning connection: %s',
                          exc)
                self.disconnect_volume(res, force=True, ignore_errors=True)
                raise

        return res
    return change_encrypted


def get_dev_path(connection_properties, device_info):
    """Return the device that was returned when connecting a volume."""
    if device_info and device_info.get('path'):
        res = device_info['path']
    else:
        res = connection_properties.get('device_path') or ''

    # Decode if path is bytes, otherwise leave it as it is
    return convert_str(res)


def connect_volume_undo_prepare_result(f=None, unlink_after=False):
    """Decorator that returns the device path to how it was originally.

    WARNING: This decorator must be **the first** decorator of the method to
             get the actual method signature during introspection.

    Undo changes made to the device path of encrypted volumes done by the
    connect_volume_prepare_result decorator.

    That way the connector will always get back the same device path that it
    returned.

    Examples of connector methods that may want to use this are
    disconnect_volume and extend_volume.

    It can optionally delete the symlink on successful completion, required for
    disconnect_volume method.

    @connect_volume_undo_prepare_result(unlink_after=True)
    def disconnect_volume(...):

    @connect_volume_undo_prepare_result
    def extend_volume(...):

    """
    def decorator(func):
        @functools.wraps(func)
        def change_encrypted(*args, **kwargs):
            # May receive only connection_properties or also device_info params
            call_args = inspect.getcallargs(func, *args, **kwargs)
            conn_props = call_args['connection_properties']

            custom_symlink = False
            if conn_props.get('encrypted'):
                dev_info = call_args.get('device_info')
                symlink = get_dev_path(conn_props, dev_info)
                devpath = _device_path_from_symlink(symlink)

                # Symlink can be a file descriptor, which we don't touch, same
                # for old symlinks where the path is the same
                if isinstance(symlink, str) and symlink != devpath:
                    custom_symlink = True
                    # Don't modify the caller's dictionaries
                    call_args['connection_properties'] = conn_props.copy()
                    call_args['connection_properties']['device_path'] = devpath

                    # Same for the device info dictionary
                    if dev_info:
                        dev_info = call_args['device_info'] = dev_info.copy()
                        dev_info['path'] = devpath

            res = func(**call_args)

            # Clean symlink only when asked (usually on disconnect)
            if custom_symlink and unlink_after:
                try:
                    priv_rootwrap.unlink_root(symlink)
                except Exception:
                    LOG.warning('Failed to remove encrypted custom symlink %s',
                                symlink)
            return res
        return change_encrypted

    if f:
        return decorator(f)
    return decorator
