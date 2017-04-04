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

"""Just in case it wasn't clear, this is a massive security back-door.

`execute_root()` (or the same via `execute(run_as_root=True)`) allows
any command to be run as the privileged user (default "root").  This
is intended only as an expedient transition and should be removed
ASAP.

This is not completely unreasonable because:

1. We have no tool/workflow for merging changes to rootwrap filter
   configs from os-brick into nova/cinder, which makes it difficult
   to evolve these loosely coupled projects.

2. Let's not pretend the earlier situation was any better.  The
   rootwrap filters config contained several entries like "allow cp as
   root with any arguments", etc, and would have posed only a mild
   inconvenience to an attacker.  At least with privsep we can (in
   principle) run the "root" commands as a non-root uid, with
   restricted Linux capabilities.

The plan is to switch os-brick to privsep using this module (removing
the urgency of (1)), then work on the larger refactor that addresses
(2) in followup changes.

"""

import os
import signal
import six
import threading
import time

from oslo_concurrency import processutils as putils
from oslo_log import log as logging
from oslo_utils import strutils

from os_brick import exception
from os_brick import privileged


LOG = logging.getLogger(__name__)


def custom_execute(*cmd, **kwargs):
    """Custom execute with additional functionality on top of Oslo's.

    Additional features are timeouts and exponential backoff retries.

    The exponential backoff retries replaces standard Oslo random sleep times
    that range from 200ms to 2seconds when attempts is greater than 1, but it
    is disabled if delay_on_retry is passed as a parameter.

    Exponential backoff is controlled via interval and backoff_rate parameters,
    just like the os_brick.utils.retry decorator.

    To use the timeout mechanism to stop the subprocess with a specific signal
    after a number of seconds we must pass a non-zero timeout value in the
    call.

    When using multiple attempts and timeout at the same time the method will
    only raise the timeout exception to the caller if the last try timeouts.

    Timeout mechanism is controlled with timeout, signal, and raise_timeout
    parameters.

    :param interval: The multiplier
    :param backoff_rate: Base used for the exponential backoff
    :param timeout: Timeout defined in seconds
    :param signal: Signal to use to stop the process on timeout
    :param raise_timeout: Raise and exception on timeout or return error as
                          stderr.  Defaults to raising if check_exit_code is
                          not False.
    :returns: Tuple with stdout and stderr
    """
    # Since python 2 doesn't have nonlocal we use a mutable variable to store
    # the previous attempt number, the timeout handler, and the process that
    # timed out
    shared_data = [0, None, None]

    def on_timeout(proc):
        sanitized_cmd = strutils.mask_password(' '.join(cmd))
        LOG.warning('Stopping %(cmd)s with signal %(signal)s after %(time)ss.',
                    {'signal': sig_end, 'cmd': sanitized_cmd, 'time': timeout})
        shared_data[2] = proc
        proc.send_signal(sig_end)

    def on_execute(proc):
        # Call user's on_execute method
        if on_execute_call:
            on_execute_call(proc)
        # Sleep if this is not the first try and we have a timeout interval
        if shared_data[0] and interval:
            exp = backoff_rate ** shared_data[0]
            wait_for = max(0, interval * exp)
            LOG.debug('Sleeping for %s seconds', wait_for)
            time.sleep(wait_for)
        # Increase the number of tries and start the timeout timer
        shared_data[0] += 1
        if timeout:
            shared_data[2] = None
            shared_data[1] = threading.Timer(timeout, on_timeout, (proc,))
            shared_data[1].start()

    def on_completion(proc):
        # This is always called regardless of success or failure
        # Cancel the timeout timer
        if shared_data[1]:
            shared_data[1].cancel()
        # Call user's on_completion method
        if on_completion_call:
            on_completion_call(proc)

    # We will be doing the wait ourselves in on_execute
    if 'delay_on_retry' in kwargs:
        interval = None
    else:
        kwargs['delay_on_retry'] = False
        interval = kwargs.pop('interval', 1)
        backoff_rate = kwargs.pop('backoff_rate', 2)

    timeout = kwargs.pop('timeout', None)
    sig_end = kwargs.pop('signal', signal.SIGTERM)
    default_raise_timeout = kwargs.get('check_exit_code', True)
    raise_timeout = kwargs.pop('raise_timeout', default_raise_timeout)

    on_execute_call = kwargs.pop('on_execute', None)
    on_completion_call = kwargs.pop('on_completion', None)

    try:
        return putils.execute(on_execute=on_execute,
                              on_completion=on_completion, *cmd, **kwargs)
    except putils.ProcessExecutionError:
        # proc is only stored if a timeout happened
        proc = shared_data[2]
        if proc:
            sanitized_cmd = strutils.mask_password(' '.join(cmd))
            msg = ('Time out on proc %(pid)s after waiting %(time)s seconds '
                   'when running %(cmd)s' %
                   {'pid': proc.pid, 'time': timeout, 'cmd': sanitized_cmd})
            LOG.debug(msg)
            if raise_timeout:
                raise exception.ExecutionTimeout(stdout='', stderr=msg,
                                                 cmd=sanitized_cmd)
            return '', msg
        raise


# Entrypoint used for rootwrap.py transition code.  Don't use this for
# other purposes, since it will be removed when we think the
# transition is finished.
def execute(*cmd, **kwargs):
    """NB: Raises processutils.ProcessExecutionError on failure."""
    run_as_root = kwargs.pop('run_as_root', False)
    kwargs.pop('root_helper', None)
    try:
        if run_as_root:
            return execute_root(*cmd, **kwargs)
        else:
            return custom_execute(*cmd, **kwargs)
    except OSError as e:
        # Note:
        #  putils.execute('bogus', run_as_root=True)
        # raises ProcessExecutionError(exit_code=1) (because there's a
        # "sh -c bogus" involved in there somewhere, but:
        #  putils.execute('bogus', run_as_root=False)
        # raises OSError(not found).
        #
        # Lots of code in os-brick catches only ProcessExecutionError
        # and never encountered the latter when using rootwrap.
        # Rather than fix all the callers, we just always raise
        # ProcessExecutionError here :(

        sanitized_cmd = strutils.mask_password(' '.join(cmd))
        raise putils.ProcessExecutionError(
            cmd=sanitized_cmd, description=six.text_type(e))


# See comment on `execute`
@privileged.default.entrypoint
def execute_root(*cmd, **kwargs):
    """NB: Raises processutils.ProcessExecutionError/OSError on failure."""
    return custom_execute(*cmd, shell=False, run_as_root=False, **kwargs)


@privileged.default.entrypoint
def unlink_root(*links, **kwargs):
    """Unlink system links with sys admin privileges.

    By default it will raise an exception if a link does not exist and stop
    unlinking remaining links.

    This behavior can be modified passing optional parameters `no_errors` and
    `raise_at_end`.

    :param no_errors: Don't raise an exception on error
    "param raise_at_end: Don't raise an exception on first error, try to
                         unlink all links and then raise a ChainedException
                         with all the errors that where found.
    """
    no_errors = kwargs.get('no_errors', False)
    raise_at_end = kwargs.get('raise_at_end', False)
    exc = exception.ExceptionChainer()
    catch_exception = no_errors or raise_at_end
    for link in links:
        with exc.context(catch_exception, 'Unlink failed for %s', link):
            os.unlink(link)
    if not no_errors and raise_at_end and exc:
        raise exc
