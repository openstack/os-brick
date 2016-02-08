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

import six

from oslo_concurrency import processutils as putils
from oslo_utils import strutils

from os_brick import privileged


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
            return putils.execute(*cmd, **kwargs)
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
    return putils.execute(*cmd, shell=False, run_as_root=False, **kwargs)
