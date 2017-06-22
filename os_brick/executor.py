# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

"""Generic exec utility that allows us to set the
   execute and root_helper attributes for putils.
   Some projects need their own execute wrapper
   and root_helper settings, so this provides that hook.
"""

import threading

from oslo_concurrency import processutils as putils
from oslo_context import context as context_utils
from oslo_utils import encodeutils

from os_brick.privileged import rootwrap as priv_rootwrap


class Executor(object):
    def __init__(self, root_helper, execute=None,
                 *args, **kwargs):
        if execute is None:
            execute = priv_rootwrap.execute
        self.set_execute(execute)
        self.set_root_helper(root_helper)

    @staticmethod
    def safe_decode(string):
        return string and encodeutils.safe_decode(string, errors='ignore')

    @classmethod
    def make_putils_error_safe(cls, exc):
        """Converts ProcessExecutionError string attributes to unicode."""
        for field in ('stderr', 'stdout', 'cmd', 'description'):
            value = getattr(exc, field, None)
            if value:
                setattr(exc, field, cls.safe_decode(value))

    def _execute(self, *args, **kwargs):
        try:
            result = self.__execute(*args, **kwargs)
            if result:
                result = (self.safe_decode(result[0]),
                          self.safe_decode(result[1]))
            return result
        except putils.ProcessExecutionError as e:
            self.make_putils_error_safe(e)
            raise

    def set_execute(self, execute):
        self.__execute = execute

    def set_root_helper(self, helper):
        self._root_helper = helper


class Thread(threading.Thread):
    """Thread class that inherits the parent's context.

    This is useful when you are spawning a thread and want LOG entries to
    display the right context information, such as the request.
    """

    def __init__(self, *args, **kwargs):
        # Store the caller's context as a private variable shared among threads
        self.__context__ = context_utils.get_current()
        super(Thread, self).__init__(*args, **kwargs)

    def run(self):
        # Store the context in the current thread's request store
        if self.__context__:
            self.__context__.update_store()
        super(Thread, self).run()
