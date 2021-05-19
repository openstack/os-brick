# Copyright (c) 2021, Red Hat, Inc.
# All Rights Reserved.
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

import errno
import os

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

import os_brick.privileged
from os_brick.privileged import rootwrap


LOG = logging.getLogger(__name__)


@os_brick.privileged.default.entrypoint
def create_hostnqn():
    """Create the hostnqn file to speed up finding out the nqn.

    By having the /etc/nvme/hostnqn not only do we make sure that that value is
    always used on this system, but we are also able to just open the file to
    get the nqn on each get_connector_properties call instead of having to make
    a call to nvme show-hostnqn command.
    """
    host_nqn = ''
    try:
        os.makedirs('/etc/nvme', mode=0o755, exist_ok=True)

        # Try to get existing nqn generated from dmi or systemd
        try:
            host_nqn, err = rootwrap.custom_execute('nvme', 'show-hostnqn')
            host_nqn = host_nqn.strip()

        # This is different from OSError's ENOENT, which is missing nvme
        # command.  This ENOENT is when nvme says there isn't an nqn.
        except putils.ProcessExecutionError as e:
            if e.exit_code != errno.ENOENT:
                raise
            LOG.debug('No nqn could be formed from dmi or systemd.')

        if not host_nqn:
            LOG.debug('Generating nqn')
            host_nqn, err = rootwrap.custom_execute('nvme', 'gen-hostnqn')
            host_nqn = host_nqn.strip()

        with open('/etc/nvme/hostnqn', 'w') as f:
            LOG.debug('Writing hostnqn file')
            f.write(host_nqn)
        os.chmod('/etc/nvme/hostnqn', 0o644)
    except Exception as e:
        LOG.warning("Could not generate host nqn: %s" % str(e))

    return host_nqn
