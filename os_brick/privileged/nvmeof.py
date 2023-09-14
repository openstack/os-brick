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

from __future__ import annotations

import errno
import os
from typing import Optional  # noqa: H301

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

import os_brick.privileged
from os_brick.privileged import rootwrap


LOG = logging.getLogger(__name__)


@os_brick.privileged.default.entrypoint
def create_hostnqn(system_uuid: Optional[str] = None) -> str:
    """Create the hostnqn file to speed up finding out the nqn.

    By having the /etc/nvme/hostnqn not only do we make sure that that value is
    always used on this system, but we are also able to just open the file to
    get the nqn on each get_connector_properties call instead of having to make
    a call to nvme show-hostnqn command.

    In newer nvme-cli versions calling show-hostnqn will not only try to
    locate the file (which we know doesn't exist or this method wouldn't have
    been called), but it will also generate one.  In older nvme-cli versions
    that is not the case.
    """
    host_nqn = ''
    try:
        os.makedirs('/etc/nvme', mode=0o755, exist_ok=True)

        # If we have the system's unique uuid we can just write the file
        if system_uuid:
            host_nqn = 'nqn.2014-08.org.nvmexpress:uuid:' + system_uuid
        else:
            # Try to get existing nqn generated from dmi or systemd
            try:
                host_nqn, err = rootwrap.custom_execute('nvme', 'show-hostnqn')
                host_nqn = host_nqn.strip()

            # This is different from OSError's ENOENT, which is missing nvme
            # command.  This ENOENT is when nvme says there isn't an nqn.
            except putils.ProcessExecutionError as e:
                # nvme-cli's error are all over the place, so merge the output
                err_msg = e.stdout + '\n' + e.stderr
                msg = err_msg.casefold()
                if 'error: invalid sub-command' in msg:
                    LOG.debug('Version too old cannot check current hostnqn.')
                elif 'hostnqn is not available' in msg:
                    LOG.debug('Version too old to return hostnqn from non '
                              'file sources')
                elif e.exit_code == errno.ENOENT:
                    LOG.debug('No nqn could be formed from dmi or systemd.')
                else:
                    LOG.debug('Unknown error from nvme show-hostnqn: %s',
                              err_msg)
                    raise

            if not host_nqn:
                LOG.debug('Generating nqn')
                host_nqn, err = rootwrap.custom_execute('nvme', 'gen-hostnqn')
                host_nqn = host_nqn.strip()

        with open('/etc/nvme/hostnqn', 'w') as f:
            LOG.debug('Writing hostnqn file')
            f.write(host_nqn)
        os.chmod('/etc/nvme/hostnqn', 0o644)
    except Exception as e:
        LOG.warning("Could not generate host nqn: %s", e)

    return host_nqn


@os_brick.privileged.default.entrypoint
def get_system_uuid() -> str:
    # RSD requires system_uuid to let Cinder RSD Driver identify
    # Nova node for later RSD volume attachment.
    try:
        with open('/sys/class/dmi/id/product_uuid', 'r') as f:
            return f.read().strip()
    except Exception:
        LOG.debug("Could not read dmi's 'product_uuid' on sysfs")

    try:
        out, err = rootwrap.custom_execute('dmidecode', '-ssystem-uuid')
        if not out:
            LOG.warning('dmidecode returned empty system-uuid')
    except (putils.ProcessExecutionError, FileNotFoundError) as e:
        LOG.debug("Unable to locate dmidecode. For Cinder RSD Backend,"
                  " please make sure it is installed: %s", e)
        out = ""

    return out.strip()


@os_brick.privileged.default.entrypoint
def create_hostid(uuid: str) -> Optional[str]:
    """Create the hostid to ensure it's always the same."""
    try:
        os.makedirs('/etc/nvme', mode=0o755, exist_ok=True)

        with open('/etc/nvme/hostid', 'w') as f:
            LOG.debug('Writing nvme hostid %s', uuid)
            f.write(f'{uuid}\n')
        os.chmod('/etc/nvme/hostid', 0o644)

    except Exception as e:
        LOG.warning("Could not generate nvme host id: %s", e)
        return None

    return uuid
