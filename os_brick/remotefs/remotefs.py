# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved
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

"""Remote filesystem client utilities."""

import hashlib
import os
import re
import tempfile

from oslo_concurrency import processutils
from oslo_log import log as logging
import six

from os_brick import exception
from os_brick import executor
from os_brick.i18n import _

LOG = logging.getLogger(__name__)


class RemoteFsClient(executor.Executor):

    def __init__(self, mount_type, root_helper,
                 execute=None, *args, **kwargs):
        super(RemoteFsClient, self).__init__(root_helper, execute=execute,
                                             *args, **kwargs)

        mount_type_to_option_prefix = {
            'nfs': 'nfs',
            'cifs': 'smbfs',
            'glusterfs': 'glusterfs',
            'vzstorage': 'vzstorage',
            'quobyte': 'quobyte',
            'scality': 'scality'
        }

        if mount_type not in mount_type_to_option_prefix:
            raise exception.ProtocolNotSupported(protocol=mount_type)

        self._mount_type = mount_type
        option_prefix = mount_type_to_option_prefix[mount_type]

        self._mount_base = kwargs.get(option_prefix + '_mount_point_base')
        if not self._mount_base:
            raise exception.InvalidParameterValue(
                err=_('%s_mount_point_base required') % option_prefix)

        self._mount_options = kwargs.get(option_prefix + '_mount_options')

        if mount_type == "nfs":
            self._check_nfs_options()

    def get_mount_base(self):
        return self._mount_base

    def _get_hash_str(self, base_str):
        """Return a string that represents hash of base_str (hex format)."""
        if isinstance(base_str, six.text_type):
            base_str = base_str.encode('utf-8')
        return hashlib.md5(base_str).hexdigest()

    def get_mount_point(self, device_name):
        """Get Mount Point.

        :param device_name: example 172.18.194.100:/var/nfs
        """
        return os.path.join(self._mount_base,
                            self._get_hash_str(device_name))

    def _read_mounts(self):
        """Returns a dict of mounts and their mountpoint

        Format reference:
        http://man7.org/linux/man-pages/man5/fstab.5.html
        """
        with open("/proc/mounts", "r") as mounts:
            # Remove empty lines and split lines by whitespace
            lines = [line.split() for line in mounts.read().splitlines()
                     if line.strip()]

            # Return {mountpoint: mountdevice}.  Fields 2nd and 1st as per
            # http://man7.org/linux/man-pages/man5/fstab.5.html
            return {line[1]: line[0] for line in lines if line[0] != '#'}

    def mount(self, share, flags=None):
        """Mount given share."""
        mount_path = self.get_mount_point(share)

        if mount_path in self._read_mounts():
            LOG.debug('Already mounted: %s', mount_path)
            return

        self._execute('mkdir', '-p', mount_path, check_exit_code=0)
        if self._mount_type == 'nfs':
            self._mount_nfs(share, mount_path, flags)
        else:
            self._do_mount(self._mount_type, share, mount_path,
                           self._mount_options, flags)

    def _do_mount(self, mount_type, share, mount_path, mount_options=None,
                  flags=None):
        """Mounts share based on the specified params."""
        mnt_cmd = ['mount', '-t', mount_type]
        if mount_options is not None:
            mnt_cmd.extend(['-o', mount_options])
        if flags is not None:
            mnt_cmd.extend(flags)
        mnt_cmd.extend([share, mount_path])

        try:
            self._execute(*mnt_cmd, root_helper=self._root_helper,
                          run_as_root=True, check_exit_code=0)
        except processutils.ProcessExecutionError as exc:
            if 'already mounted' in exc.stderr:
                LOG.debug("Already mounted: %s", share)

                # The error message can say "busy or already mounted" when the
                # share didn't actually mount, so look for it.
                if share in self._read_mounts():
                    return

            LOG.error("Failed to mount %(share)s, reason: %(reason)s",
                      {'share': share, 'reason': exc.stderr})
            raise

    def _mount_nfs(self, nfs_share, mount_path, flags=None):
        """Mount nfs share using present mount types."""
        mnt_errors = {}

        # This loop allows us to first try to mount with NFS 4.1 for pNFS
        # support but falls back to mount NFS 4 or NFS 3 if either the client
        # or server do not support it.
        for mnt_type in sorted(self._nfs_mount_type_opts.keys(), reverse=True):
            options = self._nfs_mount_type_opts[mnt_type]
            try:
                self._do_mount('nfs', nfs_share, mount_path, options, flags)
                LOG.debug('Mounted %(sh)s using %(mnt_type)s.',
                          {'sh': nfs_share, 'mnt_type': mnt_type})
                return
            except Exception as e:
                mnt_errors[mnt_type] = six.text_type(e)
                LOG.debug('Failed to do %s mount.', mnt_type)
        raise exception.BrickException(_("NFS mount failed for share %(sh)s. "
                                         "Error - %(error)s")
                                       % {'sh': nfs_share,
                                          'error': mnt_errors})

    def _check_nfs_options(self):
        """Checks and prepares nfs mount type options."""
        self._nfs_mount_type_opts = {'nfs': self._mount_options}
        nfs_vers_opt_patterns = ['^nfsvers', '^vers', r'^v[\d]']
        for opt in nfs_vers_opt_patterns:
            if self._option_exists(self._mount_options, opt):
                return

        # pNFS requires NFS 4.1. The mount.nfs4 utility does not automatically
        # negotiate 4.1 support, we have to ask for it by specifying two
        # options: vers=4 and minorversion=1.
        pnfs_opts = self._update_option(self._mount_options, 'vers', '4')
        pnfs_opts = self._update_option(pnfs_opts, 'minorversion', '1')
        self._nfs_mount_type_opts['pnfs'] = pnfs_opts

    def _option_exists(self, options, opt_pattern):
        """Checks if the option exists in nfs options and returns position."""
        options = [x.strip() for x in options.split(',')] if options else []
        pos = 0
        for opt in options:
            pos = pos + 1
            if re.match(opt_pattern, opt, flags=0):
                return pos
        return 0

    def _update_option(self, options, option, value=None):
        """Update option if exists else adds it and returns new options."""
        opts = [x.strip() for x in options.split(',')] if options else []
        pos = self._option_exists(options, option)
        if pos:
            opts.pop(pos - 1)
        opt = '%s=%s' % (option, value) if value else option
        opts.append(opt)
        return ",".join(opts) if len(opts) > 1 else opts[0]


class ScalityRemoteFsClient(RemoteFsClient):
    def __init__(self, mount_type, root_helper,
                 execute=None, *args, **kwargs):
        super(ScalityRemoteFsClient, self).__init__(mount_type, root_helper,
                                                    execute=execute,
                                                    *args, **kwargs)
        self._mount_type = mount_type
        self._mount_base = kwargs.get(
            'scality_mount_point_base', "").rstrip('/')
        if not self._mount_base:
            raise exception.InvalidParameterValue(
                err=_('scality_mount_point_base required'))
        self._mount_options = None

    def get_mount_point(self, device_name):
        return os.path.join(self._mount_base,
                            device_name,
                            "00")

    def mount(self, share, flags=None):
        """Mount the Scality ScaleOut FS.

        The `share` argument is ignored because you can't mount several
        SOFS at the same type on a single server. But we want to keep the
        same method signature for class inheritance purpose.
        """
        if self._mount_base in self._read_mounts():
            LOG.debug('Already mounted: %s', self._mount_base)
            return
        self._execute('mkdir', '-p', self._mount_base, check_exit_code=0)
        super(ScalityRemoteFsClient, self)._do_mount(
            'sofs', '/etc/sfused.conf', self._mount_base)


class VZStorageRemoteFSClient(RemoteFsClient):
    def _vzstorage_write_mds_list(self, cluster_name, mdss):
        tmp_dir = tempfile.mkdtemp(prefix='vzstorage-')
        tmp_bs_path = os.path.join(tmp_dir, 'bs_list')
        with open(tmp_bs_path, 'w') as f:
            for mds in mdss:
                f.write(mds + "\n")

        conf_dir = os.path.join('/etc/pstorage/clusters', cluster_name)
        if os.path.exists(conf_dir):
            bs_path = os.path.join(conf_dir, 'bs_list')
            self._execute('cp', '-f', tmp_bs_path, bs_path,
                          root_helper=self._root_helper, run_as_root=True)
        else:
            self._execute('cp', '-rf', tmp_dir, conf_dir,
                          root_helper=self._root_helper, run_as_root=True)
        self._execute('chown', '-R', 'root:root', conf_dir,
                      root_helper=self._root_helper, run_as_root=True)

    def _do_mount(self, mount_type, vz_share, mount_path,
                  mount_options=None, flags=None):
        m = re.search(r"(?:(\S+):\/)?([a-zA-Z0-9_-]+)(?::(\S+))?", vz_share)
        if not m:
            msg = (_("Invalid Virtuozzo Storage share specification: %r."
                     "Must be: [MDS1[,MDS2],...:/]<CLUSTER NAME>[:PASSWORD].")
                   % vz_share)
            raise exception.BrickException(msg)

        mdss = m.group(1)
        cluster_name = m.group(2)
        passwd = m.group(3)

        if mdss:
            mdss = mdss.split(',')
            self._vzstorage_write_mds_list(cluster_name, mdss)

        if passwd:
            self._execute('pstorage', '-c', cluster_name, 'auth-node', '-P',
                          process_input=passwd,
                          root_helper=self._root_helper, run_as_root=True)

        mnt_cmd = ['pstorage-mount', '-c', cluster_name]
        if flags:
            mnt_cmd.extend(flags)
        mnt_cmd.extend([mount_path])

        self._execute(*mnt_cmd, root_helper=self._root_helper,
                      run_as_root=True, check_exit_code=0)
