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

import glob
import os.path
import time

from oslo_concurrency import lockutils
from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick import exception
from os_brick.initiator.connectors import base
try:
    from os_brick.initiator.connectors import nvmeof_agent
except ImportError:
    nvmeof_agent = None
from os_brick import utils

DEVICE_SCAN_ATTEMPTS_DEFAULT = 5

synchronized = lockutils.synchronized_with_prefix('os-brick-')

LOG = logging.getLogger(__name__)


class NVMeOFConnector(base.BaseLinuxConnector):
    """Connector class to attach/detach NVMe-oF volumes."""

    def __init__(self, root_helper, driver=None, use_multipath=False,
                 device_scan_attempts=DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(NVMeOFConnector, self).__init__(
            root_helper,
            driver=driver,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs)
        self.use_multipath = use_multipath

    def get_search_path():
        return '/dev/'

    def get_volume_paths(self, connection_properties):
        device_path = connection_properties.get('device_path')
        if device_path:
            return [device_path]
        volume_replicas = connection_properties.get('volume_replicas')
        try:
            if volume_replicas and len(volume_replicas) > 1:
                return ['/dev/md/' + connection_properties.get('alias')]
            if volume_replicas and len(volume_replicas) == 1:
                return [NVMeOFConnector.get_nvme_device_path(
                    self, volume_replicas[0]['target_nqn'],
                    volume_replicas[0]['vol_uuid'])]
            else:
                return [NVMeOFConnector.get_nvme_device_path(
                    self, connection_properties.get('target_nqn'),
                    connection_properties.get('vol_uuid'))]
        except exception.VolumeDeviceNotFound:
            return []

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The NVMe-oF connector properties (initiator uuid and nqn.)"""
        nvmf = NVMeOFConnector(root_helper=root_helper,
                               execute=kwargs.get('execute'))
        ret = {}
        uuid = nvmf._get_host_uuid()
        nqn = nvmf._get_host_nqn()
        if uuid:
            ret['uuid'] = uuid
        if nqn:
            ret['nqn'] = nqn
        return ret

    def _get_host_uuid(self):
        cmd = ('findmnt', '/', '-n', '-o', 'SOURCE')
        try:
            lines, err = self._execute(
                *cmd, run_as_root=True, root_helper=self._root_helper)
            blkid_cmd = (
                'blkid', lines.split('\n')[0], '-s', 'UUID', '-o', 'value')
            lines, _err = self._execute(
                *blkid_cmd, run_as_root=True, root_helper=self._root_helper)
            return lines.split('\n')[0]
        except putils.ProcessExecutionError as e:
            LOG.warning(
                "Process execution error in _get_host_uuid: %s" % str(e))
            return None

    def _get_host_nqn(self):
        try:
            with open('/etc/nvme/hostnqn', 'r') as f:
                host_nqn = f.read().strip()
                f.close()
        except IOError:
            try:
                out, err = self._execute(
                    'nvme', 'gen-hostuuid',
                    root_helper=self._root_helper, run_as_root=True)
                host_nqn = out.strip()
                with open('/etc/nvme/hostnqn', 'w') as f:
                    f.write(host_nqn)
                    f.close()
            except Exception as e:
                LOG.warning("Could not generate host nqn: %s" % str(e))
                return None
        return host_nqn

    @utils.trace
    @synchronized('connect_volume')
    def connect_volume(self, connection_properties):
        """connect to volume on host

        connection_properties for NVMe-oF must include:
        target_portals - list of ip,port,transport for each portal
        target_nqn - NVMe-oF Qualified Name
        vol_uuid - UUID for volume/replica
        """

        volume_replicas = connection_properties.get('volume_replicas')
        volume_alias = connection_properties.get('alias')

        if volume_replicas:
            host_device_paths = []

            for replica in volume_replicas:
                try:
                    rep_host_device_path = self._connect_target_volume(
                        replica['target_nqn'], replica['vol_uuid'],
                        replica['portals'])
                    if rep_host_device_path:
                        host_device_paths.append(rep_host_device_path)
                except Exception as ex:
                    LOG.error("_connect_target_volume: %s", ex)

            if len(volume_replicas) > 1:
                device_path = self._handle_replicated_volume(
                    host_device_paths, volume_alias, len(volume_replicas))
            else:
                device_path = host_device_paths[0]
        else:
            try:
                device_path = self._connect_target_volume(
                    connection_properties['target_nqn'],
                    connection_properties['vol_uuid'],
                    connection_properties['portals'])
            except Exception as ex:
                LOG.error("_connect_target_volume: %s", ex)

        if nvmeof_agent:
            nvmeof_agent.NVMeOFAgent.ensure_running(self)

        return {'type': 'block', 'path': device_path}

    @utils.trace
    @synchronized('connect_volume')
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        device_path = None
        volume_replicas = connection_properties.get('volume_replicas')
        if device_info and device_info.get('path'):
            device_path = device_info['path']
        elif connection_properties.get('device_path'):
            device_path = connection_properties['device_path']
        elif volume_replicas and len(volume_replicas) > 1:
            device_path = '/dev/md/' + connection_properties['alias']

        if volume_replicas and len(volume_replicas) > 1:
            NVMeOFConnector.end_raid(self, device_path)
        else:
            if self._get_fs_type(device_path) == 'linux_raid_member':
                NVMeOFConnector.end_raid(self, device_path)

    def extend_volume(self, connection_properties):
        volume_replicas = connection_properties.get('volume_replicas')

        if volume_replicas and len(volume_replicas) > 1:
            device_path = '/dev/md/' + connection_properties['alias']
            NVMeOFConnector.run_mdadm(
                self, ['mdadm', '--grow', '--size', 'max', device_path])
        else:
            if not volume_replicas:
                target_nqn = connection_properties['target_nqn']
                vol_uuid = connection_properties['vol_uuid']
            elif len(volume_replicas) == 1:
                target_nqn = volume_replicas[0]['target_nqn']
                vol_uuid = volume_replicas[0]['vol_uuid']
            device_path = NVMeOFConnector.get_nvme_device_path(
                self, target_nqn, vol_uuid)

        return self._linuxscsi.get_device_size(device_path)

    def _connect_target_volume(self, target_nqn, vol_uuid, portals):
        try:
            host_device_path = NVMeOFConnector.get_nvme_device_path(
                self, target_nqn, vol_uuid)
        except exception.VolumeDeviceNotFound:
            host_device_path = None
        if not host_device_path:
            any_connect = NVMeOFConnector.connect_to_portals(self, target_nqn,
                                                             portals)
            if not any_connect:
                LOG.error(
                    "No successful connections: %(host_devices)s",
                    {'host_devices': target_nqn})
                raise exception.VolumeDeviceNotFound(device=target_nqn)
            host_device_path = NVMeOFConnector.get_nvme_device_path(
                self, target_nqn, vol_uuid)
            if not host_device_path:
                LOG.error(
                    "No accessible volume device: %(host_devices)s",
                    {'host_devices': target_nqn})
                raise exception.VolumeDeviceNotFound(device=target_nqn)
        else:
            NVMeOFConnector.rescan(self, target_nqn, vol_uuid)
            host_device_path = NVMeOFConnector.get_nvme_device_path(
                self, target_nqn, vol_uuid)

        return host_device_path

    @staticmethod
    def connect_to_portals(executor, target_nqn, target_portals):
        """connect to any of NVMe-oF target portals"""
        any_connect = False
        for portal in target_portals:
            portal_address = portal[0]
            portal_port = portal[1]
            if portal[2] == 'RoCEv2':
                portal_transport = 'rdma'
            else:
                portal_transport = 'tcp'
            nvme_command = (
                'connect', '-a', portal_address, '-s', portal_port, '-t',
                portal_transport, '-n', target_nqn, '-Q', '128', '-l', '-1')
            try:
                NVMeOFConnector.run_nvme_cli(executor, nvme_command)
                any_connect = True
                break
            except Exception:
                LOG.exception("Could not connect to portal %s", portal)
        return any_connect

    @staticmethod
    def _get_nvme_controller(executor, target_nqn):
        ctrls = glob.glob('/sys/class/nvme-fabrics/ctl/nvme*')
        for ctrl in ctrls:
            try:
                lines, _err = executor._execute(
                    'cat', ctrl + '/subsysnqn', run_as_root=True,
                    root_helper=executor._root_helper)
                for line in lines.split('\n'):
                    if line == target_nqn:
                        state, _err = executor._execute(
                            'cat', ctrl + '/state', run_as_root=True,
                            root_helper=executor._root_helper)
                        if 'live' not in state:
                            LOG.debug("nvmeof ctrl device not live: %s", ctrl)
                            raise exception.VolumeDeviceNotFound(device=ctrl)
                        return ctrl[ctrl.rfind('/') + 1:]
            except putils.ProcessExecutionError as e:
                LOG.exception(e)

        raise exception.VolumeDeviceNotFound(device=target_nqn)

    @staticmethod
    @utils.retry(exceptions=exception.VolumeDeviceNotFound)
    def get_nvme_device_path(executor, target_nqn, vol_uuid):
        nvme_ctrl = NVMeOFConnector._get_nvme_controller(executor, target_nqn)
        try:
            blocks = glob.glob(
                '/sys/class/nvme-fabrics/ctl/' + nvme_ctrl +
                '/' + nvme_ctrl + 'n*')
            for block in blocks:
                uuid_lines, _err = executor._execute(
                    'cat', block + '/uuid', run_as_root=True,
                    root_helper=executor._root_helper)
                if uuid_lines.split('\n')[0] == vol_uuid:
                    return '/dev/' + block[block.rfind('/') + 1:]
        except putils.ProcessExecutionError as e:
            LOG.exception(e)

        raise exception.VolumeDeviceNotFound(device=vol_uuid)

    def _handle_replicated_volume(self, host_device_paths,
                                  volume_alias, num_of_replicas):
        path_in_raid = False
        for dev_path in host_device_paths:
            path_in_raid = NVMeOFConnector._is_device_in_raid(self, dev_path)
            if path_in_raid:
                break
        device_path = '/dev/md/' + volume_alias
        if path_in_raid:
            NVMeOFConnector.stop_and_assemble_raid(
                self, host_device_paths, device_path, False)
        else:
            paths_found = len(host_device_paths)
            if num_of_replicas > paths_found:
                LOG.error(
                    'Cannot create MD as %s out of %s legs were found.',
                    paths_found, num_of_replicas)
                raise exception.VolumeDeviceNotFound(device=volume_alias)
            NVMeOFConnector.create_raid(self, host_device_paths, '1',
                                        volume_alias, volume_alias, False)

        return device_path

    @staticmethod
    def run_mdadm(executor, cmd, raise_exception=False):
        cmd_output = None
        try:
            lines, err = executor._execute(
                *cmd, run_as_root=True, root_helper=executor._root_helper)
            for line in lines.split('\n'):
                cmd_output = line
                break
        except putils.ProcessExecutionError as ex:
            LOG.warning("[!] Could not run mdadm: %s", str(ex))
            if raise_exception:
                raise ex
        return cmd_output

    @staticmethod
    def _is_device_in_raid(self, device_path):
        cmd = ['mdadm', '--examine', device_path]
        raid_expected = device_path + ':'
        try:
            lines, err = self._execute(
                *cmd, run_as_root=True, root_helper=self._root_helper)
            for line in lines.split('\n'):
                if line == raid_expected:
                    return True
                else:
                    return False
        except putils.ProcessExecutionError:
            return False

    @staticmethod
    def ks_readlink(dest):
        try:
            return os.readlink(dest)
        except Exception:
            return ''

    @staticmethod
    def get_md_name(executor, device_name):
        get_md_cmd = (
            'cat /proc/mdstat | grep ' + device_name +
            ' | awk \'{print $1;}\'')
        cmd = ['bash', '-c', get_md_cmd]
        LOG.debug("[!] cmd = " + str(cmd))
        cmd_output = None

        try:
            lines, err = executor._execute(
                *cmd, run_as_root=True, root_helper=executor._root_helper)

            for line in lines.split('\n'):
                cmd_output = line
                break

            LOG.debug("[!] cmd_output = " + cmd_output)
            if err:
                return None

            return cmd_output
        except putils.ProcessExecutionError as ex:
            LOG.warning("[!] Could not run cmd: %s", str(ex))
        return None

    @staticmethod
    def stop_and_assemble_raid(executor, drives, md_path, read_only):
        md_name = None
        i = 0
        assembled = False
        link = ''
        while i < 5 and not assembled:
            for drive in drives:
                device_name = drive[5:]
                md_name = NVMeOFConnector.get_md_name(executor, device_name)
                link = NVMeOFConnector.ks_readlink(md_path)
                if link != '':
                    link = os.path.basename(link)
                if md_name and md_name == link:
                    return
                LOG.debug(
                    "sleeping 1 sec -allow auto assemble link = " +
                    link + " md path = " + md_path)
                time.sleep(1)

            if md_name and md_name != link:
                NVMeOFConnector.stop_raid(executor, md_name)

            try:
                assembled = NVMeOFConnector.assemble_raid(
                    executor, drives, md_path, False)
            except Exception:
                i += 1

    @staticmethod
    def assemble_raid(executor, drives, md_path, read_only):
        cmd = ['mdadm', '--assemble', '--run', md_path]

        if read_only:
            cmd.append('-o')

        for i in range(len(drives)):
            cmd.append(drives[i])

        try:
            NVMeOFConnector.run_mdadm(executor, cmd, True)
        except putils.ProcessExecutionError as ex:
            LOG.warning("[!] Could not _assemble_raid: %s", str(ex))
            raise ex

        return True

    @staticmethod
    def create_raid(executor, drives, raid_type, device_name, name, read_only):
        cmd = ['mdadm']
        num_drives = len(drives)
        cmd.append('-C')

        if read_only:
            cmd.append('-o')

        cmd.append(device_name)
        cmd.append('-R')

        if name:
            cmd.append('-N')
            cmd.append(name)

        cmd.append('--level')
        cmd.append(raid_type)
        cmd.append('--raid-devices=' + str(num_drives))
        cmd.append('--bitmap=internal')
        cmd.append('--homehost=any')
        cmd.append('--failfast')
        cmd.append('--assume-clean')

        for i in range(len(drives)):
            cmd.append(drives[i])

        LOG.debug('[!] cmd = ' + str(cmd))
        NVMeOFConnector.run_mdadm(executor, cmd)

    @staticmethod
    def end_raid(executor, device_path):
        raid_exists = NVMeOFConnector.is_raid_exists(executor, device_path)
        if raid_exists:
            for i in range(10):
                try:
                    cmd_out = NVMeOFConnector.stop_raid(
                        executor, device_path)
                    if not cmd_out:
                        break
                except Exception:
                    break
                time.sleep(1)
            try:
                is_exist = os.path.exists(device_path)
                LOG.debug("[!] is_exist = %s", is_exist)
                if is_exist:
                    NVMeOFConnector.remove_raid(executor, device_path)
                    os.remove(device_path)
            except Exception:
                LOG.debug('[!] Exception_stop_raid!')

    @staticmethod
    def stop_raid(executor, md_path):
        cmd = ['mdadm', '--stop', md_path]
        LOG.debug("[!] cmd = " + str(cmd))
        cmd_out = NVMeOFConnector.run_mdadm(executor, cmd)
        return cmd_out

    @staticmethod
    def is_raid_exists(executor, device_path):
        cmd = ['mdadm', '--detail', device_path]
        LOG.debug("[!] cmd = " + str(cmd))
        raid_expected = device_path + ':'
        try:
            lines, err = executor._execute(
                *cmd, run_as_root=True, root_helper=executor._root_helper)

            for line in lines.split('\n'):
                LOG.debug("[!] line = " + line)
                if line == raid_expected:
                    return True
                else:
                    return False
        except putils.ProcessExecutionError:
            return False

    @staticmethod
    def remove_raid(executor, device_path):
        cmd = ['mdadm', '--remove', device_path]
        LOG.debug("[!] cmd = " + str(cmd))
        NVMeOFConnector.run_mdadm(executor, cmd)

    @staticmethod
    def run_nvme_cli(executor, nvme_command, **kwargs):
        (out, err) = executor._execute('nvme', *nvme_command, run_as_root=True,
                                       root_helper=executor._root_helper,
                                       check_exit_code=True)
        msg = ("nvme %(nvme_command)s: stdout=%(out)s stderr=%(err)s" %
               {'nvme_command': nvme_command, 'out': out, 'err': err})
        LOG.debug("[!] " + msg)

        return out, err

    @staticmethod
    def rescan(executor, target_nqn, vol_uuid):
        ctr_device = (
            NVMeOFConnector.get_search_path() +
            NVMeOFConnector._get_nvme_controller(executor, target_nqn))
        nvme_command = ('ns-rescan', ctr_device)
        try:
            NVMeOFConnector.run_nvme_cli(executor, nvme_command)
        except Exception as e:
            raise exception.CommandExecutionFailed(e, cmd=nvme_command)

    def _get_fs_type(self, device_path):
        cmd = ['blkid', device_path, '-s', 'TYPE', '-o', 'value']
        LOG.debug("[!] cmd = " + str(cmd))
        fs_type = None

        try:
            lines, err = self._execute(
                *cmd, run_as_root=True, root_helper=self._root_helper)

            fs_type = lines.split('\n')[0]
        except putils.ProcessExecutionError:
            return None

        return fs_type
