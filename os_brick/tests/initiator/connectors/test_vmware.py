# Copyright (c) 2016 VMware, Inc.
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

from unittest import mock

import ddt
from oslo_utils import units
from oslo_vmware.objects import datastore
from oslo_vmware import vim_util

from os_brick import exception
from os_brick.initiator.connectors import vmware
from os_brick.tests.initiator import test_connector


@ddt.ddt
class VmdkConnectorTestCase(test_connector.ConnectorTestCase):

    IP = '127.0.0.1'
    PORT = 443
    USERNAME = 'username'
    PASSWORD = 'password'
    API_RETRY_COUNT = 3
    TASK_POLL_INTERVAL = 5.0
    CA_FILE = "/etc/ssl/rui-ca-cert.pem"
    TMP_DIR = "/vmware-tmp"
    IMG_TX_TIMEOUT = 10

    VMDK_CONNECTOR = vmware.VmdkConnector

    def setUp(self):
        super(VmdkConnectorTestCase, self).setUp()

        self._connector = vmware.VmdkConnector(None)
        self._connector._ip = self.IP
        self._connector._port = self.PORT
        self._connector._username = self.USERNAME
        self._connector._password = self.PASSWORD
        self._connector._api_retry_count = self.API_RETRY_COUNT
        self._connector._task_poll_interval = self.TASK_POLL_INTERVAL
        self._connector._ca_file = self.CA_FILE
        self._connector._insecure = True
        self._connector._tmp_dir = self.TMP_DIR
        self._connector._timeout = self.IMG_TX_TIMEOUT

    def test_load_config(self):
        config = {
            'vmware_host_ip': 'localhost',
            'vmware_host_port': 1234,
            'vmware_host_username': 'root',
            'vmware_host_password': 'pswd',
            'vmware_api_retry_count': 1,
            'vmware_task_poll_interval': 1.0,
            'vmware_ca_file': None,
            'vmware_insecure': False,
            'vmware_tmp_dir': '/tmp',
            'vmware_image_transfer_timeout_secs': 5,
        }
        self._connector._load_config({'config': config})

        self.assertEqual('localhost', self._connector._ip)
        self.assertEqual(1234, self._connector._port)
        self.assertEqual('root', self._connector._username)
        self.assertEqual('pswd', self._connector._password)
        self.assertEqual(1, self._connector._api_retry_count)
        self.assertEqual(1.0, self._connector._task_poll_interval)
        self.assertIsNone(self._connector._ca_file)
        self.assertFalse(self._connector._insecure)
        self.assertEqual('/tmp', self._connector._tmp_dir)
        self.assertEqual(5, self._connector._timeout)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_create_session(self, session):
        session.return_value = mock.sentinel.session

        ret = self._connector._create_session()

        self.assertEqual(mock.sentinel.session, ret)
        session.assert_called_once_with(
            self._connector._ip,
            self._connector._username,
            self._connector._password,
            self._connector._api_retry_count,
            self._connector._task_poll_interval,
            port=self._connector._port,
            cacert=self._connector._ca_file,
            insecure=self._connector._insecure)

    @mock.patch('oslo_utils.fileutils.ensure_tree')
    @mock.patch('tempfile.mkstemp')
    @mock.patch('os.close')
    def test_create_temp_file(
            self, close, mkstemp, ensure_tree):
        fd = mock.sentinel.fd
        tmp = mock.sentinel.tmp
        mkstemp.return_value = (fd, tmp)

        prefix = ".vmdk"
        suffix = "test"
        ret = self._connector._create_temp_file(prefix=prefix, suffix=suffix)

        self.assertEqual(tmp, ret)
        ensure_tree.assert_called_once_with(self._connector._tmp_dir)
        mkstemp.assert_called_once_with(dir=self._connector._tmp_dir,
                                        prefix=prefix,
                                        suffix=suffix)
        close.assert_called_once_with(fd)

    @mock.patch('os_brick.initiator.connectors.vmware.open', create=True)
    @mock.patch('oslo_vmware.image_transfer.copy_stream_optimized_disk')
    def test_download_vmdk(self, copy_disk, file_open):
        file_open_ret = mock.Mock()
        tmp_file = mock.sentinel.tmp_file
        file_open_ret.__enter__ = mock.Mock(return_value=tmp_file)
        file_open_ret.__exit__ = mock.Mock(return_value=None)
        file_open.return_value = file_open_ret

        tmp_file_path = mock.sentinel.tmp_file_path
        session = mock.sentinel.session
        backing = mock.sentinel.backing
        vmdk_path = mock.sentinel.vmdk_path
        vmdk_size = mock.sentinel.vmdk_size
        self._connector._download_vmdk(
            tmp_file_path, session, backing, vmdk_path, vmdk_size)

        file_open.assert_called_once_with(tmp_file_path, 'wb')
        copy_disk.assert_called_once_with(None,
                                          self._connector._timeout,
                                          tmp_file,
                                          session=session,
                                          host=self._connector._ip,
                                          port=self._connector._port,
                                          vm=backing,
                                          vmdk_file_path=vmdk_path,
                                          vmdk_size=vmdk_size)

    def _create_connection_properties(self):
        return {'volume_id': 'ed083474-d325-4a99-b301-269111654f0d',
                'volume': 'ref-1',
                'vmdk_path': '[ds] foo/bar.vmdk',
                'vmdk_size': units.Gi,
                'datastore': 'ds-1',
                'datacenter': 'dc-1',
                }

    @mock.patch.object(VMDK_CONNECTOR, '_load_config')
    @mock.patch.object(VMDK_CONNECTOR, '_create_session')
    @mock.patch.object(VMDK_CONNECTOR, '_create_temp_file')
    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch.object(VMDK_CONNECTOR, '_download_vmdk')
    @mock.patch('os.path.getmtime')
    def test_connect_volume(
            self, getmtime, download_vmdk, get_moref, create_temp_file,
            create_session, load_config):
        session = mock.Mock()
        create_session.return_value = session

        tmp_file_path = mock.sentinel.tmp_file_path
        create_temp_file.return_value = tmp_file_path

        backing = mock.sentinel.backing
        get_moref.return_value = backing

        last_modified = mock.sentinel.last_modified
        getmtime.return_value = last_modified

        props = self._create_connection_properties()
        ret = self._connector.connect_volume(props)

        self.assertEqual(tmp_file_path, ret['path'])
        self.assertEqual(last_modified, ret['last_modified'])
        load_config.assert_called_once_with(props)
        create_session.assert_called_once_with()
        create_temp_file.assert_called_once_with(
            suffix=".vmdk", prefix=props['volume_id'])
        download_vmdk.assert_called_once_with(
            tmp_file_path, session, backing, props['vmdk_path'],
            props['vmdk_size'])
        session.logout.assert_called_once_with()

    @ddt.data((None, False), ([mock.sentinel.snap], True))
    @ddt.unpack
    def test_snapshot_exists(self, snap_list, exp_return_value):
        snapshot = mock.Mock(rootSnapshotList=snap_list)
        session = mock.Mock()
        session.invoke_api.return_value = snapshot

        backing = mock.sentinel.backing
        ret = self._connector._snapshot_exists(session, backing)

        self.assertEqual(exp_return_value, ret)
        session.invoke_api.assert_called_once_with(
            vim_util, 'get_object_property', session.vim, backing, 'snapshot')

    def test_create_temp_ds_folder(self):
        session = mock.Mock()
        ds_folder_path = mock.sentinel.ds_folder_path
        dc_ref = mock.sentinel.dc_ref
        self._connector._create_temp_ds_folder(session, ds_folder_path, dc_ref)

        session.invoke_api.assert_called_once_with(
            session.vim,
            'MakeDirectory',
            session.vim.service_content.fileManager,
            name=ds_folder_path,
            datacenter=dc_ref)

    @mock.patch('oslo_vmware.objects.datastore.get_datastore_by_ref')
    @mock.patch.object(VMDK_CONNECTOR, '_create_temp_ds_folder')
    @mock.patch('os_brick.initiator.connectors.vmware.open', create=True)
    @mock.patch.object(VMDK_CONNECTOR, '_upload_vmdk')
    @mock.patch('os.path.getsize')
    @mock.patch.object(VMDK_CONNECTOR, '_get_disk_device')
    @mock.patch.object(VMDK_CONNECTOR, '_detach_disk_from_backing')
    @mock.patch.object(VMDK_CONNECTOR, '_attach_disk_to_backing')
    def test_disconnect(
            self, attach_disk_to_backing, detach_disk_from_backing,
            get_disk_device, getsize, upload_vmdk, file_open,
            create_temp_ds_folder, get_ds_by_ref):
        ds_ref = mock.sentinel.ds_ref
        ds_name = 'datastore-1'
        dstore = datastore.Datastore(ds_ref, ds_name)
        get_ds_by_ref.return_value = dstore

        file_open_ret = mock.Mock()
        tmp_file = mock.sentinel.tmp_file
        file_open_ret.__enter__ = mock.Mock(return_value=tmp_file)
        file_open_ret.__exit__ = mock.Mock(return_value=None)
        file_open.return_value = file_open_ret

        dc_name = mock.sentinel.dc_name
        copy_task = mock.sentinel.copy_vdisk_task
        delete_file_task = mock.sentinel.delete_file_task
        session = mock.Mock()
        session.invoke_api.side_effect = [dc_name, copy_task, delete_file_task]

        getsize.return_value = units.Gi
        disk_device = mock.sentinel.disk_device
        get_disk_device.return_value = disk_device

        backing = mock.sentinel.backing
        tmp_file_path = '/tmp/foo.vmdk'
        dc_ref = mock.sentinel.dc_ref
        vmdk_path = mock.sentinel.vmdk_path
        self._connector._disconnect(
            backing, tmp_file_path, session, ds_ref, dc_ref, vmdk_path)

        tmp_folder_path = self._connector.TMP_IMAGES_DATASTORE_FOLDER_PATH
        ds_folder_path = '[%s] %s' % (ds_name, tmp_folder_path)
        create_temp_ds_folder.assert_called_once_with(
            session, ds_folder_path, dc_ref)
        file_open.assert_called_once_with(tmp_file_path, "rb")

        self.assertEqual(
            mock.call(vim_util, 'get_object_property', session.vim, dc_ref,
                      'name'), session.invoke_api.call_args_list[0])

        exp_rel_path = '%s/foo.vmdk' % tmp_folder_path
        upload_vmdk.assert_called_once_with(
            tmp_file, self._connector._ip, self._connector._port, dc_name,
            ds_name, session.vim.client.options.transport.cookiejar,
            exp_rel_path, units.Gi, self._connector._ca_file,
            self._connector._timeout)

        get_disk_device.assert_called_once_with(session, backing)
        detach_disk_from_backing.assert_called_once_with(
            session, backing, disk_device)

        src = '[%s] %s' % (ds_name, exp_rel_path)
        disk_mgr = session.vim.service_content.virtualDiskManager
        self.assertEqual(
            mock.call(session.vim, 'CopyVirtualDisk_Task', disk_mgr,
                      sourceName=src, sourceDatacenter=dc_ref,
                      destName=vmdk_path, destDatacenter=dc_ref),
            session.invoke_api.call_args_list[1])
        self.assertEqual(mock.call(copy_task),
                         session.wait_for_task.call_args_list[0])

        attach_disk_to_backing.assert_called_once_with(
            session, backing, disk_device)

        file_mgr = session.vim.service_content.fileManager
        self.assertEqual(
            mock.call(session.vim, 'DeleteDatastoreFile_Task', file_mgr,
                      name=src, datacenter=dc_ref),
            session.invoke_api.call_args_list[2])
        self.assertEqual(mock.call(delete_file_task),
                         session.wait_for_task.call_args_list[1])

    @mock.patch('os.path.exists')
    def test_disconnect_volume_with_missing_temp_file(self, path_exists):
        path_exists.return_value = False

        path = mock.sentinel.path
        self.assertRaises(exception.NotFound,
                          self._connector.disconnect_volume,
                          mock.ANY,
                          {'path': path})
        path_exists.assert_called_once_with(path)

    @mock.patch('os.path.exists')
    @mock.patch('os.path.getmtime')
    @mock.patch.object(VMDK_CONNECTOR, '_disconnect')
    @mock.patch('os.remove')
    def test_disconnect_volume_with_unmodified_file(
            self, remove, disconnect, getmtime, path_exists):
        path_exists.return_value = True

        mtime = 1467802060
        getmtime.return_value = mtime

        path = mock.sentinel.path
        self._connector.disconnect_volume(mock.ANY, {'path': path,
                                                     'last_modified': mtime})

        path_exists.assert_called_once_with(path)
        getmtime.assert_called_once_with(path)
        disconnect.assert_not_called()
        remove.assert_called_once_with(path)

    @mock.patch('os.path.exists')
    @mock.patch('os.path.getmtime')
    @mock.patch.object(VMDK_CONNECTOR, '_load_config')
    @mock.patch.object(VMDK_CONNECTOR, '_create_session')
    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch.object(VMDK_CONNECTOR, '_snapshot_exists')
    @mock.patch.object(VMDK_CONNECTOR, '_disconnect')
    @mock.patch('os.remove')
    def test_disconnect_volume(
            self, remove, disconnect, snapshot_exists, get_moref,
            create_session, load_config, getmtime, path_exists):
        path_exists.return_value = True

        mtime = 1467802060
        getmtime.return_value = mtime

        session = mock.Mock()
        create_session.return_value = session

        snapshot_exists.return_value = False

        backing = mock.sentinel.backing
        ds_ref = mock.sentinel.ds_ref
        dc_ref = mock.sentinel.dc_ref
        get_moref.side_effect = [backing, ds_ref, dc_ref]

        props = self._create_connection_properties()
        path = mock.sentinel.path
        self._connector.disconnect_volume(props, {'path': path,
                                                  'last_modified': mtime - 1})

        path_exists.assert_called_once_with(path)
        getmtime.assert_called_once_with(path)
        load_config.assert_called_once_with(props)
        create_session.assert_called_once_with()
        snapshot_exists.assert_called_once_with(session, backing)
        disconnect.assert_called_once_with(
            backing, path, session, ds_ref, dc_ref, props['vmdk_path'])
        remove.assert_called_once_with(path)
        session.logout.assert_called_once_with()

    def test_get_disk_device(self):
        disk_device = mock.Mock()
        disk_device.__class__.__name__ = 'VirtualDisk'

        controller_device = mock.Mock()
        controller_device.__class__.__name__ = 'VirtualLSILogicController'

        devices = mock.Mock()
        devices.__class__.__name__ = "ArrayOfVirtualDevice"
        devices.VirtualDevice = [disk_device, controller_device]
        session = mock.Mock()
        session.invoke_api.return_value = devices

        backing = mock.sentinel.backing
        self.assertEqual(disk_device,
                         self._connector._get_disk_device(session, backing))
        session.invoke_api.assert_called_once_with(
            vim_util, 'get_object_property', session.vim,
            backing, 'config.hardware.device')

    def test_create_spec_for_disk_remove(self):
        disk_spec = mock.Mock()
        session = mock.Mock()
        session.vim.client.factory.create.return_value = disk_spec

        disk_device = mock.sentinel.disk_device
        self._connector._create_spec_for_disk_remove(session, disk_device)

        session.vim.client.factory.create.assert_called_once_with(
            'ns0:VirtualDeviceConfigSpec')
        self.assertEqual('remove', disk_spec.operation)
        self.assertEqual('destroy', disk_spec.fileOperation)
        self.assertEqual(disk_device, disk_spec.device)

    @mock.patch.object(VMDK_CONNECTOR, '_create_spec_for_disk_remove')
    @mock.patch.object(VMDK_CONNECTOR, '_reconfigure_backing')
    def test_detach_disk_from_backing(self, reconfigure_backing, create_spec):
        disk_spec = mock.sentinel.disk_spec
        create_spec.return_value = disk_spec

        reconfig_spec = mock.Mock()
        session = mock.Mock()
        session.vim.client.factory.create.return_value = reconfig_spec

        backing = mock.sentinel.backing
        disk_device = mock.sentinel.disk_device
        self._connector._detach_disk_from_backing(
            session, backing, disk_device)

        create_spec.assert_called_once_with(session, disk_device)
        session.vim.client.factory.create.assert_called_once_with(
            'ns0:VirtualMachineConfigSpec')
        self.assertEqual([disk_spec], reconfig_spec.deviceChange)
        reconfigure_backing.assert_called_once_with(
            session, backing, reconfig_spec)

    @mock.patch.object(VMDK_CONNECTOR, '_reconfigure_backing')
    def test_attach_disk_to_backing(self, reconfigure_backing):
        reconfig_spec = mock.Mock()
        disk_spec = mock.Mock()
        session = mock.Mock()
        session.vim.client.factory.create.side_effect = [
            reconfig_spec, disk_spec]

        backing = mock.Mock()
        disk_device = mock.sentinel.disk_device
        self._connector._attach_disk_to_backing(session, backing, disk_device)

        self.assertEqual([disk_spec], reconfig_spec.deviceChange)
        self.assertEqual('add', disk_spec.operation)
        self.assertEqual(disk_device, disk_spec.device)
        reconfigure_backing.assert_called_once_with(
            session, backing, reconfig_spec)
