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

import builtins
import errno
import os.path
from unittest import mock

import ddt
from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick import executor
from os_brick.initiator.connectors import nvmeof
from os_brick.privileged import nvmeof as priv_nvmeof
from os_brick.privileged import rootwrap as priv_rootwrap
from os_brick.tests import base as test_base
from os_brick.tests.initiator import test_connector
from os_brick import utils


TARGET_NQN = 'target.nqn'
VOL_UUID = 'c20aba21-6ef6-446b-b374-45733b4883ba'
VOL_UUID_NO_HYPHENS = 'c20aba216ef6446bb37445733b4883ba'
NVME_DEVICE_PATH = '/dev/nvme1'
NVME_NS_PATH = '/dev/nvme1n1'
NGUID = '4941ef75-95b8-ee97-8ccf-096800f205c6'
NGUID_NO_HYPHENS = '4941ef7595b8ee978ccf096800f205c6'
SYS_UUID = '9126E942-396D-11E7-B0B7-A81E84C186D1'
HOST_UUID = 'c20aba21-6ef6-446b-b374-45733b4883ba'
HOST_NQN = 'nqn.2014-08.org.nvmexpress:uuid:' \
           'beaae2de-3a97-4be1-a739-6ac4bc5bf138'
VOL_UUID1 = '9b30ec12-75b9-4a53-be32-111111111111'
VOL_UUID2 = '9b30ec12-75b9-4a53-be32-222222222222'
VOL_UUID3 = '9b30ec12-75b9-4a53-be32-333333333333'
volume_replicas = [{'target_nqn': 'fakenqn1', 'vol_uuid': VOL_UUID1,
                    'portals': [('10.0.0.1', 4420, 'tcp')]},
                   {'target_nqn': 'fakenqn2', 'vol_uuid': VOL_UUID2,
                    'portals': [('10.0.0.2', 4420, 'tcp')]},
                   {'target_nqn': 'fakenqn3', 'vol_uuid': VOL_UUID3,
                    'portals': [('10.0.0.3', 4420, 'tcp')]}]
connection_properties = {
    'alias': 'fakealias',
    'vol_uuid': VOL_UUID,
    'volume_replicas': volume_replicas,
    'replica_count': 3
}
CONN_PROPS = nvmeof.NVMeOFConnProps(connection_properties)
fake_portal = ('fake', 'portal', 'tcp')
nvme_list_stdout = """
Node          SN      Model Namespace Usage            Format      FW Rev
------------- ------- ----- --------- ---------------- ----------- -------
/dev/nvme0n1  AB12345 s123  12682     0.00 B / 2.15 GB 512 B + 0 B 2.1.0.0
/dev/nvme0n2  AB12345 s123  12683     0.00 B / 1.07 GB 512 B + 0 B 2.1.0.0
"""

md_stat_contents = """
Personalities : [raid0]
md0 : active raid0 nvme0n1[4] nvme1n1[3] nvme2n1[2] nvme3n1[1]
      20508171264 blocks super 1.2 level 5, 512k chunk, algorithm 2 [4/4] [UUUU]
unused devices: <none>
"""  # noqa


@ddt.ddt
class UtilityMethodsTestCase(test_base.TestCase):
    @mock.patch.object(nvmeof, 'sysfs_property', return_value='live')
    def test_ctrl_property(self, mock_sysfs):
        """Controller properties just read from nvme fabrics in sysfs."""
        res = nvmeof.ctrl_property('state', 'nvme0')
        self.assertEqual('live', res)
        mock_sysfs.assert_called_once_with('state',
                                           '/sys/class/nvme-fabrics/ctl/nvme0')

    @mock.patch.object(nvmeof, 'sysfs_property', return_value='uuid_value')
    def test_blk_property(self, mock_sysfs):
        """Block properties just read from block devices in sysfs."""
        res = nvmeof.blk_property('uuid', 'nvme0n1')

        self.assertEqual('uuid_value', res)
        mock_sysfs.assert_called_once_with('uuid', '/sys/class/block/nvme0n1')

    @mock.patch.object(builtins, 'open')
    def test_sysfs_property(self, mock_open):
        """Method is basically an open an read method."""
        mock_read = mock_open.return_value.__enter__.return_value.read
        mock_read.return_value = ' uuid '
        res = nvmeof.sysfs_property('uuid', '/sys/class/block/nvme0n1')
        self.assertEqual('uuid', res)
        mock_open.assert_called_once_with('/sys/class/block/nvme0n1/uuid', 'r')
        mock_read.assert_called_once_with()

    @mock.patch.object(builtins, 'open', side_effect=FileNotFoundError)
    def test_sysfs_property_not_found(self, mock_open):
        """Failure to open file returns None."""
        mock_read = mock_open.return_value.__enter__.return_value.read
        res = nvmeof.sysfs_property('uuid', '/sys/class/block/nvme0n1')
        self.assertIsNone(res)
        mock_open.assert_called_once_with('/sys/class/block/nvme0n1/uuid', 'r')
        mock_read.assert_not_called()

    @mock.patch.object(builtins, 'open')
    def test_sysfs_property_ioerror(self, mock_open):
        """Failure to read file returns None."""
        mock_read = mock_open.return_value.__enter__.return_value.read
        mock_read.side_effect = IOError
        res = nvmeof.sysfs_property('uuid', '/sys/class/block/nvme0n1')
        self.assertIsNone(res)
        mock_open.assert_called_once_with('/sys/class/block/nvme0n1/uuid', 'r')
        mock_read.assert_called_once_with()

    @ddt.data('/dev/nvme0n10',
              '/sys/class/block/nvme0c1n10',
              '/sys/class/nvme-fabrics/ctl/nvme1/nvme0c1n10')
    def test_nvme_basename(self, name):
        """ANA devices are transformed to the right name."""
        res = nvmeof.nvme_basename(name)
        self.assertEqual('nvme0n10', res)


@ddt.ddt
class PortalTestCase(test_base.TestCase):
    def setUp(self):
        self.conn_props_dict = {'target_nqn': 'nqn_value',
                                'vol_uuid': VOL_UUID,
                                'portals': [('portal1', 'port1', 'RoCEv2')]}
        self.conn_props = nvmeof.NVMeOFConnProps(self.conn_props_dict)
        self.target = self.conn_props.targets[0]
        self.portal = self.target.portals[0]
        super().setUp()

    @ddt.data(('RoCEv2', 'rdma'), ('rdma', 'rdma'), ('tcp', 'tcp'),
              ('TCP', 'tcp'), ('other', 'tcp'))
    @ddt.unpack
    def test_init(self, transport, expected_transport):
        """Init changes conn props transport into rdma or tcp."""
        portal = nvmeof.Portal(self.target, 'address', 'port', transport)
        self.assertEqual(self.target, portal.parent_target)
        self.assertEqual('address', portal.address)
        self.assertEqual('port', portal.port)
        self.assertIsNone(portal.controller)
        self.assertEqual(expected_transport, portal.transport)

    @ddt.data(('live', True), ('connecting', False), (None, False))
    @ddt.unpack
    @mock.patch.object(nvmeof.Portal, 'state',
                       new_callable=mock.PropertyMock)
    def test_is_live(self, state, expected, mock_state):
        """Is live only returns True if the state is 'live'."""
        mock_state.return_value = state
        self.assertIs(expected, self.portal.is_live)
        mock_state.assert_called_once_with()

    @mock.patch.object(nvmeof, 'ctrl_property')
    def test_state(self, mock_property):
        """State uses sysfs to check the value."""
        self.portal.controller = 'nvme0'
        self.assertEqual(mock_property.return_value, self.portal.state)
        mock_property.assert_called_once_with('state', 'nvme0')

    @mock.patch.object(nvmeof, 'ctrl_property')
    def test_state_no_controller(self, mock_property):
        """Cannot read the state if the controller name has not been found."""
        self.portal.controller = None
        self.assertIsNone(self.portal.state)
        mock_property.assert_not_called()

    @mock.patch.object(nvmeof.Portal, 'get_device_by_property')
    def test_get_device(self, mock_property):
        """UUID has priority over everything else."""
        mock_property.return_value = 'result'
        self.target.nguid = 'nguid'  # will be ignored
        res = self.portal.get_device()
        self.assertEqual('result', res)
        mock_property.assert_called_once_with('uuid', self.target.uuid)

    @mock.patch.object(nvmeof.Portal, 'get_device_by_property')
    def test_get_device_by_nguid(self, mock_property):
        """nguid takes priority over ns_id if no UUID."""
        mock_property.return_value = 'result'
        self.target.uuid = None
        self.target.nguid = 'nguid_value'
        self.target.ns_id = 'ns_id_value'  # will be ignored
        res = self.portal.get_device()
        self.assertEqual('result', res)
        mock_property.assert_called_once_with('nguid', 'nguid_value')

    @mock.patch.object(nvmeof.Portal, 'get_device_by_property')
    def test_get_device_by_ns_id(self, mock_property):
        """ns_id takes priority if no UUID and nguid are present."""
        mock_property.return_value = 'result'
        self.target.uuid = None
        self.target.nguid = None
        self.target.ns_id = 'ns_id_value'
        res = self.portal.get_device()
        self.assertEqual('result', res)
        mock_property.assert_called_once_with('nsid', 'ns_id_value')

    @mock.patch.object(nvmeof.Target, 'get_device_path_by_initial_devices')
    @mock.patch.object(nvmeof.Portal, 'get_device_by_property')
    def test_get_device_by_initial_devices(self, mock_property, mock_get_dev):
        """With no id, calls target to get device from initial devices."""
        mock_get_dev.return_value = 'result'
        self.target.uuid = None
        self.target.nguid = None
        self.target.ns_id = None
        res = self.portal.get_device()
        self.assertEqual('result', res)
        mock_get_dev.assert_called_once_with()

    @mock.patch('glob.glob')
    def test_get_all_namespaces_ctrl_paths(self, mock_glob):
        expected = ['/sys/class/nvme-fabrics/ctl/nvme0/nvme0n1',
                    '/sys/class/nvme-fabrics/ctl/nvme0/nvme1c1n2']
        mock_glob.return_value = expected[:]
        self.portal.controller = 'nvme0'

        res = self.portal.get_all_namespaces_ctrl_paths()

        self.assertEqual(expected, res)
        mock_glob.assert_called_once_with(
            '/sys/class/nvme-fabrics/ctl/nvme0/nvme*')

    @mock.patch('glob.glob')
    def test_get_all_namespaces_ctrl_paths_no_controller(self, mock_glob):
        res = self.portal.get_all_namespaces_ctrl_paths()

        self.assertEqual([], res)
        mock_glob.assert_not_called()

    @mock.patch.object(nvmeof, 'nvme_basename', return_value='nvme1n2')
    @mock.patch.object(nvmeof, 'sysfs_property')
    @mock.patch.object(nvmeof.Portal, 'get_all_namespaces_ctrl_paths')
    def test_get_device_by_property(self, mock_paths, mock_property,
                                    mock_name):
        """Searches all devices for the right one and breaks when found."""
        mock_paths.return_value = [
            '/sys/class/nvme-fabrics/ctl/nvme0/nvme0n1',
            '/sys/class/nvme-fabrics/ctl/nvme0/nvme1c1n2',
            '/sys/class/nvme-fabrics/ctl/nvme0/nvme0n3'
        ]
        mock_property.side_effect = ['uuid1', 'uuid2']
        self.portal.controller = 'nvme0'

        res = self.portal.get_device_by_property('uuid', 'uuid2')

        self.assertEqual('/dev/nvme1n2', res)

        mock_paths.assert_called_once_with()
        self.assertEqual(2, mock_property.call_count)
        mock_property.assert_has_calls(
            [mock.call('uuid', '/sys/class/nvme-fabrics/ctl/nvme0/nvme0n1'),
             mock.call('uuid', '/sys/class/nvme-fabrics/ctl/nvme0/nvme1c1n2')]
        )
        mock_name.assert_called_once_with(
            '/sys/class/nvme-fabrics/ctl/nvme0/nvme1c1n2')

    @mock.patch.object(nvmeof, 'nvme_basename', return_value='nvme1n2')
    @mock.patch.object(nvmeof, 'sysfs_property')
    @mock.patch.object(nvmeof.Portal, 'get_all_namespaces_ctrl_paths')
    def test_get_device_by_property_not_found(
            self, mock_paths, mock_property, mock_name):
        """Exhausts devices searching before returning None."""
        mock_paths.return_value = ['/sys/class/nvme-fabrics/ctl/nvme0/nvme0n1',
                                   '/sys/class/nvme-fabrics/ctl/nvme0/nvme0n2']
        mock_property.side_effect = ['uuid1', 'uuid2']
        self.portal.controller = 'nvme0'

        res = self.portal.get_device_by_property('uuid', 'uuid3')

        self.assertIsNone(res)

        mock_paths.assert_called_once_with()
        self.assertEqual(2, mock_property.call_count)
        mock_property.assert_has_calls(
            [mock.call('uuid', '/sys/class/nvme-fabrics/ctl/nvme0/nvme0n1'),
             mock.call('uuid', '/sys/class/nvme-fabrics/ctl/nvme0/nvme0n2')]
        )
        mock_name.assert_not_called()

    @mock.patch.object(nvmeof.Portal, 'get_all_namespaces_ctrl_paths')
    def test__can_disconnect_no_controller_name(self, mock_paths):
        """Cannot disconnect when portal doesn't have a controller."""
        res = self.portal.can_disconnect()
        self.assertFalse(res)
        mock_paths.assert_not_called()

    @ddt.data(([], True),
              (['/sys/class/nvme-fabrics/ctl/nvme0/nvme0n1',
                '/sys/class/nvme-fabrics/ctl/nvme0/nvme0n2'], False))
    @ddt.unpack
    @mock.patch.object(nvmeof.Portal, 'get_all_namespaces_ctrl_paths')
    def test__can_disconnect_not_1_namespace(
            self, ctrl_paths, expected, mock_paths):
        """Check if can disconnect when we don't have 1 namespace in subsys."""
        self.portal.controller = 'nvme0'
        mock_paths.return_value = ctrl_paths
        res = self.portal.can_disconnect()
        self.assertIs(expected, res)
        mock_paths.assert_called_once_with()

    @mock.patch.object(nvmeof.Portal, 'get_device')
    @mock.patch.object(nvmeof.Portal, 'get_all_namespaces_ctrl_paths')
    def test__can_disconnect(self, mock_paths, mock_device):
        """Can disconnect if the namespace is the one from this target.

        This tests that even when ANA is enabled it can identify the control
        path as belonging to the used device path.
        """
        self.portal.controller = 'nvme0'
        mock_device.return_value = '/dev/nvme1n2'
        mock_paths.return_value = [
            '/sys/class/nvme-fabrics/ctl/nvme0/nvme1c1n2']
        self.assertTrue(self.portal.can_disconnect())

    @mock.patch.object(nvmeof.Portal, 'get_device')
    @mock.patch.object(nvmeof.Portal, 'get_all_namespaces_ctrl_paths')
    def test__can_disconnect_different_target(self, mock_paths, mock_device):
        """Cannot disconnect if the namespace is from a different target."""
        self.portal.controller = 'nvme0'
        mock_device.return_value = None
        mock_paths.return_value = [
            '/sys/class/nvme-fabrics/ctl/nvme0/nvme1c1n2']
        self.assertFalse(self.portal.can_disconnect())


@ddt.ddt
class TargetTestCase(test_base.TestCase):
    def setUp(self):
        self.conn_props_dict = {
            'target_nqn': 'nqn_value',
            'vol_uuid': VOL_UUID,
            'portals': [('portal1', 'port1', 'RoCEv2'),
                        ('portal2', 'port2', 'anything')],
        }
        self.conn_props = nvmeof.NVMeOFConnProps(self.conn_props_dict)
        self.target = self.conn_props.targets[0]
        super().setUp()

    @mock.patch.object(nvmeof.Target, '__init__', return_value=None)
    def test_factory(self, mock_init):
        """Test Target factory

        The factory's parameter names take after the keys in the connection

        properties, and then calls the class init method that uses different
        names.
        """
        res = nvmeof.Target.factory(self.conn_props, **self.conn_props_dict)
        mock_init.assert_called_once_with(
            self.conn_props,
            self.conn_props_dict['target_nqn'],
            self.conn_props_dict['portals'],
            self.conn_props_dict['vol_uuid'],
            None,  # nguid
            None,  # ns_id
            None,  # host_nqn
            False)  # find_controllers
        self.assertIsInstance(res, nvmeof.Target)

    @ddt.data(True, False)
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.Portal, '__init__', return_value=None)
    def test_init(self, find_controllers, mock_init, mock_set_ctrls):
        """Init instantiates portals and may call set_portals_controllers."""
        target = nvmeof.Target(self.conn_props,
                               'nqn',
                               self.conn_props_dict['portals'],
                               # Confirm they get converted to hyphenated
                               VOL_UUID_NO_HYPHENS,
                               NGUID_NO_HYPHENS,
                               'ns_id',
                               'host_nqn',
                               find_controllers)

        self.assertEqual(self.conn_props, target.source_conn_props)
        self.assertEqual('nqn', target.nqn)
        self.assertEqual(VOL_UUID, target.uuid)
        self.assertEqual(NGUID, target.nguid)
        self.assertEqual('ns_id', target.ns_id)
        self.assertEqual('host_nqn', target.host_nqn)

        self.assertIsInstance(target.portals[0], nvmeof.Portal)
        self.assertIsInstance(target.portals[1], nvmeof.Portal)

        if find_controllers:
            mock_set_ctrls.assert_called_once_with()
        else:
            mock_set_ctrls.assert_not_called()

        self.assertEqual(2, mock_init.call_count)
        mock_init.assert_has_calls(
            [mock.call(target, 'portal1', 'port1', 'RoCEv2'),
             mock.call(target, 'portal2', 'port2', 'anything')]
        )

    @mock.patch.object(nvmeof.Target, '_get_nvme_devices')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.Portal, '__init__', return_value=None)
    def test_init_no_id(self, mock_init, mock_set_ctrls, mock_get_devs):
        """With no ID parameters query existing nvme devices."""
        target = nvmeof.Target(self.conn_props,
                               'nqn',
                               self.conn_props_dict['portals'])

        self.assertEqual(self.conn_props, target.source_conn_props)
        self.assertEqual('nqn', target.nqn)
        for name in ('uuid', 'nguid', 'ns_id'):
            self.assertIsNone(getattr(target, name))

        self.assertIsInstance(target.portals[0], nvmeof.Portal)
        self.assertIsInstance(target.portals[1], nvmeof.Portal)

        mock_set_ctrls.assert_not_called()
        mock_get_devs.assert_called_once_with()

        self.assertEqual(2, mock_init.call_count)
        mock_init.assert_has_calls(
            [mock.call(target, 'portal1', 'port1', 'RoCEv2'),
             mock.call(target, 'portal2', 'port2', 'anything')]
        )

    @mock.patch('glob.glob', return_value=['/dev/nvme0n1', '/dev/nvme1n1'])
    def test__get_nvme_devices(self, mock_glob):
        """Test getting all nvme devices present in system."""
        res = self.target._get_nvme_devices()
        self.assertEqual(mock_glob.return_value, res)
        mock_glob.assert_called_once_with('/dev/nvme*n*')

    @mock.patch.object(nvmeof.Portal, 'is_live',
                       new_callable=mock.PropertyMock)
    def test_live_portals(self, mock_is_live):
        """List with only live portals should be returned."""
        mock_is_live.side_effect = (True, False)
        res = self.target.live_portals
        self.assertListEqual([self.target.portals[0]], res)

    @mock.patch.object(nvmeof.Portal, 'state',
                       new_callable=mock.PropertyMock)
    def test_present_portals(self, mock_state):
        """List with only live portals should be returned."""
        # Duplicate number of portals
        self.target.portals.extend(self.target.portals)
        mock_state.side_effect = (None, 'live', 'connecting', 'live')
        res = self.target.present_portals
        self.assertListEqual(self.target.portals[1:], res)

    @mock.patch('glob.glob')
    def test_set_portals_controllers_do_nothing(self, mock_glob):
        """Do nothing if all protals already have the controller name."""
        self.target.portals[0].controller = 'nvme0'
        self.target.portals[1].controller = 'nvme1'
        self.target.set_portals_controllers()
        mock_glob.assert_not_called()

    @mock.patch.object(nvmeof, 'sysfs_property')
    @mock.patch('glob.glob')
    def test_set_portals_controllers(self, mock_glob, mock_sysfs):
        """Look in sysfs for the device paths."""
        portal = nvmeof.Portal(self.target, 'portal4', 'port4', 'tcp')
        portal.controller = 'nvme0'
        self.target.portals.insert(0, portal)
        self.target.portals.append(nvmeof.Portal(self.target, 'portal5',
                                                 'port5', 'tcp'))
        self.target.host_nqn = 'nqn'
        mock_glob.return_value = ['/sys/class/nvme-fabrics/ctl/nvme0',
                                  '/sys/class/nvme-fabrics/ctl/nvme1',
                                  '/sys/class/nvme-fabrics/ctl/nvme2',
                                  '/sys/class/nvme-fabrics/ctl/nvme3',
                                  '/sys/class/nvme-fabrics/ctl/nvme4',
                                  '/sys/class/nvme-fabrics/ctl/nvme5']
        mock_sysfs.side_effect = [
            # nvme0 is skipped because it already belongs to the first portal
            # nvme1 nqn doesn't match
            'wrong-nqn',
            # nvme2 matches nqn but not the address
            self.target.nqn, 'rdma', 'traddr=portal5,trsvcid=port5', 'nqn',
            # nvme3 matches first portal but not the host_nqn
            self.target.nqn, 'rdma', 'traddr=portal2,trsvcid=port2', 'badnqn',
            # nvme4 matches first portal
            self.target.nqn, 'tcp', 'traddr=portal2,trsvcid=port2', 'nqn',
            # nvme5 simulates OS doesn't have the hostnqn attribute
            self.target.nqn, 'tcp', 'traddr=portal5,trsvcid=port5', None,
        ]

        self.target.set_portals_controllers()

        mock_glob.assert_called_once_with('/sys/class/nvme-fabrics/ctl/nvme*')

        expected_calls = [
            mock.call('subsysnqn', '/sys/class/nvme-fabrics/ctl/nvme1'),
            mock.call('subsysnqn', '/sys/class/nvme-fabrics/ctl/nvme2'),
            mock.call('transport', '/sys/class/nvme-fabrics/ctl/nvme2'),
            mock.call('address', '/sys/class/nvme-fabrics/ctl/nvme2'),
            mock.call('hostnqn', '/sys/class/nvme-fabrics/ctl/nvme2'),
            mock.call('subsysnqn', '/sys/class/nvme-fabrics/ctl/nvme3'),
            mock.call('transport', '/sys/class/nvme-fabrics/ctl/nvme3'),
            mock.call('address', '/sys/class/nvme-fabrics/ctl/nvme3'),
            mock.call('hostnqn', '/sys/class/nvme-fabrics/ctl/nvme3'),
            mock.call('subsysnqn', '/sys/class/nvme-fabrics/ctl/nvme4'),
            mock.call('transport', '/sys/class/nvme-fabrics/ctl/nvme4'),
            mock.call('address', '/sys/class/nvme-fabrics/ctl/nvme4'),
            mock.call('hostnqn', '/sys/class/nvme-fabrics/ctl/nvme4'),
            mock.call('subsysnqn', '/sys/class/nvme-fabrics/ctl/nvme5'),
            mock.call('transport', '/sys/class/nvme-fabrics/ctl/nvme5'),
            mock.call('address', '/sys/class/nvme-fabrics/ctl/nvme5'),
            mock.call('hostnqn', '/sys/class/nvme-fabrics/ctl/nvme5'),
        ]
        self.assertEqual(len(expected_calls), mock_sysfs.call_count)
        mock_sysfs.assert_has_calls(expected_calls)

        # Confirm we didn't touch the first two portals
        self.assertEqual('nvme0', self.target.portals[0].controller)
        self.assertIsNone(self.target.portals[1].controller)
        self.assertEqual('nvme4', self.target.portals[2].controller)
        self.assertEqual('nvme5', self.target.portals[3].controller)

    @mock.patch('os_brick.utils.get_host_nqn', mock.Mock(return_value='nqn'))
    @mock.patch.object(nvmeof, 'sysfs_property')
    @mock.patch('glob.glob')
    def test_set_portals_controllers_short_circuit(
            self, mock_glob, mock_sysfs):
        """Stops looking once we have found names for all portals."""
        self.target.portals[0].controller = 'nvme0'
        mock_glob.return_value = ['/sys/class/nvme-fabrics/ctl/nvme0',
                                  '/sys/class/nvme-fabrics/ctl/nvme1',
                                  '/sys/class/nvme-fabrics/ctl/nvme2',
                                  '/sys/class/nvme-fabrics/ctl/nvme3']
        mock_sysfs.side_effect = [
            self.target.nqn, 'tcp', 'traddr=portal2,trsvcid=port2', 'nqn',
        ]

        self.target.set_portals_controllers()

        mock_glob.assert_called_once_with('/sys/class/nvme-fabrics/ctl/nvme*')

        expected_calls = [
            mock.call('subsysnqn', '/sys/class/nvme-fabrics/ctl/nvme1'),
            mock.call('transport', '/sys/class/nvme-fabrics/ctl/nvme1'),
            mock.call('address', '/sys/class/nvme-fabrics/ctl/nvme1'),
            mock.call('hostnqn', '/sys/class/nvme-fabrics/ctl/nvme1'),
        ]
        self.assertEqual(len(expected_calls), mock_sysfs.call_count)
        mock_sysfs.assert_has_calls(expected_calls)

        # We set the first portal with the newly found controller name
        self.assertEqual('nvme0', self.target.portals[0].controller)
        # Confirm we didn't touch second portal
        self.assertEqual('nvme1', self.target.portals[1].controller)

    @mock.patch.object(nvmeof.Target, 'present_portals',
                       new_callable=mock.PropertyMock)
    @mock.patch.object(nvmeof.Target, 'live_portals',
                       new_callable=mock.PropertyMock)
    def test_get_devices_first_live(self, mock_live, mock_present):
        """Return on first live portal with a device."""
        portal1 = mock.Mock(**{'get_device.return_value': None})
        portal2 = mock.Mock(**{'get_device.return_value': '/dev/nvme0n1'})
        portal3 = mock.Mock(**{'get_device.return_value': None})
        mock_live.return_value = [portal1, portal2]

        res = self.target.get_devices(only_live=True, get_one=True)

        self.assertListEqual(['/dev/nvme0n1'], res)

        mock_live.assert_called_once_with()
        mock_present.assert_not_called()
        portal1.get_device.assert_called_once_with()
        portal2.get_device.assert_called_once_with()
        portal3.get_device.assert_not_called()

    @mock.patch.object(nvmeof.Target, 'present_portals',
                       new_callable=mock.PropertyMock)
    @mock.patch.object(nvmeof.Target, 'live_portals',
                       new_callable=mock.PropertyMock)
    def test_get_devices_get_present(self, mock_live, mock_present):
        """Return all devices that are found."""
        portal1 = mock.Mock(**{'get_device.return_value': '/dev/nvme0n1'})
        portal2 = mock.Mock(**{'get_device.return_value': None})
        portal3 = mock.Mock(**{'get_device.return_value': '/dev/nvme1n1'})
        mock_present.return_value = [portal1, portal2, portal3]

        res = self.target.get_devices(only_live=False)

        self.assertIsInstance(res, list)
        self.assertEqual({'/dev/nvme0n1', '/dev/nvme1n1'}, set(res))

        mock_present.assert_called_once_with()
        mock_live.assert_not_called()
        portal1.get_device.assert_called_once_with()
        portal2.get_device.assert_called_once_with()
        portal3.get_device.assert_called_once_with()

    @mock.patch.object(nvmeof.Target, 'get_devices')
    def test_find_device_not_found(self, mock_get_devs):
        """Finding a devices tries up to 5 times before giving up."""
        mock_get_devs.return_value = []
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.target.find_device)

        self.assertEqual(5, mock_get_devs.call_count)
        mock_get_devs.assert_has_calls(
            5 * [mock.call(only_live=True, get_one=True)]
        )

    @mock.patch.object(nvmeof.Target, 'get_devices')
    def test_find_device_first_found(self, mock_get_devs):
        """Returns the first device found."""
        mock_get_devs.return_value = ['/dev/nvme0n1']
        res = self.target.find_device()
        mock_get_devs.assert_called_once_with(only_live=True, get_one=True)
        self.assertEqual('/dev/nvme0n1', res)

    @mock.patch.object(nvmeof.Target, '_get_nvme_devices')
    def test_get_device_path_by_initial_devices(self, mock_get_devs):
        """There's a new device since we started, return it."""
        self.target.portals[0].controller = 'nvme0'
        self.target.portals[1].controller = 'nvme1'
        mock_get_devs.return_value = ['/dev/nvme0n1', '/dev/nvme0n2',
                                      '/dev/nvme1n2', '/dev/nvme2n1']
        self.target.devices_on_start = ['/dev/nvme0n1', '/dev/nvme1n2']

        res = self.target.get_device_path_by_initial_devices()

        mock_get_devs.assert_called_once_with()
        self.assertEqual('/dev/nvme0n2', res)

    @mock.patch.object(nvmeof.Target, '_get_nvme_devices')
    def test_get_device_path_by_initial_devices_not_found(self, mock_get_devs):
        """There are now new devices since we started, return None."""
        self.target.portals[0].controller = 'nvme0'
        self.target.portals[1].controller = 'nvme1'
        mock_get_devs.return_value = ['/dev/nvme0n1', '/dev/nvme1n2']
        self.target.devices_on_start = ['/dev/nvme0n1', '/dev/nvme1n2']

        res = self.target.get_device_path_by_initial_devices()

        mock_get_devs.assert_called_once_with()
        self.assertIsNone(res)

    @mock.patch.object(nvmeof, 'blk_property')
    @mock.patch.object(nvmeof.Target, '_get_nvme_devices')
    def test_get_device_path_by_initial_devices_multiple(self, mock_get_devs,
                                                         mock_property):
        """There are multiple new devices, but they are the same volume."""
        self.target.portals[0].controller = 'nvme0'
        self.target.portals[1].controller = 'nvme1'
        mock_property.return_value = 'uuid'
        mock_get_devs.return_value = ['/dev/nvme0n1', '/dev/nvme0n2',
                                      '/dev/nvme1n1', '/dev/nvme1n2']
        self.target.devices_on_start = ['/dev/nvme0n1', '/dev/nvme1n1']

        res = self.target.get_device_path_by_initial_devices()

        mock_get_devs.assert_called_once_with()
        self.assertEqual(2, mock_property.call_count)
        mock_property.assert_has_calls([mock.call('uuid', 'nvme0n2'),
                                        mock.call('uuid', 'nvme1n2')],
                                       any_order=True)
        # The result is any of the 2 volumes, since they are the same
        self.assertIn(res, ['/dev/nvme0n2', '/dev/nvme1n2'])

    @mock.patch.object(nvmeof, 'blk_property')
    @mock.patch.object(nvmeof.Target, '_get_nvme_devices')
    def test_get_device_path_by_initial_devices_multiple_different(
            self, mock_get_devs, mock_property):
        """There are multiple new devices and they are different."""
        self.target.portals[0].controller = 'nvme0'
        self.target.portals[1].controller = 'nvme1'
        mock_property.side_effect = ('uuid1', 'uuid2')
        mock_get_devs.return_value = ['/dev/nvme0n1', '/dev/nvme0n2',
                                      '/dev/nvme1n1', '/dev/nvme1n2']
        self.target.devices_on_start = ['/dev/nvme0n1', '/dev/nvme1n1']

        res = self.target.get_device_path_by_initial_devices()

        mock_get_devs.assert_called_once_with()
        self.assertEqual(2, mock_property.call_count)
        mock_property.assert_has_calls([mock.call('uuid', 'nvme0n2'),
                                        mock.call('uuid', 'nvme1n2')],
                                       any_order=True)
        self.assertIsNone(res)


@ddt.ddt
class NVMeOFConnPropsTestCase(test_base.TestCase):
    @mock.patch.object(nvmeof.Target, 'factory')
    def test_init_old_props(self, mock_target):
        """Test init with old format connection properties."""
        conn_props = {'nqn': 'nqn_value',
                      'transport_type': 'rdma',
                      'target_portal': 'portal_value',
                      'target_port': 'port_value',
                      'volume_nguid': 'nguid',
                      'ns_id': 'nsid',
                      'host_nqn': 'host_nqn_value',
                      'qos_specs': None,
                      'access_mode': 'rw',
                      'encrypted': False,
                      'cacheable': True,
                      'discard': True}
        res = nvmeof.NVMeOFConnProps(conn_props,
                                     mock.sentinel.find_controllers)

        self.assertFalse(res.is_replicated)
        self.assertIsNone(res.qos_specs)
        self.assertFalse(res.readonly)
        self.assertFalse(res.encrypted)
        self.assertTrue(res.cacheable)
        self.assertTrue(res.discard)
        self.assertIsNone(res.alias)
        self.assertIsNone(res.cinder_volume_id)

        mock_target.assert_called_once_with(
            source_conn_props=res,
            find_controllers=mock.sentinel.find_controllers,
            volume_nguid='nguid', ns_id='nsid', host_nqn='host_nqn_value',
            portals=[('portal_value', 'port_value', 'rdma')], vol_uuid=None,
            target_nqn='nqn_value',
            # These parameters are no necessary for the Target, but for
            # convenience they are accepted and ignored.
            qos_specs=None, access_mode='rw', encrypted=False, cacheable=True,
            discard=True)

        self.assertListEqual([mock_target.return_value], res.targets)

    @ddt.data('vol_uuid', 'ns_id', 'volume_nguid')
    @mock.patch.object(nvmeof.Target, 'factory')
    def test_init_new_props_unreplicated(self, id_name, mock_target):
        """Test init with new format connection properties but no replicas."""
        conn_props = {'target_nqn': 'nqn_value',
                      id_name: 'uuid',
                      'portals': [('portal1', 'port_value', 'RoCEv2'),
                                  ('portal2', 'port_value', 'anything')],
                      'qos_specs': None,
                      'access_mode': 'rw',
                      'encrypted': False,
                      'cacheable': True,
                      'discard': True}

        res = nvmeof.NVMeOFConnProps(conn_props,
                                     mock.sentinel.find_controllers)

        self.assertFalse(res.is_replicated)
        self.assertIsNone(res.qos_specs)
        self.assertFalse(res.readonly)
        self.assertFalse(res.encrypted)
        self.assertTrue(res.cacheable)
        self.assertTrue(res.discard)
        self.assertIsNone(res.alias)
        self.assertIsNone(res.cinder_volume_id)

        kw_id_arg = {id_name: 'uuid'}
        mock_target.assert_called_once_with(
            source_conn_props=res,
            find_controllers=mock.sentinel.find_controllers,
            target_nqn='nqn_value',
            portals=[('portal1', 'port_value', 'RoCEv2'),
                     ('portal2', 'port_value', 'anything')],

            # These parameters are no necessary for the Target, but for
            # convenience they are accepted and ignored.
            qos_specs=None, access_mode='rw', encrypted=False, cacheable=True,
            discard=True,

            **kw_id_arg
        )
        self.assertListEqual([mock_target.return_value], res.targets)

    @mock.patch.object(nvmeof.Target, 'factory')
    def test_init_new_props_replicated(self, mock_target):
        """Test init with new format connection properties with replicas."""
        conn_props = {
            'vol_uuid': VOL_UUID_NO_HYPHENS,
            'alias': 'raid_alias',
            'replica_count': 2,
            'volume_replicas': [
                {'target_nqn': 'nqn1',
                 'vol_uuid': VOL_UUID1,
                 'portals': [['portal1', 'port_value', 'RoCEv2'],
                             ['portal2', 'port_value', 'anything']]},
                {'target_nqn': 'nqn2',
                 'vol_uuid': VOL_UUID2,
                 'portals': [['portal4', 'port_value', 'anything'],
                             ['portal3', 'port_value', 'RoCEv2']]}
            ],
            'qos_specs': None,
            'access_mode': 'ro',
            'encrypted': True,
            'cacheable': False,
            'discard': False
        }
        targets = [mock.Mock(), mock.Mock()]
        mock_target.side_effect = targets
        res = nvmeof.NVMeOFConnProps(conn_props,
                                     mock.sentinel.find_controllers)

        self.assertTrue(res.is_replicated)
        self.assertIsNone(res.qos_specs)
        self.assertTrue(res.readonly)
        self.assertTrue(res.encrypted)
        self.assertFalse(res.cacheable)
        self.assertFalse(res.discard)
        self.assertEqual('raid_alias', res.alias)
        self.assertEqual(VOL_UUID, res.cinder_volume_id)

        self.assertEqual(2, mock_target.call_count)
        call_1 = dict(source_conn_props=res,
                      find_controllers=mock.sentinel.find_controllers,
                      vol_uuid=VOL_UUID1, target_nqn='nqn1',
                      portals=[['portal1', 'port_value', 'RoCEv2'],
                               ['portal2', 'port_value', 'anything']])
        call_2 = dict(source_conn_props=res,
                      find_controllers=mock.sentinel.find_controllers,
                      vol_uuid=VOL_UUID2, target_nqn='nqn2',
                      portals=[['portal4', 'port_value', 'anything'],
                               ['portal3', 'port_value', 'RoCEv2']])
        mock_target.assert_has_calls([mock.call(**call_1),
                                      mock.call(**call_2)])
        self.assertListEqual(targets, res.targets)

    @mock.patch.object(nvmeof.Target, 'factory')
    def test_get_devices(self, mock_target):
        """Connector get devices gets devices from all its portals."""
        conn_props = {
            'vol_uuid': VOL_UUID,
            'alias': 'raid_alias',
            'replica_count': 2,
            'volume_replicas': [
                {'target_nqn': 'nqn1',
                 'vol_uuid': VOL_UUID1,
                 'portals': [['portal1', 'port_value', 'RoCEv2'],
                             ['portal2', 'port_value', 'anything']]},
                {'target_nqn': VOL_UUID2,
                 'vol_uuid': 'uuid2',
                 'portals': [['portal4', 'port_value', 'anything'],
                             ['portal3', 'port_value', 'RoCEv2']]}
            ],
        }
        targets = [mock.Mock(), mock.Mock()]
        targets[0].get_devices.return_value = []
        targets[1].get_devices.return_value = ['/dev/nvme0n1', '/dev/nvme0n2']
        mock_target.side_effect = targets
        conn_props_instance = nvmeof.NVMeOFConnProps(conn_props)

        res = conn_props_instance.get_devices(mock.sentinel.only_live)
        self.assertListEqual(['/dev/nvme0n1', '/dev/nvme0n2'], res)

    @mock.patch.object(nvmeof.Target, 'factory')
    def test_from_dictionary_parameter(self, mock_target):
        """Decorator converts dict into connection properties instance."""
        class Connector(object):
            @nvmeof.NVMeOFConnProps.from_dictionary_parameter
            def connect_volume(my_self, connection_properties):
                self.assertIsInstance(connection_properties,
                                      nvmeof.NVMeOFConnProps)
                return 'result'

        conn = Connector()

        conn_props = {'target_nqn': 'nqn_value', 'vol_uuid': 'uuid',
                      'portals': [('portal1', 'port_value', 'RoCEv2'),
                                  ('portal2', 'port_value', 'anything')]}
        res = conn.connect_volume(conn_props)

        self.assertEqual('result', res)


@ddt.ddt
class NVMeOFConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for NVMe initiator class."""

    def setUp(self):
        super(NVMeOFConnectorTestCase, self).setUp()
        self.connector = nvmeof.NVMeOFConnector(None,
                                                execute=self.fake_execute,
                                                use_multipath=False)
        self.conn_props_dict = {'target_nqn': 'nqn_value',
                                'vol_uuid': VOL_UUID,
                                'portals': [('portal1', 'port1', 'RoCEv2'),
                                            ('portal2', 'port2', 'tcp'),
                                            ('portal3', 'port3', 'rdma')]}
        self.conn_props = nvmeof.NVMeOFConnProps(self.conn_props_dict)
        self.patch('oslo_concurrency.lockutils.external_lock')

    @mock.patch.object(priv_rootwrap, 'custom_execute', autospec=True)
    def test_nvme_present(self, mock_execute):
        nvme_present = self.connector.nvme_present()
        self.assertTrue(nvme_present)

    @ddt.data(OSError(2, 'FileNotFoundError'), Exception())
    @mock.patch('os_brick.initiator.connectors.nvmeof.LOG')
    @mock.patch.object(priv_rootwrap, 'custom_execute', autospec=True)
    def test_nvme_present_exception(self, exc, mock_execute, mock_log):
        mock_execute.side_effect = exc
        nvme_present = self.connector.nvme_present()
        log = mock_log.debug if isinstance(exc, OSError) else mock_log.warning
        log.assert_called_once()
        self.assertFalse(nvme_present)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test_get_sysuuid_without_newline(self, mock_execute):
        mock_execute.return_value = (
            "9126E942-396D-11E7-B0B7-A81E84C186D1\n", "")
        uuid = self.connector._get_host_uuid()
        expected_uuid = "9126E942-396D-11E7-B0B7-A81E84C186D1"
        self.assertEqual(expected_uuid, uuid)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute', autospec=True)
    def test_get_sysuuid_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        uuid = self.connector._get_host_uuid()
        self.assertIsNone(uuid)

    @mock.patch.object(utils, 'get_nvme_host_id',
                       return_value=SYS_UUID)
    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported',
                       return_value=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, 'nvme_present',
                       return_value=True)
    @mock.patch.object(utils, 'get_host_nqn',
                       return_value='fakenqn')
    @mock.patch.object(priv_nvmeof, 'get_system_uuid',
                       return_value=None)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid',
                       return_value=None)
    def test_get_connector_properties_without_sysuuid(self, mock_host_uuid,
                                                      mock_sysuuid, mock_nqn,
                                                      mock_nvme_present,
                                                      mock_nat_mpath_support,
                                                      mock_get_host_id):
        props = self.connector.get_connector_properties('sudo')
        expected_props = {'nqn': 'fakenqn',
                          'nvme_native_multipath': False,
                          'nvme_hostid': SYS_UUID}
        self.assertEqual(expected_props, props)
        mock_get_host_id.assert_called_once_with(None)

    @mock.patch.object(utils, 'get_nvme_host_id',
                       return_value=SYS_UUID)
    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported',
                       return_value=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, 'nvme_present')
    @mock.patch.object(utils, 'get_host_nqn', autospec=True)
    @mock.patch.object(priv_nvmeof, 'get_system_uuid',
                       autospec=True)
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_host_uuid', autospec=True)
    def test_get_connector_properties_with_sysuuid(self, mock_host_uuid,
                                                   mock_sysuuid, mock_nqn,
                                                   mock_nvme_present,
                                                   mock_native_mpath_support,
                                                   mock_get_host_id):
        mock_host_uuid.return_value = HOST_UUID
        mock_sysuuid.return_value = SYS_UUID
        mock_nqn.return_value = HOST_NQN
        mock_nvme_present.return_value = True
        props = self.connector.get_connector_properties('sudo')
        expected_props = {"system uuid": SYS_UUID, "nqn": HOST_NQN,
                          "uuid": HOST_UUID, 'nvme_native_multipath': False,
                          'nvme_hostid': SYS_UUID}
        self.assertEqual(expected_props, props)
        mock_get_host_id.assert_called_once_with(SYS_UUID)

    def test_get_volume_paths_device_info(self):
        """Device info path has highest priority."""
        dev_path = '/dev/nvme0n1'
        device_info = {'type': 'block', 'path': dev_path}
        conn_props = connection_properties.copy()
        conn_props['device_path'] = 'lower_priority'
        conn_props = nvmeof.NVMeOFConnProps(conn_props)
        res = self.connector.get_volume_paths(conn_props, device_info)
        self.assertEqual([dev_path], res)

    def test_get_volume_paths_nova_conn_props(self):
        """Second highest priority is device_path nova puts in conn props."""
        dev_path = '/dev/nvme0n1'
        device_info = None
        conn_props = connection_properties.copy()
        conn_props['device_path'] = dev_path
        conn_props = nvmeof.NVMeOFConnProps(conn_props)
        res = self.connector.get_volume_paths(conn_props, device_info)
        self.assertEqual([dev_path], res)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_raid_device')
    @mock.patch.object(nvmeof.NVMeOFConnProps, 'get_devices')
    def test_get_volume_paths_unreplicated(self, mock_get_devs, mock_is_raid):
        """Search for device from unreplicated connection properties."""
        mock_get_devs.return_value = ['/dev/nvme0n1']
        conn_props = nvmeof.NVMeOFConnProps(volume_replicas[0])

        res = self.connector.get_volume_paths(conn_props, None)
        self.assertEqual(mock_get_devs.return_value, res)
        mock_is_raid.assert_not_called()
        mock_get_devs.assert_called_once_with()

    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_raid_device')
    @mock.patch.object(nvmeof.NVMeOFConnProps, 'get_devices')
    def test_get_volume_paths_single_replica(self, mock_get_devs,
                                             mock_is_raid):
        """Search for device from replicated conn props with 1 replica."""
        dev_path = '/dev/nvme1n1'
        mock_get_devs.return_value = [dev_path]
        target_props = volume_replicas[0]
        connection_properties = {
            'vol_uuid': VOL_UUID,
            'alias': 'fakealias',
            'volume_replicas': [target_props],
            'replica_count': 1
        }
        conn_props = nvmeof.NVMeOFConnProps(connection_properties)
        res = self.connector.get_volume_paths(conn_props, None)
        self.assertEqual(['/dev/md/fakealias'], res)
        mock_is_raid.assert_called_once_with(dev_path)
        mock_get_devs.assert_called_once_with()

    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_raid_device')
    @mock.patch.object(nvmeof.NVMeOFConnProps, 'get_devices')
    def test_get_volume_paths_single_replica_not_replicated(
            self, mock_get_devs, mock_is_raid):
        """Search for device from unreplicated conn props with 1 replica."""
        mock_is_raid.return_value = False
        dev_path = '/dev/nvme1n1'
        mock_get_devs.return_value = [dev_path]
        target_props = volume_replicas[0]
        connection_properties = {
            'vol_uuid': VOL_UUID,
            'alias': 'fakealias',
            'volume_replicas': [target_props],
            'replica_count': 1
        }
        conn_props = nvmeof.NVMeOFConnProps(connection_properties)

        res = self.connector.get_volume_paths(conn_props, None)
        self.assertEqual([dev_path], res)
        mock_is_raid.assert_called_once_with(dev_path)
        mock_get_devs.assert_called_once_with()

    def test_get_volume_paths_replicated(self):
        """Search for device from replicated conn props with >1 replica."""
        conn_props = nvmeof.NVMeOFConnProps(connection_properties)
        self.assertEqual(['/dev/md/fakealias'],
                         self.connector.get_volume_paths(conn_props))

    @mock.patch.object(nvmeof.Target, 'set_portals_controllers', mock.Mock())
    @mock.patch.object(nvmeof.NVMeOFConnector, '_try_disconnect_all')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target')
    def test_connect_volume_not_replicated(
            self, mock_connect_target, mock_disconnect):
        """Single vol attach."""
        connection_properties = volume_replicas[0].copy()
        mock_connect_target.return_value = '/dev/nvme0n1'
        self.assertEqual({'type': 'block', 'path': '/dev/nvme0n1'},
                         self.connector.connect_volume(connection_properties))
        mock_connect_target.assert_called_with(mock.ANY)
        self.assertIsInstance(mock_connect_target.call_args[0][0],
                              nvmeof.Target)
        mock_disconnect.assert_not_called()

    @mock.patch.object(nvmeof.Target, 'set_portals_controllers', mock.Mock())
    @mock.patch.object(nvmeof.NVMeOFConnector, '_try_disconnect_all')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target')
    def test_connect_volume_not_replicated_fails(
            self, mock_connect_target, mock_disconnect):
        """Single vol attach fails and disconnects on failure."""
        connection_properties = volume_replicas[0].copy()
        mock_connect_target.side_effect = exception.VolumeDeviceNotFound,
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector.connect_volume,
                          connection_properties)
        mock_connect_target.assert_called_with(mock.ANY)
        self.assertIsInstance(mock_connect_target.call_args[0][0],
                              nvmeof.Target)
        mock_disconnect.assert_called_with(mock.ANY)
        self.assertIsInstance(mock_disconnect.call_args[0][0],
                              nvmeof.NVMeOFConnProps)

    @mock.patch.object(nvmeof.Target, 'set_portals_controllers', mock.Mock())
    @mock.patch.object(nvmeof.NVMeOFConnector, '_try_disconnect_all')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_volume_replicated')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target')
    def test_connect_volume_replicated(
            self, mock_connect_target, mock_replicated_volume,
            mock_disconnect):
        mock_replicated_volume.return_value = '/dev/md/md1'

        actual = self.connector.connect_volume(connection_properties)

        expected = {'type': 'block', 'path': '/dev/md/md1'}
        self.assertEqual(expected, actual)

        mock_replicated_volume.assert_called_once_with(mock.ANY)
        self.assertIsInstance(mock_replicated_volume.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_connect_target.assert_not_called()
        mock_disconnect.assert_not_called()

    @mock.patch.object(nvmeof.Target, 'set_portals_controllers', mock.Mock())
    @mock.patch.object(nvmeof.NVMeOFConnector, '_try_disconnect_all')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_replicated_volume')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target')
    def test_connect_volume_replicated_exception(
            self, mock_connect_target, mock_replicated_volume,
            mock_disconnect):
        mock_connect_target.side_effect = Exception()
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector.connect_volume, connection_properties)
        mock_disconnect.assert_called_with(mock.ANY)
        self.assertIsInstance(mock_disconnect.call_args[0][0],
                              nvmeof.NVMeOFConnProps)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_try_disconnect_all')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths')
    @mock.patch('os.path.exists', return_value=True)
    def test_disconnect_volume_path_not_found(
            self, mock_exists, mock_get_paths, mock_disconnect):
        """Disconnect can't find device path from conn props and dev info."""
        mock_get_paths.return_value = []
        res = self.connector.disconnect_volume(connection_properties,
                                               mock.sentinel.device_info)
        self.assertIsNone(res)
        mock_get_paths.assert_called_once_with(mock.ANY,
                                               mock.sentinel.device_info)
        self.assertIsInstance(mock_get_paths.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_exists.assert_not_called()
        mock_disconnect.assert_not_called()

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths')
    @mock.patch('os.path.exists', return_value=True)
    def test_disconnect_volume_path_doesnt_exist(
            self, mock_exists, mock_get_paths):
        """Disconnect path doesn't exist"""
        dev_path = '/dev/nvme0n1'
        mock_get_paths.return_value = [dev_path]
        mock_exists.return_value = False
        res = self.connector.disconnect_volume(connection_properties,
                                               mock.sentinel.device_info)
        self.assertIsNone(res)
        mock_get_paths.assert_called_once_with(mock.ANY,
                                               mock.sentinel.device_info)
        self.assertIsInstance(mock_get_paths.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_exists.assert_called_once_with(dev_path)

    @mock.patch.object(nvmeof.Target, 'set_portals_controllers', mock.Mock())
    @mock.patch('os_brick.initiator.linuxscsi.LinuxSCSI.flush_device_io')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'end_raid')
    @mock.patch('os.path.exists', return_value=True)
    def test_disconnect_volume_unreplicated(
            self, mock_exists, mock_end_raid, mock_get_paths, mock_flush):
        """Disconnect a single device."""
        dev_path = '/dev/nvme0n1'
        mock_get_paths.return_value = [dev_path]
        self.connector.disconnect_volume(connection_properties,
                                         mock.sentinel.device_info,
                                         ignore_errors=True)
        mock_get_paths.assert_called_once_with(mock.ANY,
                                               mock.sentinel.device_info)
        self.assertIsInstance(mock_get_paths.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_exists.assert_called_once_with(dev_path)
        mock_end_raid.assert_not_called()
        mock_flush.assert_called_with(dev_path)

    @mock.patch.object(nvmeof.Target, 'set_portals_controllers', mock.Mock())
    @mock.patch('os_brick.initiator.linuxscsi.LinuxSCSI.flush_device_io')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'end_raid')
    @mock.patch('os.path.exists', return_value=True)
    def test_disconnect_volume_replicated(
            self, mock_exists, mock_end_raid, mock_get_paths, mock_flush):
        """Disconnect a raid."""
        raid_path = '/dev/md/md1'
        mock_get_paths.return_value = [raid_path]
        self.connector.disconnect_volume(connection_properties,
                                         mock.sentinel.device_info,
                                         ignore_errors=True)
        mock_get_paths.assert_called_once_with(mock.ANY,
                                               mock.sentinel.device_info)
        self.assertIsInstance(mock_get_paths.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_exists.assert_called_once_with(raid_path)
        mock_end_raid.assert_called_with(raid_path)
        mock_flush.assert_not_called()

    def test__get_sizes_from_lba(self):
        """Get nsze and new size using nvme LBA information."""
        nsze = 6291456
        ns_data = {"nsze": nsze, "ncap": nsze, "nuse": nsze,
                   "lbafs": [{"ms": 0, "ds": 9, "rp": 0}]}
        res_nsze, res_size = self.connector._get_sizes_from_lba(ns_data)
        self.assertEqual(nsze, res_nsze)
        self.assertEqual(nsze * 1 << 9, res_size)

    @ddt.data([{"ms": 0, "ds": 6, "rp": 0}],
              [{"ms": 0, "ds": 9, "rp": 0}, {"ms": 0, "ds": 9, "rp": 0}])
    def test__get_sizes_from_lba_error(self, lbafs):
        """Incorrect data returned in LBA information."""
        nsze = 6291456
        ns_data = {"nsze": nsze, "ncap": nsze, "nuse": nsze, "lbafs": lbafs}
        res_nsze, res_size = self.connector._get_sizes_from_lba(ns_data)
        self.assertIsNone(res_nsze)
        self.assertIsNone(res_size)

    @mock.patch.object(nvmeof, 'blk_property')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_sizes_from_lba')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths')
    @mock.patch('os_brick.utils.get_device_size')
    def test_extend_volume_unreplicated(self, mock_device_size, mock_paths,
                                        mock_exec, mock_lba, mock_property):
        """Uses nvme to get expected size and waits until sysfs shows it."""
        new_size = 3221225472
        new_nsze = int(new_size / 512)  # nsze is size / block-size
        old_nsze = int(new_nsze / 2)
        dev_path = '/dev/nvme0n1'

        mock_paths.return_value = [dev_path]
        stdout = '{"data": "jsondata"}'
        mock_exec.return_value = (stdout, '')
        mock_lba.return_value = (new_nsze, new_size)
        # Simulate a delay before the new value is present in sysfs
        mock_property.side_effect = (str(old_nsze), str(new_nsze))

        self.assertEqual(new_size,
                         self.connector.extend_volume(connection_properties))

        mock_paths.assert_called_with(mock.ANY)
        self.assertIsInstance(mock_paths.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_exec.assert_called_once_with(
            'nvme', 'id-ns', '-ojson', dev_path,
            run_as_root=True, root_helper=self.connector._root_helper)
        mock_lba.assert_called_once_with({"data": "jsondata"})
        self.assertEqual(2, mock_property.call_count)
        mock_property.assert_has_calls([mock.call('size', 'nvme0n1'),
                                        mock.call('size', 'nvme0n1')])
        mock_device_size.assert_not_called()

    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof, 'blk_property')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_sizes_from_lba')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths')
    @mock.patch('os_brick.utils.get_device_size')
    def test_extend_volume_unreplicated_nvme_fails(
            self, mock_device_size, mock_paths, mock_exec, mock_lba,
            mock_property, mock_rescan):
        """nvme command fails, so it rescans, waits, and reads size."""
        dev_path = '/dev/nvme0n1'
        mock_device_size.return_value = 100
        mock_paths.return_value = [dev_path]
        mock_exec.side_effect = putils.ProcessExecutionError()

        self.assertEqual(100,
                         self.connector.extend_volume(connection_properties))

        mock_paths.assert_called_with(mock.ANY)
        self.assertIsInstance(mock_paths.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_exec.assert_called_once_with(
            'nvme', 'id-ns', '-ojson', dev_path,
            run_as_root=True, root_helper=self.connector._root_helper)
        mock_lba.assert_not_called()
        mock_property.assert_not_called()
        mock_rescan.assert_called_once_with('nvme0')
        mock_device_size.assert_called_with(self.connector, '/dev/nvme0n1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_volume_paths')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    @mock.patch('os_brick.utils.get_device_size')
    def test_extend_volume_replicated(
            self, mock_device_size, mock_mdadm, mock_paths):
        device_path = '/dev/md/' + connection_properties['alias']
        mock_paths.return_value = [device_path]
        mock_device_size.return_value = 100
        self.assertEqual(
            100,
            self.connector.extend_volume(connection_properties))
        mock_paths.assert_called_once_with(mock.ANY)
        self.assertIsInstance(mock_paths.call_args[0][0],
                              nvmeof.NVMeOFConnProps)
        mock_mdadm.assert_called_with(
            ('mdadm', '--grow', '--size', 'max', device_path))
        mock_device_size.assert_called_with(self.connector, device_path)

    @mock.patch.object(nvmeof.Target, 'find_device')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.Portal, 'state', new_callable=mock.PropertyMock)
    def test__connect_target_with_connected_device(
            self, mock_state, mock_rescan, mock_cli, mock_set_ctrls,
            mock_find_dev):
        """Test connect target when there's a connection to the subsystem."""
        self.conn_props.targets[0].portals[-1].controller = 'nvme0'
        mock_state.side_effect = ('connecting', None, 'live')
        dev_path = '/dev/nvme0n1'
        mock_find_dev.return_value = dev_path

        res = self.connector._connect_target(self.conn_props.targets[0])
        self.assertEqual(dev_path, res)

        self.assertEqual(3, mock_state.call_count)
        mock_state.assert_has_calls(3 * [mock.call()])
        mock_rescan.assert_called_once_with('nvme0')
        mock_set_ctrls.assert_called_once_with()
        mock_find_dev.assert_called_once_with()
        mock_cli.assert_not_called()

    @ddt.data(True, False)
    @mock.patch.object(nvmeof.Target, 'find_device')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_do_multipath')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.Portal, 'state', new_callable=mock.PropertyMock)
    def test__connect_target_not_found(self, do_multipath, mock_state,
                                       mock_rescan, mock_cli, doing_multipath,
                                       mock_set_ctrls, mock_find_dev):
        """Test connect target fails to find device after connecting."""
        self.conn_props.targets[0].portals[-1].controller = 'nvme0'
        doing_multipath.return_value = do_multipath
        retries = 3
        mock_state.side_effect = retries * ['connecting', None, 'live']

        mock_find_dev.side_effect = exception.VolumeDeviceNotFound()

        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_target,
                          self.conn_props.targets[0])

        self.assertEqual(retries * 3, mock_state.call_count)
        mock_state.assert_has_calls(retries * 3 * [mock.call()])
        self.assertEqual(retries, mock_rescan.call_count)
        mock_rescan.assert_has_calls(retries * [mock.call('nvme0')])

        self.assertEqual(retries, mock_set_ctrls.call_count)
        mock_set_ctrls.assert_has_calls(retries * [mock.call()])
        self.assertEqual(retries, mock_find_dev.call_count)
        mock_find_dev.assert_has_calls(retries * [mock.call()])
        if do_multipath:
            self.assertEqual(retries, mock_cli.call_count)
            mock_cli.assert_has_calls(
                retries * [mock.call(['connect', '-a', 'portal2', '-s',
                                      'port2', '-t', 'tcp', '-n', 'nqn_value',
                                      '-Q', '128', '-l', '-1'])])
        else:
            mock_cli.assert_not_called()

    @mock.patch.object(nvmeof.Target, 'find_device')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.Portal, 'state', new_callable=mock.PropertyMock)
    def test__connect_target_portals_down(
            self, mock_state, mock_rescan, mock_cli, mock_set_ctrls,
            mock_find_dev):
        """Test connect target has all portal connections down."""
        retries = 3
        mock_state.side_effect = retries * 3 * ['connecting']

        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_target,
                          self.conn_props.targets[0])

        self.assertEqual(retries * 3, mock_state.call_count)
        mock_state.assert_has_calls(retries * 3 * [mock.call()])
        mock_rescan.assert_not_called()
        mock_set_ctrls.assert_not_called()
        mock_find_dev.assert_not_called()
        mock_cli.assert_not_called()

    @mock.patch.object(nvmeof.LOG, 'error')
    @mock.patch.object(nvmeof.Target, 'find_device')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.Portal, 'state', new_callable=mock.PropertyMock)
    def test__connect_target_no_portals_connect(
            self, mock_state, mock_rescan, mock_cli, mock_set_ctrls,
            mock_find_dev, mock_log):
        """Test connect target when fails to connect to any portal."""
        retries = 3
        mock_state.side_effect = retries * ['connecting', 'connecting', None]
        mock_cli.side_effect = putils.ProcessExecutionError()

        target = self.conn_props.targets[0]

        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_target, target)

        self.assertEqual(retries, mock_log.call_count)
        self.assertEqual(retries * 3, mock_state.call_count)
        mock_state.assert_has_calls(retries * 3 * [mock.call()])
        mock_rescan.assert_not_called()
        mock_set_ctrls.assert_not_called()
        mock_find_dev.assert_not_called()
        self.assertEqual(3, mock_cli.call_count)
        portal = target.portals[-1]
        mock_cli.assert_has_calls(
            retries * [mock.call(['connect', '-a', portal.address,
                                  '-s', portal.port, '-t', portal.transport,
                                  '-n', target.nqn, '-Q', '128', '-l', '-1'])])

    @mock.patch.object(nvmeof.Target, 'find_device')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.Portal, 'state', new_callable=mock.PropertyMock)
    def test__connect_target_new_device_path(
            self, mock_state, mock_rescan, mock_cli, mock_set_ctrls,
            mock_find_dev):
        """Test connect when we do a new connection and find the device."""
        mock_state.side_effect = ['connecting', 'connecting', None]
        dev_path = '/dev/nvme0n1'
        mock_find_dev.return_value = dev_path

        target = self.conn_props.targets[0]
        target.host_nqn = 'host_nqn'

        res = self.connector._connect_target(target)
        self.assertEqual(dev_path, res)

        self.assertEqual(3, mock_state.call_count)
        mock_state.assert_has_calls(3 * [mock.call()])
        mock_rescan.assert_not_called()
        mock_set_ctrls.assert_called_once_with()
        mock_find_dev.assert_called_once_with()

        portal = target.portals[-1]
        mock_cli.assert_called_once_with([
            'connect', '-a', portal.address, '-s', portal.port, '-t',
            portal.transport, '-n', target.nqn, '-Q', '128', '-l', '-1',
            '-q', 'host_nqn'])

    @mock.patch.object(nvmeof.NVMeOFConnector, '_do_multipath',
                       mock.Mock(return_value=True))
    @mock.patch.object(nvmeof.Target, 'find_device')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.Portal, 'state', new_callable=mock.PropertyMock)
    def test__connect_target_multipath(
            self, mock_state, mock_rescan, mock_cli, mock_set_ctrls,
            mock_find_dev):
        """Test connect when we do a new connection and find the device."""
        target = self.conn_props.targets[0]

        mock_state.side_effect = [None, None, None]
        dev_path = '/dev/nvme0n1'
        mock_find_dev.return_value = dev_path

        res = self.connector._connect_target(target)
        self.assertEqual(dev_path, res)

        self.assertEqual(3, mock_state.call_count)
        mock_state.assert_has_calls(3 * [mock.call()])
        mock_rescan.assert_not_called()
        mock_set_ctrls.assert_called_once_with()
        mock_find_dev.assert_called_once_with()

        self.assertEqual(len(target.portals), mock_cli.call_count)
        mock_cli.assert_has_calls(
            [mock.call(['connect', '-a', portal.address,
                        '-s', portal.port, '-t', portal.transport,
                        '-n', target.nqn, '-Q', '128', '-l', '-1'])
             for portal in target.portals])

    @ddt.data(70, errno.EALREADY)
    @mock.patch.object(nvmeof.LOG, 'warning')
    @mock.patch.object(nvmeof.Target, 'find_device')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'rescan')
    @mock.patch.object(nvmeof.Portal, 'state', new_callable=mock.PropertyMock)
    def test__connect_target_race(
            self, exit_code, mock_state, mock_rescan, mock_cli,
            mock_set_ctrls, mock_find_dev, mock_log):
        """Treat race condition with sysadmin as success."""
        mock_state.side_effect = ['connecting', 'connecting', None]
        dev_path = '/dev/nvme0n1'
        mock_find_dev.return_value = dev_path
        mock_cli.side_effect = putils.ProcessExecutionError(
            exit_code=exit_code)

        target = self.conn_props.targets[0]

        res = self.connector._connect_target(target)
        self.assertEqual(dev_path, res)

        self.assertEqual(3, mock_state.call_count)
        mock_state.assert_has_calls(3 * [mock.call()])
        mock_rescan.assert_not_called()
        mock_set_ctrls.assert_called_once_with()
        mock_find_dev.assert_called_once_with()

        portal = target.portals[-1]
        mock_cli.assert_called_once_with([
            'connect', '-a', portal.address, '-s', portal.port, '-t',
            portal.transport, '-n', target.nqn, '-Q', '128', '-l', '-1'])
        self.assertEqual(1, mock_log.call_count)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_and_assemble_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_device_in_raid')
    def test_handle_replicated_volume_existing(
            self, mock_device_raid, mock_stop_assemble_raid):
        mock_device_raid.return_value = True
        conn_props = nvmeof.NVMeOFConnProps(connection_properties)
        result = self.connector._handle_replicated_volume(
            ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'], conn_props)
        self.assertEqual('/dev/md/fakealias', result)
        mock_device_raid.assert_called_with('/dev/nvme1n1')
        mock_stop_assemble_raid.assert_called_with(
            ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
            '/dev/md/fakealias', False)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_device_in_raid')
    def test_handle_replicated_volume_not_found(self, mock_device_raid):
        mock_device_raid.return_value = False
        conn_props = nvmeof.NVMeOFConnProps(connection_properties)
        conn_props.replica_count = 4
        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._handle_replicated_volume,
                          ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
                          conn_props)
        mock_device_raid.assert_any_call('/dev/nvme1n1')
        mock_device_raid.assert_any_call('/dev/nvme1n2')
        mock_device_raid.assert_any_call('/dev/nvme1n3')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'create_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_is_device_in_raid')
    def test_handle_replicated_volume_new(
            self, mock_device_raid, mock_create_raid):
        conn_props = nvmeof.NVMeOFConnProps(connection_properties)
        mock_device_raid.return_value = False
        res = self.connector._handle_replicated_volume(
            ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'], conn_props)
        self.assertEqual('/dev/md/fakealias', res)
        mock_device_raid.assert_any_call('/dev/nvme1n1')
        mock_device_raid.assert_any_call('/dev/nvme1n2')
        mock_device_raid.assert_any_call('/dev/nvme1n3')
        mock_create_raid.assert_called_with(
            ['/dev/nvme1n1', '/dev/nvme1n2', '/dev/nvme1n3'],
            '1', 'fakealias', 'fakealias', False)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'ks_readlink')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_md_name')
    def test_stop_and_assemble_raid_existing_simple(
            self, mock_md_name, mock_readlink):
        mock_readlink.return_value = ''
        mock_md_name.return_value = 'mdalias'
        self.assertIsNone(self.connector.stop_and_assemble_raid(
            ['/dev/sda'], '/dev/md/mdalias', False))
        mock_md_name.assert_called_with('sda')
        mock_readlink.assert_called_with('/dev/md/mdalias')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'ks_readlink')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_md_name')
    def test_stop_and_assemble_raid(
            self, mock_md_name, mock_readlink):
        mock_readlink.return_value = '/dev/md/mdalias'
        mock_md_name.return_value = 'mdalias'
        self.assertIsNone(self.connector.stop_and_assemble_raid(
            ['/dev/sda'], '/dev/md/mdalias', False))
        mock_md_name.assert_called_with('sda')
        mock_readlink.assert_called_with('/dev/md/mdalias')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'assemble_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'ks_readlink')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'get_md_name')
    def test_stop_and_assemble_raid_err(self, mock_md_name, mock_readlink,
                                        mock_assemble):
        mock_readlink.return_value = '/dev/md/mdalias'
        mock_md_name.return_value = 'dummy'
        mock_assemble.side_effect = Exception()
        self.assertIsNone(self.connector.stop_and_assemble_raid(
            ['/dev/sda'], '/dev/md/mdalias', False))
        mock_md_name.assert_called_with('sda')
        mock_readlink.assert_called_with('/dev/md/mdalias')
        mock_assemble.assert_called_with(
            ['/dev/sda'], '/dev/md/mdalias', False)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_assemble_raid_simple(self, mock_run_mdadm):
        self.assertEqual(self.connector.assemble_raid(
            ['/dev/sda'], '/dev/md/md1', True), True)
        mock_run_mdadm.assert_called_with(
            ['mdadm', '--assemble', '--run', '/dev/md/md1', '-o', '/dev/sda'],
            True)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_assemble_raid_simple_err(self, mock_run_mdadm):
        mock_run_mdadm.side_effect = putils.ProcessExecutionError()
        self.assertRaises(putils.ProcessExecutionError,
                          self.connector.assemble_raid,
                          ['/dev/sda'], '/dev/md/md1', True)
        mock_run_mdadm.assert_called_with(
            ['mdadm', '--assemble', '--run', '/dev/md/md1', '-o', '/dev/sda'],
            True)

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_create_raid_cmd_simple(self, mock_run_mdadm, mock_os):
        mock_os.return_value = True
        self.assertIsNone(self.connector.create_raid(
            ['/dev/sda'], '1', 'md1', 'name', True))
        mock_run_mdadm.assert_called_with(
            ['mdadm', '-C', '-o', 'md1', '-R', '-N', 'name', '--level', '1',
             '--raid-devices=1', '--bitmap=internal', '--homehost=any',
             '--failfast', '--assume-clean', '/dev/sda'])
        mock_os.assert_called_with('/dev/md/name')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'is_raid_exists')
    def test_end_raid_simple(self, mock_raid_exists, mock_stop_raid):
        mock_raid_exists.return_value = True
        mock_stop_raid.return_value = False
        self.assertIsNone(self.connector.end_raid('/dev/md/md1'))
        mock_raid_exists.assert_called_with('/dev/md/md1')
        mock_stop_raid.assert_called_with('/dev/md/md1', True)

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'is_raid_exists')
    def test_end_raid(self, mock_raid_exists, mock_stop_raid, mock_os):
        mock_raid_exists.return_value = True
        mock_stop_raid.return_value = False
        mock_os.return_value = True
        self.assertIsNone(self.connector.end_raid('/dev/md/md1'))
        mock_raid_exists.assert_called_with('/dev/md/md1')
        mock_stop_raid.assert_called_with('/dev/md/md1', True)
        mock_os.assert_called_with('/dev/md/md1')

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'stop_raid')
    @mock.patch.object(nvmeof.NVMeOFConnector, 'is_raid_exists')
    def test_end_raid_err(self, mock_raid_exists, mock_stop_raid, mock_os):
        mock_raid_exists.return_value = True
        mock_stop_raid.side_effect = Exception()
        mock_os.return_value = True
        self.assertIsNone(self.connector.end_raid('/dev/md/md1'))
        mock_raid_exists.assert_called_with('/dev/md/md1')
        mock_stop_raid.assert_called_with('/dev/md/md1', True)
        mock_os.assert_called_with('/dev/md/md1')

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_stop_raid_simple(self, mock_run_mdadm):
        mock_run_mdadm.return_value = 'mdadm output'
        self.assertEqual(self.connector.stop_raid('/dev/md/md1', True),
                         'mdadm output')
        mock_run_mdadm.assert_called_with(['mdadm', '--stop', '/dev/md/md1'],
                                          True)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_mdadm')
    def test_remove_raid_simple(self, mock_run_mdadm):
        self.assertIsNone(self.connector.remove_raid('/dev/md/md1'))
        mock_run_mdadm.assert_called_with(['mdadm', '--remove', '/dev/md/md1'])

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    def test_rescan(self, mock_run_nvme_cli):
        """Test successful nvme rescan."""
        mock_run_nvme_cli.return_value = None
        result = self.connector.rescan('nvme1')
        self.assertIsNone(result)
        nvme_command = ('ns-rescan', NVME_DEVICE_PATH)
        mock_run_nvme_cli.assert_called_with(nvme_command)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'run_nvme_cli')
    def test_rescan_err(self, mock_run_nvme_cli):
        """Test failure on nvme rescan subprocess execution."""
        mock_run_nvme_cli.side_effect = Exception()
        self.assertRaises(exception.CommandExecutionFailed,
                          self.connector.rescan, 'nvme1')
        nvme_command = ('ns-rescan', NVME_DEVICE_PATH)
        mock_run_nvme_cli.assert_called_with(nvme_command)

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_raid_exists_not(self, mock_execute):
        mock_execute.return_value = (VOL_UUID + "\n", "")
        result = self.connector.is_raid_exists(NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--detail', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_raid_exists(self, mock_execute):
        mock_execute.return_value = (NVME_DEVICE_PATH + ':' + "\n", "")
        result = self.connector.is_raid_exists(NVME_DEVICE_PATH)
        self.assertEqual(True, result)
        cmd = ['mdadm', '--detail', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_raid_exists_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError
        result = self.connector.is_raid_exists(NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--detail', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    def test_get_md_name(self):
        mock_open = mock.mock_open(read_data=md_stat_contents)
        with mock.patch('builtins.open', mock_open):
            result = self.connector.get_md_name(os.path.basename(NVME_NS_PATH))
        self.assertEqual('md0', result)
        mock_open.assert_called_once_with('/proc/mdstat', 'r')
        mock_fd = mock_open.return_value.__enter__.return_value
        mock_fd.__iter__.assert_called_once_with()

    @mock.patch.object(builtins, 'open', side_effect=Exception)
    def test_get_md_name_err(self, mock_open):
        result = self.connector.get_md_name(os.path.basename(NVME_NS_PATH))
        self.assertIsNone(result)
        mock_open.assert_called_once_with('/proc/mdstat', 'r')

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_device_in_raid(self, mock_execute):
        mock_execute.return_value = (NVME_DEVICE_PATH + ':' + "\n", "")
        result = self.connector._is_device_in_raid(NVME_DEVICE_PATH)
        self.assertEqual(True, result)
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_device_in_raid_not_found(self, mock_execute):
        mock_execute.return_value = (VOL_UUID + "\n", "")
        result = self.connector._is_device_in_raid(NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_is_device_in_raid_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        result = self.connector._is_device_in_raid(NVME_DEVICE_PATH)
        self.assertEqual(False, result)
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_run_mdadm(self, mock_execute):
        mock_execute.return_value = (VOL_UUID + "\n", "")
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        result = self.connector.run_mdadm(cmd)
        self.assertEqual(VOL_UUID, result)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(executor.Executor, '_execute')
    def test_run_mdadm_err(self, mock_execute):
        mock_execute.side_effect = putils.ProcessExecutionError()
        cmd = ['mdadm', '--examine', NVME_DEVICE_PATH]
        result = self.connector.run_mdadm(cmd)
        self.assertIsNone(result)
        args, kwargs = mock_execute.call_args
        self.assertEqual(args[0], cmd[0])
        self.assertEqual(args[1], cmd[1])
        self.assertEqual(args[2], cmd[2])

    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_file_available(self, mock_open):
        mock_open.return_value.__enter__.return_value.read = (
            lambda: HOST_NQN + "\n")
        host_nqn = self._get_host_nqn()
        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'r')
        self.assertEqual(HOST_NQN, host_nqn)

    @mock.patch.object(utils.priv_nvme, 'create_hostnqn')
    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_io_err(self, mock_open, mock_create):
        mock_create.return_value = mock.sentinel.nqn
        mock_open.side_effect = IOError()
        result = utils.get_host_nqn()
        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'r')
        mock_create.assert_called_once_with()
        self.assertEqual(mock.sentinel.nqn, result)

    @mock.patch.object(utils.priv_nvme, 'create_hostnqn')
    @mock.patch.object(builtins, 'open')
    def test_get_host_nqn_err(self, mock_open, mock_create):
        mock_open.side_effect = Exception()
        result = utils.get_host_nqn()
        mock_open.assert_called_once_with('/etc/nvme/hostnqn', 'r')
        mock_create.assert_not_called()
        self.assertIsNone(result)

    @mock.patch.object(executor.Executor, '_execute')
    def test_run_nvme_cli(self, mock_execute):
        mock_execute.return_value = ("\n", "")
        cmd = 'dummy command'
        result = self.connector.run_nvme_cli(cmd)
        self.assertEqual(("\n", ""), result)

    def test_ks_readlink(self):
        dest = 'dummy path'
        result = self.connector.ks_readlink(dest)
        self.assertEqual('', result)

    @mock.patch.object(executor.Executor, '_execute')
    def test__get_fs_type(self, mock_execute):
        mock_execute.return_value = ('expected\n', '')
        result = self.connector._get_fs_type(NVME_DEVICE_PATH)
        self.assertEqual('expected', result)
        mock_execute.assert_called_once_with(
            'blkid', NVME_DEVICE_PATH, '-s', 'TYPE', '-o', 'value',
            run_as_root=True, root_helper=self.connector._root_helper,
            check_exit_code=False)

    @mock.patch.object(executor.Executor, '_execute',
                       return_value=('', 'There was a big error'))
    def test__get_fs_type_err(self, mock_execute):
        result = self.connector._get_fs_type(NVME_DEVICE_PATH)
        self.assertIsNone(result)
        mock_execute.assert_called_once_with(
            'blkid', NVME_DEVICE_PATH, '-s', 'TYPE', '-o', 'value',
            run_as_root=True, root_helper=self.connector._root_helper,
            check_exit_code=False)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_fs_type')
    def test__is_raid_device(self, mock_get_fs_type):
        mock_get_fs_type.return_value = 'linux_raid_member'
        result = self.connector._is_raid_device(NVME_DEVICE_PATH)
        self.assertTrue(result)
        mock_get_fs_type.assert_called_once_with(NVME_DEVICE_PATH)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_get_fs_type')
    def test__is_raid_device_not(self, mock_get_fs_type):
        mock_get_fs_type.return_value = 'xfs'
        result = self.connector._is_raid_device(NVME_DEVICE_PATH)
        self.assertFalse(result)
        mock_get_fs_type.assert_called_once_with(NVME_DEVICE_PATH)

    def _get_host_nqn(self):
        host_nqn = None
        try:
            with open('/etc/nvme/hostnqn', 'r') as f:
                host_nqn = f.read().strip()
                f.close()
        except IOError:
            host_nqn = HOST_NQN
        return host_nqn

    @ddt.data(True, False)
    @mock.patch.object(nvmeof.NVMeOFConnector, 'native_multipath_supported',
                       None)
    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported')
    def test__set_native_multipath_supported(self, value, mock_ana):
        mock_ana.return_value = value
        res = self.connector._set_native_multipath_supported()
        mock_ana.assert_called_once_with()
        self.assertIs(value, res)

    @mock.patch.object(nvmeof.NVMeOFConnector, 'native_multipath_supported',
                       True)
    @mock.patch.object(nvmeof.NVMeOFConnector,
                       '_is_native_multipath_supported')
    def test__set_native_multipath_supported_second_call(self, mock_ana):
        mock_ana.return_value = False
        res = self.connector._set_native_multipath_supported()
        mock_ana.assert_not_called()
        self.assertTrue(res)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_single_replica')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_replicated_volume')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target')
    def test__connect_volume_replicated(
            self, mock_connect, mock_replicated, mock_single):
        """Connect to replicated backend handles connection failures."""
        found_devices = ['/dev/nvme0n1', '/dev/nvme1n1']
        mock_connect.side_effect = [Exception] + found_devices
        res = self.connector._connect_volume_replicated(CONN_PROPS)

        self.assertEqual(mock_replicated.return_value, res)

        mock_replicated.assert_called_once_with(found_devices, CONN_PROPS)
        mock_single.assert_not_called()

    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_single_replica')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_replicated_volume')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target')
    def test__connect_volume_replicated_single_replica(
            self, mock_connect, mock_replicated, mock_single):
        """Connect to single repica backend."""
        conn_props = nvmeof.NVMeOFConnProps({
            'alias': 'fakealias',
            'vol_uuid': VOL_UUID,
            'volume_replicas': [volume_replicas[0]],
            'replica_count': 1
        })

        found_devices = ['/dev/nvme0n1']
        mock_connect.side_effect = found_devices
        res = self.connector._connect_volume_replicated(conn_props)

        self.assertEqual(mock_single.return_value, res)

        mock_replicated.assert_not_called()
        mock_single.assert_called_once_with(found_devices, 'fakealias')

    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_single_replica')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_handle_replicated_volume')
    @mock.patch.object(nvmeof.NVMeOFConnector, '_connect_target')
    def test__connect_volume_replicated_no_device_paths_found(
            self, mock_connect, mock_replicated, mock_single):
        """Fail if cannot connect to any replica."""
        mock_connect.side_effect = 3 * [Exception]

        self.assertRaises(exception.VolumeDeviceNotFound,
                          self.connector._connect_volume_replicated,
                          CONN_PROPS)

        mock_replicated.assert_not_called()
        mock_single.assert_not_called()

    @ddt.data({'result': False, 'use_multipath': False, 'ana_support': True},
              {'result': False, 'use_multipath': False, 'ana_support': False},
              {'result': False, 'use_multipath': True, 'ana_support': False},
              {'result': True, 'use_multipath': True, 'ana_support': True})
    @ddt.unpack
    def test__do_multipath(self, result, use_multipath, ana_support):
        self.connector.use_multipath = use_multipath
        self.connector.native_multipath_supported = ana_support
        self.assertIs(result, self.connector._do_multipath())

    @mock.patch.object(nvmeof.NVMeOFConnector, '_try_disconnect')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    def test__try_disconnect_all(self, mock_set_portals, mock_disconnect):
        """Disconnect all portals for all targets in connection properties."""
        connection_properties = {
            'vol_uuid': VOL_UUID,
            'alias': 'raid_alias',
            'replica_count': 2,
            'volume_replicas': [
                {'target_nqn': 'nqn1',
                 'vol_uuid': VOL_UUID1,
                 'portals': [['portal1', 'port_value', 'RoCEv2'],
                             ['portal2', 'port_value', 'anything']]},
                {'target_nqn': 'nqn2',
                 'vol_uuid': VOL_UUID2,
                 'portals': [['portal4', 'port_value', 'anything'],
                             ['portal3', 'port_value', 'RoCEv2']]}
            ],
        }
        conn_props = nvmeof.NVMeOFConnProps(connection_properties)
        exc = exception.ExceptionChainer()

        self.connector._try_disconnect_all(conn_props, exc)

        self.assertEqual(2, mock_set_portals.call_count)
        mock_set_portals.assert_has_calls((mock.call(), mock.call()))
        self.assertEqual(4, mock_disconnect.call_count)
        mock_disconnect.assert_has_calls((
            mock.call(conn_props.targets[0].portals[0]),
            mock.call(conn_props.targets[0].portals[1]),
            mock.call(conn_props.targets[1].portals[0]),
            mock.call(conn_props.targets[1].portals[1])
        ))
        self.assertFalse(bool(exc))

    @mock.patch.object(nvmeof.NVMeOFConnector, '_try_disconnect')
    @mock.patch.object(nvmeof.Target, 'set_portals_controllers')
    def test__try_disconnect_all_with_failures(
            self, mock_set_portals, mock_disconnect):
        """Even with failures it should try to disconnect all portals."""
        exc = exception.ExceptionChainer()
        mock_disconnect.side_effect = [Exception, None]

        self.connector._try_disconnect_all(self.conn_props, exc)

        mock_set_portals.assert_called_once_with()

        self.assertEqual(3, mock_disconnect.call_count)
        mock_disconnect.assert_has_calls((
            mock.call(self.conn_props.targets[0].portals[0]),
            mock.call(self.conn_props.targets[0].portals[1]),
            mock.call(self.conn_props.targets[0].portals[2])
        ))
        self.assertTrue(bool(exc))

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute')
    @mock.patch.object(nvmeof.Portal, 'can_disconnect')
    def test__try_disconnect(self, mock_can_disconnect, mock_execute):
        """We try to disconnect when we can without breaking other devices."""
        mock_can_disconnect.return_value = True
        portal = self.conn_props.targets[0].portals[0]
        portal.controller = 'nvme0'
        self.connector._try_disconnect(portal)
        mock_can_disconnect.assert_called_once_with()
        mock_execute.assert_called_once_with(
            'nvme', 'disconnect', '-d', '/dev/nvme0',
            root_helper=self.connector._root_helper, run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute')
    @mock.patch.object(nvmeof.Portal, 'can_disconnect')
    def test__try_disconnect_failure(self, mock_can_disconnect, mock_execute):
        """Confirm disconnect doesn't swallow exceptions."""
        mock_can_disconnect.return_value = True
        portal = self.conn_props.targets[0].portals[0]
        portal.controller = 'nvme0'
        mock_execute.side_effect = ValueError
        self.assertRaises(ValueError,
                          self.connector._try_disconnect, portal)
        mock_can_disconnect.assert_called_once_with()
        mock_execute.assert_called_once_with(
            'nvme', 'disconnect', '-d', '/dev/nvme0',
            root_helper=self.connector._root_helper, run_as_root=True)

    @mock.patch.object(nvmeof.NVMeOFConnector, '_execute')
    @mock.patch.object(nvmeof.Portal, 'can_disconnect')
    def test__try_disconnect_no_disconnect(
            self, mock_can_disconnect, mock_execute):
        """Doesn't disconnect when it would break other devices."""
        mock_can_disconnect.return_value = False
        portal = self.conn_props.targets[0].portals[0]
        self.connector._try_disconnect(portal)
        mock_can_disconnect.assert_called_once_with()
        mock_execute.assert_not_called()
