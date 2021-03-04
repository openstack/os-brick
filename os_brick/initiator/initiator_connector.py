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


import abc

from os_brick import exception
from os_brick import executor
from os_brick import initiator


class InitiatorConnector(executor.Executor, metaclass=abc.ABCMeta):

    # This object can be used on any platform (x86, S390)
    platform = initiator.PLATFORM_ALL

    # This object can be used on any os type (linux, windows)
    os_type = initiator.OS_TYPE_ALL

    def __init__(self, root_helper, driver=None, execute=None,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(InitiatorConnector, self).__init__(root_helper, execute=execute,
                                                 *args, **kwargs)
        self.device_scan_attempts = device_scan_attempts

    def set_driver(self, driver):
        """The driver is used to find used LUNs."""
        self.driver = driver

    @staticmethod
    @abc.abstractmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The generic connector properties."""
        pass

    @abc.abstractmethod
    def check_valid_device(self, path, run_as_root=True):
        """Test to see if the device path is a real device.

        :param path: The file system path for the device.
        :type path: str
        :param run_as_root: run the tests as root user?
        :type run_as_root: bool
        :returns: bool
        """
        pass

    @abc.abstractmethod
    def connect_volume(self, connection_properties):
        """Connect to a volume.

        The connection_properties describes the information needed by
        the specific protocol to use to make the connection.

        The connection_properties is a dictionary that describes the target
        volume.  It varies slightly by protocol type (iscsi, fibre_channel),
        but the structure is usually the same.


        An example for iSCSI:

        {'driver_volume_type': 'iscsi',
         'data': {
             'target_luns': [0, 2],
             'target_iqns': ['iqn.2000-05.com.3pardata:20810002ac00383d',
                             'iqn.2000-05.com.3pardata:21810002ac00383d'],
             'target_discovered': True,
             'encrypted': False,
             'qos_specs': None,
             'target_portals': ['10.52.1.11:3260', '10.52.2.11:3260'],
             'access_mode': 'rw',
        }}

        An example for fibre_channel with single lun:

        {'driver_volume_type': 'fibre_channel',
         'data': {
            'initiator_target_map': {'100010604b010459': ['20210002AC00383D'],
                                     '100010604b01045d': ['20220002AC00383D']},
            'target_discovered': True,
            'encrypted': False,
            'qos_specs': None,
            'target_lun': 1,
            'access_mode': 'rw',
            'target_wwn': [
                '20210002AC00383D',
                '20220002AC00383D',
                ],
         }}

        An example for fibre_channel target_wwns and with different LUNs and
        all host ports mapped to target ports:

        {'driver_volume_type': 'fibre_channel',
         'data': {
            'initiator_target_map': {
                '100010604b010459': ['20210002AC00383D', '20220002AC00383D'],
                '100010604b01045d': ['20210002AC00383D', '20220002AC00383D']
                },
            'target_discovered': True,
            'encrypted': False,
            'qos_specs': None,
            'target_luns': [1, 2],
            'access_mode': 'rw',
            'target_wwns': ['20210002AC00383D', '20220002AC00383D'],
         }}

         For FC the dictionary could also present the enable_wildcard_scan key
         with a boolean value (defaults to True) in case a driver doesn't want
         OS-Brick to use a SCSI scan with wildcards when the FC initiator on
         the host doesn't find any target port.

         This is useful for drivers that know that sysfs gets populated
         whenever there's a connection between the host's HBA and the storage
         array's target ports.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """
        pass

    @abc.abstractmethod
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Disconnect a volume from the local host.

        The connection_properties are the same as from connect_volume.
        The device_info is returned from connect_volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        :param force: Whether to forcefully disconnect even if flush fails.
        :type force: bool
        :param ignore_errors: When force is True, this will decide whether to
                              ignore errors or raise an exception once finished
                              the operation.  Default is False.
        :type ignore_errors: bool
        """
        pass

    @abc.abstractmethod
    def get_volume_paths(self, connection_properties):
        """Return the list of existing paths for a volume.

        The job of this method is to find out what paths in
        the system are associated with a volume as described
        by the connection_properties.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        """
        pass

    @abc.abstractmethod
    def get_search_path(self):
        """Return the directory where a Connector looks for volumes.

        Some Connectors need the information in the
        connection_properties to determine the search path.
        """
        pass

    @abc.abstractmethod
    def extend_volume(self, connection_properties):
        """Update the attached volume's size.

        This method will attempt to update the local hosts's
        volume after the volume has been extended on the remote
        system.  The new volume size in bytes will be returned.
        If there is a failure to update, then None will be returned.

        :param connection_properties: The volume connection properties.
        :returns: new size of the volume.
        """
        pass

    @abc.abstractmethod
    def get_all_available_volumes(self, connection_properties=None):
        """Return all volumes that exist in the search directory.

        At connect_volume time, a Connector looks in a specific
        directory to discover a volume's paths showing up.
        This method's job is to return all paths in the directory
        that connect_volume uses to find a volume.

        This method is used in coordination with get_volume_paths()
        to verify that volumes have gone away after disconnect_volume
        has been called.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        """
        pass

    def check_IO_handle_valid(self, handle, data_type, protocol):
        """Check IO handle has correct data type."""
        if (handle and not isinstance(handle, data_type)):
            raise exception.InvalidIOHandleObject(
                protocol=protocol,
                actual_type=type(handle))
