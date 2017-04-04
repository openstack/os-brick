# Copyright 2013 OpenStack Foundation.
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


from os_brick.initiator.connectors import base
from os_brick.initiator.connectors import base_iscsi


class FakeConnector(base.BaseLinuxConnector):

    fake_path = '/dev/vdFAKE'

    def connect_volume(self, connection_properties):
        fake_device_info = {'type': 'fake',
                            'path': self.fake_path}
        return fake_device_info

    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        pass

    def get_volume_paths(self, connection_properties):
        return [self.fake_path]

    def get_search_path(self):
        return '/dev/disk/by-path'

    def extend_volume(self, connection_properties):
        return None

    def get_all_available_volumes(self, connection_properties=None):
        return ['/dev/disk/by-path/fake-volume-1',
                '/dev/disk/by-path/fake-volume-X']


class FakeBaseISCSIConnector(FakeConnector, base_iscsi.BaseISCSIConnector):
    pass
