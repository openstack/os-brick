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


import copy

from os_brick.initiator import initiator_connector


class BaseISCSIConnector(initiator_connector.InitiatorConnector):
    def _iterate_all_targets(self, connection_properties):
        for portal, iqn, lun in self._get_all_targets(connection_properties):
            props = copy.deepcopy(connection_properties)
            props['target_portal'] = portal
            props['target_iqn'] = iqn
            props['target_lun'] = lun
            for key in ('target_portals', 'target_iqns', 'target_luns'):
                props.pop(key, None)
            yield props

    @staticmethod
    def _get_luns(con_props, iqns=None):
        luns = con_props.get('target_luns')
        num_luns = len(con_props['target_iqns']) if iqns is None else len(iqns)
        return luns or [con_props['target_lun']] * num_luns

    def _get_all_targets(self, connection_properties):
        if all(key in connection_properties for key in ('target_portals',
                                                        'target_iqns')):
            return list(zip(connection_properties['target_portals'],
                            connection_properties['target_iqns'],
                            self._get_luns(connection_properties)))

        return [(connection_properties['target_portal'],
                 connection_properties['target_iqn'],
                 connection_properties.get('target_lun', 0))]
