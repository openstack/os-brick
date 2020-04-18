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
from unittest import mock

from os_brick.initiator.connectors import base_iscsi
from os_brick.initiator.connectors import fake
from os_brick.tests import base as test_base


class BaseISCSIConnectorTestCase(test_base.TestCase):

    def setUp(self):
        super(BaseISCSIConnectorTestCase, self).setUp()
        self.connector = fake.FakeBaseISCSIConnector(None)

    @mock.patch.object(base_iscsi.BaseISCSIConnector, '_get_all_targets')
    def test_iterate_all_targets(self, mock_get_all_targets):
        # extra_property cannot be a sentinel, a copied sentinel will not
        # identical to the original one.
        connection_properties = {
            'target_portals': mock.sentinel.target_portals,
            'target_iqns': mock.sentinel.target_iqns,
            'target_luns': mock.sentinel.target_luns,
            'extra_property': 'extra_property'}
        mock_get_all_targets.return_value = [(
            mock.sentinel.portal, mock.sentinel.iqn, mock.sentinel.lun)]

        # method is a generator, and it yields dictionaries. list() will
        # iterate over all of the method's items.
        list_props = list(
            self.connector._iterate_all_targets(connection_properties))

        mock_get_all_targets.assert_called_once_with(connection_properties)
        self.assertEqual(1, len(list_props))

        expected_props = {'target_portal': mock.sentinel.portal,
                          'target_iqn': mock.sentinel.iqn,
                          'target_lun': mock.sentinel.lun,
                          'extra_property': 'extra_property'}
        self.assertEqual(expected_props, list_props[0])

    def test_get_all_targets(self):
        connection_properties = {
            'target_portals': [mock.sentinel.target_portals],
            'target_iqns': [mock.sentinel.target_iqns],
            'target_luns': [mock.sentinel.target_luns]}

        all_targets = self.connector._get_all_targets(connection_properties)

        expected_targets = zip([mock.sentinel.target_portals],
                               [mock.sentinel.target_iqns],
                               [mock.sentinel.target_luns])
        self.assertEqual(list(expected_targets), list(all_targets))

    def test_get_all_targets_single_target(self):
        connection_properties = {
            'target_portal': mock.sentinel.target_portal,
            'target_iqn': mock.sentinel.target_iqn,
            'target_lun': mock.sentinel.target_lun}

        all_targets = self.connector._get_all_targets(connection_properties)

        expected_target = (mock.sentinel.target_portal,
                           mock.sentinel.target_iqn,
                           mock.sentinel.target_lun)
        self.assertEqual([expected_target], all_targets)
