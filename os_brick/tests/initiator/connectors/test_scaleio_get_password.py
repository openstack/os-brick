# Copyright 2020, Red Hat Inc.
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

import mock
import os

from os_brick import exception
from os_brick.initiator.connectors import scaleio
from os_brick.tests import base

EXPECTED_SECTION = "scalio_test"
EXPECTED_PASSWORD = "This is not a good password"
FAKE_CONF = """
[DEFAULT]
san_password = not me

[{}]
san_password = {}

[section_2]
san_password = not me either
""".format(EXPECTED_SECTION, EXPECTED_PASSWORD)


class ScaleioGetPasswordTestCase(base.TestCase):
    """Check the get_connector_password function.

    Launchpad bug #1883654: a change that worked fine in the
    python 3-only branches broke when run under py2.7 in the stable
    branches.

    """

    def setUp(self):
        super(ScaleioGetPasswordTestCase, self).setUp()
        # The actual ScaleIO connector
        self.connector = scaleio.ScaleIOConnector('sudo')

    @mock.patch.object(os.path, 'isfile', return_value=False)
    def test_get_connector_password_bad_filename(self, mock_isfile):
        self.assertRaises(exception.BrickException,
                          self.connector._get_connector_password,
                          EXPECTED_SECTION)

    @mock.patch.object(scaleio.ScaleIOConnector, '_execute')
    @mock.patch.object(os.path, 'isfile', return_value=True)
    def test_get_connector_password(self, mock_isfile, mock_execute):
        mock_execute.return_value = (FAKE_CONF, 0)
        found_password = self.connector._get_connector_password(
            EXPECTED_SECTION)
        self.assertEqual(EXPECTED_PASSWORD, found_password)
