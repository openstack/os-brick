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

import tempfile

from os_brick import exception
from os_brick import privileged
from os_brick.privileged import scaleio
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

        # Bypass privsep and run these simple functions in-process
        # (allows reading back the modified state of mocks)
        privileged.default.set_client_mode(False)
        self.addCleanup(privileged.default.set_client_mode, True)

        self.fake_config_file = tempfile.NamedTemporaryFile("w",
                                                            suffix='.conf')
        self.addCleanup(self.fake_config_file.close)
        self.fake_config_file.write(FAKE_CONF)
        self.fake_config_file.flush()

    def test_get_connector_password_bad_filename(self):
        self.assertRaises(exception.BrickException,
                          scaleio.get_connector_password,
                          "this_is_not_the_file_you_expect.conf",
                          EXPECTED_SECTION)

    def test_get_connector_password(self):
        found_password = scaleio.get_connector_password(
            self.fake_config_file.name, EXPECTED_SECTION)
        self.assertEqual(EXPECTED_PASSWORD, found_password)
