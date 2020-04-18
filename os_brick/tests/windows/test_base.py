# Copyright 2016 Cloudbase Solutions Srl
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

from os_win import utilsfactory

from os_brick.tests import base


class WindowsConnectorTestBase(base.TestCase):
    @mock.patch('sys.platform', 'win32')
    def setUp(self):
        super(WindowsConnectorTestBase, self).setUp()

        # All the Windows connectors use os_win.utilsfactory to fetch Windows
        # specific utils. During init, those will run methods that will fail
        # on other platforms. To make testing easier and avoid checking the
        # platform in the code, we can simply mock this factory method.
        utilsfactory_patcher = mock.patch.object(
            utilsfactory, '_get_class')
        utilsfactory_patcher.start()
        self.addCleanup(utilsfactory_patcher.stop)
