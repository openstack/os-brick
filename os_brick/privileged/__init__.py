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

import os

from oslo_privsep import capabilities as c
from oslo_privsep import priv_context


capabilities = [c.CAP_SYS_ADMIN]

# On virtual environments libraries are not owned by the Daemon user (root), so
# the Daemon needs the capability to bypass file read permission checks in
# order to dynamically load the code to run.
if os.environ.get('VIRTUAL_ENV'):
    capabilities.append(c.CAP_DAC_READ_SEARCH)

# It is expected that most (if not all) os-brick operations can be
# executed with these privileges.
default = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_osbrick',
    pypath=__name__ + '.default',
    capabilities=capabilities,
)
