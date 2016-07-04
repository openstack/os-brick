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

from oslo_log import log as logging
from oslo_utils import importutils

from os_brick.i18n import _

LOG = logging.getLogger(__name__)


# TODO(lpetrut): once we move the protocol name constants to a
#                separate module, use that instead.
_connector_dict = {
    'ISCSI':
        'os_brick.initiator.windows.iscsi.WindowsISCSIConnector',
}


def factory(protocol, *args, **kwargs):
    LOG.debug("Retrieving connector for protocol: %s.", protocol)

    connector = _connector_dict.get(protocol.upper())
    if not connector:
        msg = (_("Invalid InitiatorConnector protocol "
                 "specified %(protocol)s") %
               dict(protocol=protocol))
        raise ValueError(msg)

    conn_cls = importutils.import_class(connector)
    return conn_cls(*args, **kwargs)
