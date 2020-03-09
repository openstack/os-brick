# Copyright 2020 Cloudbase Solutions Srl
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
from oslo_utils import netutils

LOG = logging.getLogger(__name__)


class RBDConnectorMixin(object):
    """Mixin covering cross platform RBD connector functionality"""

    @staticmethod
    def _sanitize_mon_hosts(hosts):
        def _sanitize_host(host):
            if netutils.is_valid_ipv6(host):
                host = '[%s]' % host
            return host
        return list(map(_sanitize_host, hosts))

    @classmethod
    def _get_rbd_args(cls, connection_properties, conf=None):
        user = connection_properties.get('auth_username')
        monitor_ips = connection_properties.get('hosts')
        monitor_ports = connection_properties.get('ports')

        args = []
        if user:
            args = ['--id', user]
        if monitor_ips and monitor_ports:
            monitors = ["%s:%s" % (ip, port) for ip, port in
                        zip(
                            cls._sanitize_mon_hosts(monitor_ips),
                            monitor_ports)]
            for monitor in monitors:
                args += ['--mon_host', monitor]

        if conf:
            args += ['--conf', conf]

        return args
