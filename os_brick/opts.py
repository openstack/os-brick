# Copyright (c) 2022, Red Hat, Inc.
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
from oslo_config import cfg


_opts = [
    cfg.StrOpt('lock_path',
               default=None,  # Set by set_defaults method below on setup
               help='Directory to use for os-brick lock files. Defaults to '
                    'oslo_concurrency.lock_path which is a sensible default '
                    'for compute nodes, but not for HCI deployments or '
                    'controllers where Glance uses Cinder as a backend, as '
                    'locks should use the same directory.'),
]

cfg.CONF.register_opts(_opts, group='os_brick')


def list_opts():
    """oslo.config.opts entrypoint for sample config generation."""
    return [('os_brick', _opts)]


def set_defaults(conf=cfg.CONF):
    """Set default values that depend on other libraries.

    Service configuration options must have been initialized before this call
    because oslo's lock_path doesn't have a value before that.

    Called from both os_brick setup and from the oslo.config.opts entrypoint
    for sample config generation.
    """
    conf.set_default('lock_path', conf.oslo_concurrency.lock_path, 'os_brick')
