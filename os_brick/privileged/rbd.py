# Copyright (c) 2020, Red Hat, Inc.
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

from oslo_utils import fileutils
from oslo_utils import importutils

import os_brick.privileged

# Lazy load the rbd module to avoid circular references
RBDConnector = None


def _get_rbd_class():
    global RBDConnector
    global get_rbd_class

    # Lazy load the class
    if not RBDConnector:
        rbd_class_route = 'os_brick.initiator.connectors.rbd.RBDConnector'
        RBDConnector = importutils.import_class(rbd_class_route)

    # Job is done, following calls don't need to do anything
    get_rbd_class = lambda: None  # noqa


get_rbd_class = _get_rbd_class


@os_brick.privileged.default.entrypoint
def delete_if_exists(path):
    return fileutils.delete_if_exists(path)


@os_brick.privileged.default.entrypoint
def root_create_ceph_conf(monitor_ips, monitor_ports, cluster_name, user,
                          keyring):
    """Create a .conf file for Ceph cluster only accessible by root."""
    get_rbd_class()
    return RBDConnector._create_ceph_conf(monitor_ips, monitor_ports,
                                          cluster_name, user, keyring)


@os_brick.privileged.default.entrypoint
def check_valid_path(path):
    get_rbd_class()
    with open(path, 'rb') as rbd_handle:
        return RBDConnector._check_valid_device(rbd_handle)
