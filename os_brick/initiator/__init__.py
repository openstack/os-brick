# Copyright 2015 OpenStack Foundation
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
"""Brick's Initiator module.

The initator module contains the capabilities for discovering the initiator
information as well as discovering and removing volumes from a host.
"""

import re


DEVICE_SCAN_ATTEMPTS_DEFAULT = 3
MULTIPATH_ERROR_REGEX = re.compile(r"\w{3} \d+ \d\d:\d\d:\d\d \|.*$")
MULTIPATH_PATH_CHECK_REGEX = re.compile(r"\s+\d+:\d+:\d+:\d+\s+")

PLATFORM_ALL = 'ALL'
PLATFORM_x86 = 'X86'
PLATFORM_S390 = 'S390'
PLATFORM_PPC64 = 'PPC64'
OS_TYPE_ALL = 'ALL'
OS_TYPE_LINUX = 'LINUX'
OS_TYPE_WINDOWS = 'WIN'

S390X = "s390x"
S390 = "s390"
PPC64 = "ppc64"
PPC64LE = "ppc64le"

ISCSI = "ISCSI"
ISER = "ISER"
FIBRE_CHANNEL = "FIBRE_CHANNEL"
NFS = "NFS"
SMBFS = 'SMBFS'
GLUSTERFS = "GLUSTERFS"
LOCAL = "LOCAL"
HUAWEISDSHYPERVISOR = "HUAWEISDSHYPERVISOR"
RBD = "RBD"
SCALEIO = "SCALEIO"
SCALITY = "SCALITY"
QUOBYTE = "QUOBYTE"
VZSTORAGE = "VZSTORAGE"
VMDK = "VMDK"
GPFS = "GPFS"
STORPOOL = "STORPOOL"
NVME = "NVME"
NVMEOF = "NVMEOF"
