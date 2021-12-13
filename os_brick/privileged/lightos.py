# Copyright (C) 2016-2022 Lightbits Labs Ltd.
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

import shutil

from oslo_utils import fileutils

import os_brick.privileged


@os_brick.privileged.default.entrypoint
def delete_dsc_file(file_name):
    return fileutils.delete_if_exists(file_name)


@os_brick.privileged.default.entrypoint
def move_dsc_file(src, dst):
    return shutil.move(src, dst)
