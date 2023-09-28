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

from binascii import hexlify
import configparser
from contextlib import contextmanager
from fcntl import ioctl
import os
import struct
import uuid

from os_brick import exception
from os_brick import privileged

SCINI_DEVICE_PATH = '/dev/scini'


@contextmanager
def open_scini_device():
    """Open scini device for low-level I/O using contextmanager.

    File descriptor will be closed after all operations performed if it was
    opened successfully.

    :return: scini device file descriptor
    :rtype: int
    """

    fd = None
    try:
        fd = os.open(SCINI_DEVICE_PATH, os.O_RDWR)
        yield fd
    finally:
        if fd:
            os.close(fd)


@privileged.default.entrypoint
def get_guid(op_code):
    """Query ScaleIO sdc GUID via ioctl request.

    :param op_code: operational code
    :type op_code: int
    :return: ScaleIO sdc GUID
    :rtype: str
    """

    with open_scini_device() as fd:
        out = ioctl(fd, op_code, struct.pack('QQQ', 0, 0, 0))
        # The first 8 bytes contain a return code that is not used
        # so they can be discarded.
        out_to_hex = hexlify(out[8:]).decode()
        return str(uuid.UUID(out_to_hex))


@privileged.default.entrypoint
def rescan_vols(op_code):
    """Rescan ScaleIO volumes via ioctl request.

    :param op_code: operational code
    :type op_code: int
    """

    with open_scini_device() as fd:
        ioctl(fd, op_code, struct.pack('Q', 0))


@privileged.default.entrypoint
def get_connector_password(filename, config_group, failed_over):
    """Read ScaleIO connector configuration file and get appropriate password.

    :param filename: path to connector configuration file
    :type filename: str
    :param config_group: name of section in configuration file
    :type config_group: str
    :param failed_over: flag representing if storage is in failed over state
    :type failed_over: bool
    :return: connector password
    :rtype: str
    """

    if not os.path.isfile(filename):
        msg = (
            "ScaleIO connector configuration file "
            "is not found in path %s." % filename
        )
        raise exception.BrickException(message=msg)

    conf = configparser.ConfigParser()
    conf.read(filename)
    password_key = (
        "replicating_san_password" if failed_over else "san_password"
    )
    return conf[config_group][password_key]
