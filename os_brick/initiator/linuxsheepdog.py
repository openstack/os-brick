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

"""
Generic SheepDog Connection Utilities.

"""
import eventlet
import io
from oslo_concurrency import processutils

from os_brick import exception
from os_brick.i18n import _


class SheepdogVolumeIOWrapper(io.RawIOBase):
    """File-like object with Sheepdog backend."""

    def __init__(self, addr, port, volume, snapshot_name=None):
        self._addr = addr
        self._port = port
        self._vdiname = volume
        self._snapshot_name = snapshot_name
        self._offset = 0
        # SheepdogVolumeIOWrapper instance becomes invalid
        # if a write error occurs.
        self._valid = True

    def _execute(self, cmd, data=None):
        try:
            # NOTE(yamada-h): processutils.execute causes busy waiting
            # under eventlet.
            # To avoid wasting CPU resources, it should not be used for
            # the command which takes long time to execute.
            # For workaround, we replace a subprocess module with
            # the original one while only executing a read/write command.
            _processutils_subprocess = processutils.subprocess
            processutils.subprocess = eventlet.patcher.original('subprocess')
            return processutils.execute(*cmd, process_input=data)[0]
        except (processutils.ProcessExecutionError, OSError):
            self._valid = False
            raise exception.VolumeDriverException(name=self._vdiname)
        finally:
            processutils.subprocess = _processutils_subprocess

    def read(self, length=None):
        if not self._valid:
            raise exception.VolumeDriverException(name=self._vdiname)

        cmd = ['dog', 'vdi', 'read', '-a', self._addr, '-p', self._port]
        if self._snapshot_name:
            cmd.extend(('-s', self._snapshot_name))
        cmd.extend((self._vdiname, self._offset))
        if length:
            cmd.append(length)
        data = self._execute(cmd)
        self._offset += len(data)
        return data

    def write(self, data):
        if not self._valid:
            raise exception.VolumeDriverException(name=self._vdiname)

        length = len(data)
        cmd = ('dog', 'vdi', 'write', '-a', self._addr, '-p', self._port,
               self._vdiname, self._offset, length)
        self._execute(cmd, data)
        self._offset += length
        return length

    def seek(self, offset, whence=0):
        if not self._valid:
            raise exception.VolumeDriverException(name=self._vdiname)

        if whence == 0:
            # SEEK_SET or 0 - start of the stream (the default);
            # offset should be zero or positive
            new_offset = offset
        elif whence == 1:
            # SEEK_CUR or 1 - current stream position; offset may be negative
            new_offset = self._offset + offset
        else:
            # SEEK_END or 2 - end of the stream; offset is usually negative
            # TODO(yamada-h): Support SEEK_END
            raise IOError(_("Invalid argument - whence=%s not supported.") %
                          whence)

        if new_offset < 0:
            raise IOError(_("Invalid argument - negative seek offset."))

        self._offset = new_offset

    def tell(self):
        return self._offset

    def flush(self):
        pass

    def fileno(self):
        """Sheepdog does not have support for fileno so we raise IOError.

        Raising IOError is recommended way to notify caller that interface is
        not supported - see http://docs.python.org/2/library/io.html#io.IOBase
        """
        raise IOError(_("fileno is not supported by SheepdogVolumeIOWrapper"))
