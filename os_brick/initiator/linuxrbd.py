# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

""" Generic RBD connection utilities."""

import io
from oslo_log import log as logging
from oslo_utils import encodeutils

from os_brick import exception
from os_brick.i18n import _, _LE, _LW

try:
    import rados
    import rbd
except ImportError:
    rados = None
    rbd = None


LOG = logging.getLogger(__name__)


class RBDClient(object):

    def __init__(self, user, pool, *args, **kwargs):

        self.rbd_user = user
        self.rbd_pool = pool

        for attr in ['rbd_user', 'rbd_pool']:
            val = getattr(self, attr)
            if val is not None:
                setattr(self, attr, encodeutils.safe_encode(val))

        # allow these to be overridden for testing
        self.rados = kwargs.get('rados', rados)
        self.rbd = kwargs.get('rbd', rbd)

        if self.rados is None:
            raise exception.InvalidParameterValue(
                err=_('rados module required'))
        if self.rbd is None:
            raise exception.InvalidParameterValue(
                err=_('rbd module required'))

        self.rbd_conf = kwargs.get('conffile', '/etc/ceph/ceph.conf')

        self.client, self.ioctx = self.connect()

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.disconnect()

    def connect(self):
        client = self.rados.Rados(rados_id=self.rbd_user,
                                  conffile=self.rbd_conf)

        try:
            client.connect()
            ioctx = client.open_ioctx(self.rbd_pool)
            return client, ioctx
        except self.rados.Error:
            msg = _("Error connecting to ceph cluster.")
            LOG.exception(msg)
            # shutdown cannot raise an exception
            client.shutdown()
            raise exception.BrickException(message=msg)

    def disconnect(self):
        # closing an ioctx cannot raise an exception
        self.ioctx.close()
        self.client.shutdown()


class RBDVolume(object):
    """Context manager for dealing with an existing rbd volume."""

    def __init__(self, client, name, snapshot=None, read_only=False):
        if snapshot is not None:
            snapshot = encodeutils.safe_encode(snapshot)

        try:
            self.image = client.rbd.Image(client.ioctx,
                                          encodeutils.safe_encode(name),
                                          snapshot=snapshot,
                                          read_only=read_only)
        except client.rbd.Error:
            LOG.exception(_LE("error opening rbd image %s"), name)
            client.disconnect()
            raise

        self.client = client

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        try:
            self.image.close()
        finally:
            self.client.disconnect()

    def __getattr__(self, attrib):
        return getattr(self.image, attrib)


class RBDVolumeIOWrapper(io.RawIOBase):
    """Enables LibRBD.Image objects to be treated as Python IO objects.

    Calling unimplemented interfaces will raise IOError.
    """

    def __init__(self, rbd_volume):
        super(RBDVolumeIOWrapper, self).__init__()
        self._rbd_volume = rbd_volume
        self._offset = 0

    def _inc_offset(self, length):
        self._offset += length

    def read(self, length=None):
        offset = self._offset
        total = self._rbd_volume.image.size()

        # NOTE(dosaboy): posix files do not barf if you read beyond their
        # length (they just return nothing) but rbd images do so we need to
        # return empty string if we have reached the end of the image.
        if (offset >= total):
            return ''

        if length is None:
            length = total

        if (offset + length) > total:
            length = total - offset

        self._inc_offset(length)
        return self._rbd_volume.image.read(int(offset), int(length))

    def write(self, data):
        self._rbd_volume.image.write(data, self._offset)
        self._inc_offset(len(data))

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        if whence == 0:
            new_offset = offset
        elif whence == 1:
            new_offset = self._offset + offset
        elif whence == 2:
            new_offset = self._rbd_volume.image.size()
            new_offset += offset
        else:
            raise IOError(_("Invalid argument - whence=%s not supported") %
                          (whence))

        if (new_offset < 0):
            raise IOError(_("Invalid argument"))

        self._offset = new_offset

    def tell(self):
        return self._offset

    def flush(self):
        try:
            self._rbd_volume.image.flush()
        except AttributeError:
            LOG.warning(_LW("flush() not supported in this version of librbd"))

    def fileno(self):
        """RBD does not have support for fileno() so we raise IOError.

        Raising IOError is recommended way to notify caller that interface is
        not supported - see http://docs.python.org/2/library/io.html#io.IOBase
        """
        raise IOError(_("fileno() not supported by RBD()"))

    # NOTE(dosaboy): if IO object is not closed explicitly, Python auto closes
    # it which, if this is not overridden, calls flush() prior to close which
    # in this case is unwanted since the rbd image may have been closed prior
    # to the autoclean - currently triggering a segfault in librbd.
    def close(self):
        pass
