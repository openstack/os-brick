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

"""Generic RBD connection utilities."""

import io

from oslo_log import log as logging

from os_brick import exception
from os_brick.i18n import _
from os_brick import utils

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
                setattr(self, attr, utils.convert_str(val))

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
        self.rbd_cluster_name = kwargs.get('rbd_cluster_name', 'ceph')
        self.rados_connect_timeout = kwargs.get('rados_connect_timeout', -1)

        self.client, self.ioctx = self.connect()

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.disconnect()

    def connect(self):
        LOG.debug("opening connection to ceph cluster (timeout=%s).",
                  self.rados_connect_timeout)
        client = self.rados.Rados(rados_id=self.rbd_user,
                                  clustername=self.rbd_cluster_name,
                                  conffile=self.rbd_conf)

        try:
            if self.rados_connect_timeout >= 0:
                client.connect(
                    timeout=self.rados_connect_timeout)
            else:
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
            snapshot = utils.convert_str(snapshot)

        try:
            self.image = client.rbd.Image(client.ioctx,
                                          utils.convert_str(name),
                                          snapshot=snapshot,
                                          read_only=read_only)
        except client.rbd.Error:
            LOG.exception("error opening rbd image %s", name)
            client.disconnect()
            raise

        # Ceph provides rbd.so to cinder, but we can't
        # get volume name from rbd.Image, so, we record
        # name here, so other modules can easily get
        # volume name.
        self.name = name
        self.client = client

    def close(self):
        try:
            self.image.close()
        finally:
            self.client.disconnect()

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.close()

    def __getattr__(self, attrib):
        return getattr(self.image, attrib)


class RBDImageMetadata(object):
    """RBD image metadata to be used with RBDVolumeIOWrapper."""
    def __init__(self, image, pool, user, conf):
        self.image = image
        self.pool = utils.convert_str(pool or '')
        self.user = utils.convert_str(user or '')
        self.conf = utils.convert_str(conf or '')


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

    @property
    def rbd_image(self):
        return self._rbd_volume.image

    @property
    def rbd_user(self):
        return self._rbd_volume.user

    @property
    def rbd_pool(self):
        return self._rbd_volume.pool

    @property
    def rbd_conf(self):
        return self._rbd_volume.conf

    def read(self, length=None):
        offset = self._offset
        total = self._rbd_volume.image.size()

        # NOTE(dosaboy): posix files do not barf if you read beyond their
        # length (they just return nothing) but rbd images do so we need to
        # return empty string if we have reached the end of the image.
        if (offset >= total):
            return b''

        if length is None:
            length = total

        if (offset + length) > total:
            length = total - offset

        try:
            data = self._rbd_volume.image.read(int(offset), int(length))
        except Exception:
            LOG.exception('Exception encountered during image read')
            raise

        self._inc_offset(length)
        return data

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
            LOG.warning("flush() not supported in this version of librbd")

    def fileno(self):
        """RBD does not have support for fileno() so we raise IOError.

        Raising IOError is recommended way to notify caller that interface is
        not supported - see http://docs.python.org/2/library/io.html#io.IOBase
        """
        raise IOError(_("fileno() not supported by RBD()"))

    def close(self):
        self.rbd_image.close()
