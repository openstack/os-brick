# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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

"""Exceptions for the Brick library."""

import traceback
from typing import Iterable, List, Optional  # noqa: H301

from oslo_concurrency import processutils as putils
from oslo_log import log as logging

from os_brick.i18n import _


LOG = logging.getLogger(__name__)


class BrickException(Exception):
    """Base Brick Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = _("An unknown exception occurred.")
    code = 500
    headers: dict = {}
    safe = False

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        if not message:
            try:
                message = self.message % kwargs

            except Exception:
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception("Exception in string format operation. "
                              "msg='%s'", self.message)
                for name, value in kwargs.items():
                    LOG.error("%(name)s: %(value)s", {'name': name,
                                                      'value': value})

                # at least get the core message out if something happened
                message = self.message

        # Put the message in 'msg' so that we can access it.  If we have it in
        # message it will be overshadowed by the class' message attribute
        self.msg = message
        super(BrickException, self).__init__(message)


class NotFound(BrickException):
    message = _("Resource could not be found.")
    code = 404
    safe = True


class Invalid(BrickException):
    message = _("Unacceptable parameters.")
    code = 400


# Cannot be templated as the error syntax varies.
# msg needs to be constructed when raised.
class InvalidParameterValue(Invalid):
    message = _("%(err)s")


class NoFibreChannelHostsFound(BrickException):
    message = _("We are unable to locate any Fibre Channel devices.")


class NoFibreChannelVolumeDeviceFound(BrickException):
    message = _("Unable to find a Fibre Channel volume device.")


class VolumeNotDeactivated(BrickException):
    message = _('Volume %(name)s was not deactivated in time.')


class VolumeDeviceNotFound(BrickException):
    message = _("Volume device not found at %(device)s.")


class VolumePathsNotFound(BrickException):
    message = _("Could not find any paths for the volume.")


class VolumePathNotRemoved(BrickException):
    message = _("Volume path %(volume_path)s was not removed in time.")


class ProtocolNotSupported(BrickException):
    message = _("Connect to volume via protocol %(protocol)s not supported.")


class TargetPortalNotFound(BrickException):
    message = _("Unable to find target portal %(target_portal)s.")


class TargetPortalsNotFound(TargetPortalNotFound):
    message = _("Unable to find target portal in %(target_portals)s.")


class FailedISCSITargetPortalLogin(BrickException):
    message = _("Unable to login to iSCSI Target Portal")


class BlockDeviceReadOnly(BrickException):
    message = _("Block device %(device)s is Read-Only.")


class VolumeGroupNotFound(BrickException):
    message = _("Unable to find Volume Group: %(vg_name)s")


class VolumeGroupCreationFailed(BrickException):
    message = _("Failed to create Volume Group: %(vg_name)s")


class CommandExecutionFailed(BrickException):
    message = _("Failed to execute command %(cmd)s")


class VolumeDriverException(BrickException):
    message = _('An error occurred while IO to volume %(name)s.')


class InvalidIOHandleObject(BrickException):
    message = _('IO handle of %(protocol)s has wrong object '
                'type %(actual_type)s.')


class VolumeEncryptionNotSupported(Invalid):
    message = _("Volume encryption is not supported for %(volume_type)s "
                "volume %(volume_id)s.")


class VolumeLocalCacheNotSupported(Invalid):
    message = _("Volume local cache is not supported for %(volume_type)s "
                "volume %(volume_id)s.")


# NOTE(mriedem): This extends ValueError to maintain backward compatibility.
class InvalidConnectorProtocol(ValueError):
    pass


class ExceptionChainer(BrickException):
    """A Exception that can contain a group of exceptions.

    This exception serves as a container for exceptions, useful when we want to
    store all exceptions that happened during a series of steps and then raise
    them all together as one.

    The representation of the exception will include all exceptions and their
    tracebacks.

    This class also includes a context manager for convenience, one that will
    support both swallowing the exception as if nothing had happened and
    raising the exception.  In both cases the exception will be stored.

    If a message is provided to the context manager it will be formatted and
    logged with warning level.
    """
    def __init__(self, *args, **kwargs):
        self._exceptions: List[tuple] = []
        self._repr: Optional[str] = None
        self._exc_msg_args = []
        super(ExceptionChainer, self).__init__(*args, **kwargs)

    def __repr__(self):
        # Since generating the representation can be slow we cache it
        if not self._repr:
            tracebacks = (
                ''.join(traceback.format_exception(*e)).replace('\n', '\n\t')
                for e in self._exceptions)
            self._repr = '\n'.join('\nChained Exception #%s\n\t%s' % (i + 1, t)
                                   for i, t in enumerate(tracebacks))
        return self._repr

    __str__ = __repr__

    def __nonzero__(self) -> bool:
        # We want to be able to do boolean checks on the exception
        return bool(self._exceptions)

    __bool__ = __nonzero__  # For Python 3

    def add_exception(self, exc_type, exc_val, exc_tb) -> None:
        # Clear the representation cache
        self._repr = None
        self._exceptions.append((exc_type, exc_val, exc_tb))

    def context(self,
                catch_exception: bool,
                msg: str = '',
                *msg_args: Iterable):
        self._catch_exception = catch_exception
        self._exc_msg = msg
        self._exc_msg_args = list(msg_args)
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.add_exception(exc_type, exc_val, exc_tb)
            if self._exc_msg:
                LOG.warning(self._exc_msg, *self._exc_msg_args)
            if self._catch_exception:
                return True


class ExecutionTimeout(putils.ProcessExecutionError):
    pass
