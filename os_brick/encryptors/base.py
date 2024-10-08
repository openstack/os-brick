# Copyright (c) 2013 The Johns Hopkins University/Applied Physics Laboratory
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


import abc

from os_brick import executor
from os_brick import utils


class VolumeEncryptor(executor.Executor, metaclass=abc.ABCMeta):
    """Base class to support encrypted volumes.

    A VolumeEncryptor provides hooks for attaching and detaching volumes, which
    are called immediately prior to attaching the volume to an instance and
    immediately following detaching the volume from an instance. This class
    performs no actions for either hook.
    """

    def __init__(self, root_helper,
                 connection_info,
                 keymgr,
                 execute=None,
                 *args, **kwargs):
        super(VolumeEncryptor, self).__init__(root_helper,
                                              execute=execute,
                                              *args, **kwargs)
        self._key_manager = keymgr

        self.encryption_key_id = kwargs.get('encryption_key_id')

    def _get_key(self, context):
        """Retrieves the encryption key for the specified volume.

        :param: the connection information used to attach the volume
        """
        return self._key_manager.get(context, self.encryption_key_id)

    def _get_encryption_key_as_passphrase(self, context):
        key = self._get_key(context)
        return utils.get_passphrase_from_secret(key)

    @abc.abstractmethod
    def attach_volume(self, context, **kwargs):
        """Hook called immediately prior to attaching a volume to an instance.

        """
        pass

    @abc.abstractmethod
    def detach_volume(self, **kwargs):
        """Hook called immediately after detaching a volume from an instance.

        """
        pass

    @abc.abstractmethod
    def extend_volume(self, context, **kwargs):
        """Extend an encrypted volume and return the decrypted volume size."""
        pass
