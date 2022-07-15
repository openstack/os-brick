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

import json
import os
import urllib

from oslo_log import log as logging
import requests

from os_brick import exception
from os_brick.i18n import _
from os_brick import initiator
from os_brick.initiator.connectors import base
from os_brick.privileged import scaleio as priv_scaleio
from os_brick import utils

LOG = logging.getLogger(__name__)
DEVICE_SCAN_ATTEMPTS_DEFAULT = 3
CONNECTOR_CONF_PATH = '/opt/emc/scaleio/openstack/connector.conf'


def io(_type, nr):
    """Implementation of _IO macro from <sys/ioctl.h>."""

    return ioc(0x0, _type, nr, 0)


def ioc(direction, _type, nr, size):
    """Implementation of _IOC macro from <sys/ioctl.h>."""

    return direction | (size & 0x1fff) << 16 | ord(_type) << 8 | nr


class ScaleIOConnector(base.BaseLinuxConnector):
    """Class implements the connector driver for ScaleIO."""

    OK_STATUS_CODE = 200
    VOLUME_NOT_MAPPED_ERROR = 84
    VOLUME_ALREADY_MAPPED_ERROR = 81
    GET_GUID_OP_CODE = io('a', 14)
    RESCAN_VOLS_OP_CODE = io('a', 10)

    def __init__(self, root_helper, driver=None,
                 device_scan_attempts=initiator.DEVICE_SCAN_ATTEMPTS_DEFAULT,
                 *args, **kwargs):
        super(ScaleIOConnector, self).__init__(
            root_helper,
            driver=driver,
            device_scan_attempts=device_scan_attempts,
            *args, **kwargs
        )

        self.local_sdc_ip = None
        self.server_ip = None
        self.server_port = None
        self.server_username = None
        self.server_password = None
        self.server_token = None
        self.volume_id = None
        self.volume_name = None
        self.volume_path = None
        self.iops_limit = None
        self.bandwidth_limit = None
        self.verify_certificate = None
        self.certificate_path = None

    def _get_guid(self):
        try:
            guid = priv_scaleio.get_guid(self.GET_GUID_OP_CODE)
            LOG.info("Current sdc guid: %s", guid)
            return guid
        except (IOError, OSError, ValueError) as e:
            msg = _("Error querying sdc guid: %s") % e
            LOG.error(msg)
            raise exception.BrickException(message=msg)

    @staticmethod
    def _get_password_token(connection_properties):
        # In old connection format we had the password and token in properties
        if 'serverPassword' in connection_properties:
            return (connection_properties['serverPassword'],
                    connection_properties['serverToken'])

        # The new format reads password from file and doesn't have the token
        LOG.info("Get ScaleIO connector password from configuration file")
        try:
            password = priv_scaleio.get_connector_password(
                CONNECTOR_CONF_PATH,
                connection_properties['config_group'],
                connection_properties.get('failed_over', False))
            return password, None
        except Exception as e:
            msg = _("Error getting ScaleIO connector password from "
                    "configuration file: %s") % e
            LOG.error(msg)
            raise exception.BrickException(message=msg)

    def _rescan_vols(self):
        LOG.info("ScaleIO rescan volumes")

        try:
            priv_scaleio.rescan_vols(self.RESCAN_VOLS_OP_CODE)
        except (IOError, OSError) as e:
            msg = _("Error querying volumes: %s") % e
            LOG.error(msg)
            raise exception.BrickException(message=msg)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The ScaleIO connector properties."""
        return {}

    def get_search_path(self):
        return "/dev/disk/by-id"

    def get_volume_paths(self, connection_properties):
        self.get_config(connection_properties)
        volume_paths = []
        device_paths = [self._find_volume_path()]
        for path in device_paths:
            if os.path.exists(path):
                volume_paths.append(path)
        return volume_paths

    def _find_volume_path(self):
        LOG.info(
            "Looking for volume %(volume_id)s, maximum tries: %(tries)s",
            {'volume_id': self.volume_id, 'tries': self.device_scan_attempts}
        )

        # look for the volume in /dev/disk/by-id directory
        by_id_path = self.get_search_path()

        disk_filename = self._wait_for_volume_path(by_id_path)
        full_disk_name = ("%(path)s/%(filename)s" %
                          {'path': by_id_path, 'filename': disk_filename})
        LOG.info("Full disk name is %(full_path)s",
                 {'full_path': full_disk_name})
        return full_disk_name

    # NOTE: Usually 3 retries is enough to find the volume.
    # If there are network issues, it could take much longer. Set
    # the max retries to 15 to make sure we can find the volume.
    @utils.retry(exception.BrickException,
                 retries=15,
                 backoff_rate=1)
    def _wait_for_volume_path(self, path):
        if not os.path.isdir(path):
            msg = (
                _("ScaleIO volume %(volume_id)s not found at "
                  "expected path.") % {'volume_id': self.volume_id}
            )

            LOG.debug(msg)
            raise exception.BrickException(message=msg)

        disk_filename = None
        filenames = os.listdir(path)
        LOG.info(
            "Files found in %(path)s path: %(files)s ",
            {'path': path, 'files': filenames}
        )

        for filename in filenames:
            if (filename.startswith("emc-vol") and
                    filename.endswith(self.volume_id)):
                disk_filename = filename
                break

        if not disk_filename:
            msg = (_("ScaleIO volume %(volume_id)s not found.") %
                   {'volume_id': self.volume_id})
            LOG.debug(msg)
            raise exception.BrickException(message=msg)

        return disk_filename

    def _get_client_id(self):
        request = (
            "https://%(server_ip)s:%(server_port)s/"
            "api/types/Client/instances/getByIp::%(sdc_ip)s/" %
            {
                'server_ip': self.server_ip,
                'server_port': self.server_port,
                'sdc_ip': self.local_sdc_ip
            }
        )

        LOG.info("ScaleIO get client id by ip request: %(request)s",
                 {'request': request})

        r = requests.get(
            request,
            auth=(self.server_username, self.server_token),
            verify=self._verify_cert()
        )

        r = self._check_response(r, request)
        sdc_id = r.json()
        if not sdc_id:
            msg = (_("Client with ip %(sdc_ip)s was not found.") %
                   {'sdc_ip': self.local_sdc_ip})
            raise exception.BrickException(message=msg)

        if r.status_code != 200 and "errorCode" in sdc_id:
            msg = (_("Error getting sdc id from ip %(sdc_ip)s: %(err)s") %
                   {'sdc_ip': self.local_sdc_ip, 'err': sdc_id['message']})

            LOG.error(msg)
            raise exception.BrickException(message=msg)

        LOG.info("ScaleIO sdc id is %(sdc_id)s.",
                 {'sdc_id': sdc_id})
        return sdc_id

    def _get_volume_id(self):
        volname_encoded = urllib.parse.quote(self.volume_name, '')
        volname_double_encoded = urllib.parse.quote(volname_encoded, '')
        LOG.debug(_(
            "Volume name after double encoding is %(volume_name)s."),
            {'volume_name': volname_double_encoded}
        )

        request = (
            "https://%(server_ip)s:%(server_port)s/api/types/Volume/instances"
            "/getByName::%(encoded_volume_name)s" %
            {
                'server_ip': self.server_ip,
                'server_port': self.server_port,
                'encoded_volume_name': volname_double_encoded
            }
        )

        LOG.info(
            "ScaleIO get volume id by name request: %(request)s",
            {'request': request}
        )

        r = requests.get(request,
                         auth=(self.server_username, self.server_token),
                         verify=self._verify_cert())

        r = self._check_response(r, request)

        volume_id = r.json()
        if not volume_id:
            msg = (_("Volume with name %(volume_name)s wasn't found.") %
                   {'volume_name': self.volume_name})

            LOG.error(msg)
            raise exception.BrickException(message=msg)

        if r.status_code != self.OK_STATUS_CODE and "errorCode" in volume_id:
            msg = (
                _("Error getting volume id from name %(volume_name)s: "
                  "%(err)s") %
                {'volume_name': self.volume_name, 'err': volume_id['message']}
            )

            LOG.error(msg)
            raise exception.BrickException(message=msg)

        LOG.info("ScaleIO volume id is %(volume_id)s.",
                 {'volume_id': volume_id})
        return volume_id

    def _check_response(self, response, request, is_get_request=True,
                        params=None):
        if response.status_code == 401 or response.status_code == 403:
            LOG.info("Token is invalid, "
                     "going to re-login to get a new one")

            login_request = (
                "https://%(server_ip)s:%(server_port)s/api/login" %
                {'server_ip': self.server_ip, 'server_port': self.server_port}
            )

            r = requests.get(
                login_request,
                auth=(self.server_username, self.server_password),
                verify=self._verify_cert()
            )

            token = r.json()
            # repeat request with valid token
            LOG.debug(_("Going to perform request %(request)s again "
                        "with valid token"), {'request': request})

            if is_get_request:
                res = requests.get(request,
                                   auth=(self.server_username, token),
                                   verify=self._verify_cert())
            else:
                headers = {'content-type': 'application/json'}
                res = requests.post(
                    request,
                    data=json.dumps(params),
                    headers=headers,
                    auth=(self.server_username, token),
                    verify=self._verify_cert()
                )

            self.server_token = token
            return res

        return response

    def _verify_cert(self):
        verify_cert = self.verify_certificate
        if self.verify_certificate and self.certificate_path:
            verify_cert = self.certificate_path
        return verify_cert

    def get_config(self, connection_properties):
        self.local_sdc_ip = connection_properties['hostIP']
        self.volume_name = connection_properties['scaleIO_volname']
        # instances which were created before Newton release don't have
        # 'scaleIO_volume_id' property, in such cases connector will resolve
        # volume_id from volname
        self.volume_id = connection_properties.get('scaleIO_volume_id')
        self.server_ip = connection_properties['serverIP']
        self.server_port = connection_properties['serverPort']
        self.server_username = connection_properties['serverUsername']
        self.server_password, self.server_token = self._get_password_token(
            connection_properties)
        self.iops_limit = connection_properties['iopsLimit']
        self.bandwidth_limit = connection_properties['bandwidthLimit']
        self.verify_certificate = (
            connection_properties.get('verify_certificate')
        )
        self.certificate_path = connection_properties.get('certificate_path')
        device_info = {'type': 'block',
                       'path': self.volume_path}
        return device_info

    @utils.trace
    @utils.connect_volume_prepare_result
    @base.synchronized('scaleio', 'scaleio-', external=True)
    def connect_volume(self, connection_properties):
        """Connect the volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :returns: dict
        """
        device_info = self.get_config(connection_properties)
        LOG.debug(
            _(
                "scaleIO Volume name: %(volume_name)s, SDC IP: %(sdc_ip)s, "
                "REST Server IP: %(server_ip)s, "
                "REST Server username: %(username)s, "
                "iops limit: %(iops_limit)s, "
                "bandwidth limit: %(bandwidth_limit)s."
            ), {
                'volume_name': self.volume_name,
                'volume_id': self.volume_id,
                'sdc_ip': self.local_sdc_ip,
                'server_ip': self.server_ip,
                'username': self.server_username,
                'iops_limit': self.iops_limit,
                'bandwidth_limit': self.bandwidth_limit
            }
        )

        guid = self._get_guid()
        params = {'guid': guid, 'allowMultipleMappings': 'TRUE'}
        self.volume_id = self.volume_id or self._get_volume_id()

        headers = {'content-type': 'application/json'}
        request = (
            "https://%(server_ip)s:%(server_port)s/api/instances/"
            "Volume::%(volume_id)s/action/addMappedSdc" %
            {'server_ip': self.server_ip, 'server_port': self.server_port,
             'volume_id': self.volume_id}
        )

        LOG.info("map volume request: %(request)s", {'request': request})
        r = requests.post(
            request,
            data=json.dumps(params),
            headers=headers,
            auth=(self.server_username, self.server_token),
            verify=self._verify_cert()
        )

        r = self._check_response(r, request, False, params)
        if r.status_code != self.OK_STATUS_CODE:
            response = r.json()
            error_code = response['errorCode']
            if error_code == self.VOLUME_ALREADY_MAPPED_ERROR:
                LOG.warning(
                    "Ignoring error mapping volume %(volume_name)s: "
                    "volume already mapped.",
                    {'volume_name': self.volume_name}
                )
            else:
                msg = (
                    _("Error mapping volume %(volume_name)s: %(err)s") %
                    {'volume_name': self.volume_name,
                     'err': response['message']}
                )

                LOG.error(msg)
                raise exception.BrickException(message=msg)

        self.volume_path = self._find_volume_path()
        device_info['path'] = self.volume_path

        # Set QoS settings after map was performed
        if self.iops_limit is not None or self.bandwidth_limit is not None:
            params = {'guid': guid}
            if self.bandwidth_limit is not None:
                params['bandwidthLimitInKbps'] = self.bandwidth_limit
            if self.iops_limit is not None:
                params['iopsLimit'] = self.iops_limit

            request = (
                "https://%(server_ip)s:%(server_port)s/api/instances/"
                "Volume::%(volume_id)s/action/setMappedSdcLimits" %
                {'server_ip': self.server_ip, 'server_port': self.server_port,
                 'volume_id': self.volume_id}
            )

            LOG.info("Set client limit request: %(request)s",
                     {'request': request})

            r = requests.post(
                request,
                data=json.dumps(params),
                headers=headers,
                auth=(self.server_username, self.server_token),
                verify=self._verify_cert()
            )
            r = self._check_response(r, request, False, params)
            if r.status_code != self.OK_STATUS_CODE:
                response = r.json()
                LOG.info("Set client limit response: %(response)s",
                         {'response': response})
                msg = (
                    _("Error setting client limits for volume "
                      "%(volume_name)s: %(err)s") %
                    {'volume_name': self.volume_name,
                     'err': response['message']}
                )

                LOG.error(msg)

        return device_info

    @utils.trace
    @base.synchronized('scaleio', 'scaleio-', external=True)
    @utils.connect_volume_undo_prepare_result(unlink_after=True)
    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        """Disconnect the ScaleIO volume.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        :param device_info: historical difference, but same as connection_props
        :type device_info: dict
        :type force: bool
        :param ignore_errors: When force is True, this will decide whether to
                              ignore errors or raise an exception once finished
                              the operation.  Default is False.
        """
        self.get_config(connection_properties)
        self.volume_id = self.volume_id or self._get_volume_id()
        LOG.info(
            "ScaleIO disconnect volume in ScaleIO brick volume driver."
        )

        LOG.debug(
            _("ScaleIO Volume name: %(volume_name)s, SDC IP: %(sdc_ip)s, "
              "REST Server IP: %(server_ip)s"),
            {'volume_name': self.volume_name, 'sdc_ip': self.local_sdc_ip,
             'server_ip': self.server_ip}
        )

        guid = self._get_guid()
        params = {'guid': guid}
        headers = {'content-type': 'application/json'}
        request = (
            "https://%(server_ip)s:%(server_port)s/api/instances/"
            "Volume::%(volume_id)s/action/removeMappedSdc" %
            {'server_ip': self.server_ip, 'server_port': self.server_port,
             'volume_id': self.volume_id}
        )

        LOG.info("Unmap volume request: %(request)s",
                 {'request': request})
        r = requests.post(
            request,
            data=json.dumps(params),
            headers=headers,
            auth=(self.server_username, self.server_token),
            verify=self._verify_cert()
        )

        r = self._check_response(r, request, False, params)
        if r.status_code != self.OK_STATUS_CODE:
            response = r.json()
            error_code = response['errorCode']
            if error_code == self.VOLUME_NOT_MAPPED_ERROR:
                LOG.warning(
                    "Ignoring error unmapping volume %(volume_id)s: "
                    "volume not mapped.", {'volume_id': self.volume_name}
                )
            else:
                msg = (_("Error unmapping volume %(volume_id)s: %(err)s") %
                       {'volume_id': self.volume_name,
                        'err': response['message']})
                LOG.error(msg)
                raise exception.BrickException(message=msg)

    @utils.connect_volume_undo_prepare_result
    def extend_volume(self, connection_properties):
        """Update the local kernel's size information.

        Try and update the local kernel's size information
        for a ScaleIO volume.
        """

        self._rescan_vols()
        volume_paths = self.get_volume_paths(connection_properties)
        if volume_paths:
            return self.get_device_size(volume_paths[0])

        # if we got here, the volume is not mapped
        msg = (_("Error extending ScaleIO volume"))
        LOG.error(msg)
        raise exception.BrickException(message=msg)

    def get_device_size(self, device):
        """Get the size in bytes of a volume."""
        (out, _err) = self._execute('blockdev', '--getsize64',
                                    device, run_as_root=True,
                                    root_helper=self._root_helper)
        var = str(out.strip())
        LOG.debug("Device %(dev)s size: %(var)s",
                  {'dev': device, 'var': var})
        if var.isnumeric():
            return int(var)
        else:
            return None
