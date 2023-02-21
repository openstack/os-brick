# Copyright (c) 2023, Red Hat, Inc.
# All Rights Reserved.
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

# Valid SCSI addressing values for 'addressing_mode' in connection info.
# More information in os_bric.initiator.linuxscsi.LinuxSCSI.lun_for_addressing
SCSI_ADDRESSING_TRANSPARENT = 'transparent'
SCSI_ADDRESSING_SAM = 'SAM'
SCSI_ADDRESSING_SAM2 = 'SAM2'
SCSI_ADDRESSING_SAM3_FLAT = 'SAM3-flat'

SCSI_ADDRESSING_MODES = (SCSI_ADDRESSING_TRANSPARENT,
                         SCSI_ADDRESSING_SAM,
                         SCSI_ADDRESSING_SAM2,
                         SCSI_ADDRESSING_SAM3_FLAT)
