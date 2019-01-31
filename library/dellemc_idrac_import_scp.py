#! /usr/bin/python
# _*_ coding: utf-8 _*_

#
# Dell EMC OpenManage Ansible Modules
# Version BETA
#
# Copyright (C) 2018 Dell Inc.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# All rights reserved. Dell, EMC, and other trademarks are trademarks of Dell Inc. or its subsidiaries.
# Other trademarks may be trademarks of their respective owners.
#

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: dellemc_idrac_import_scp
short_description: Import SCP from a network share
version_added: "2.3"
description:
    - Import a given Server Configuration Profile (SCP) file from a network share
options:
  idrac_ip:
    required: True
    description:
      - iDRAC IP Address
    type: 'str'
  idrac_user:
    required: True
    description:
      - iDRAC user name
    type: 'str'
  idrac_pwd:
    required: True
    description:
      - iDRAC user password
    type: 'str'
  idrac_port:
    required: False
    description:
      - iDRAC port
    default: 443
    type: 'int'
  share_name:
    required: True
    description:
      - Local directory path or a Remote Network file share (either CIFS or NFS)
    type: 'str'
  share_user:
    required: False
    description:
      - Network share user in the format 'user@domain' if user is part of a domain else 'user'
    type: 'str'
  share_pwd:
    required: False
    description:
      - Network share user password
    type: 'str'
  share_mnt:
    required: False
    description:
      - Local mount path of the network file share specified in I(share_name) with read-write permission for ansible user
    type: 'path'
  scp_file:
    required: True
    description:
      - Server Configuration Profile file name relative to I(share_mnt)
    default: None
    type: 'str'
  scp_components:
    required: False
    description:
      - if C(ALL), will import all components configurations from SCP file
      - if C(IDRAC), will import iDRAC comfiguration from SCP file
      - if C(BIOS), will import BIOS configuration from SCP file
      - if C(NIC), will import NIC configuration from SCP file
      - if C(RAID), will import RAID configuration from SCP file
    choices: ['ALL', 'IDRAC', 'BIOS', 'NIC', 'RAID']
    default: 'ALL'
  end_host_power_state:
    required: False
    description:
      - if C(On), host's power state after importing the SCP will be ON
      - if C(Off), host's power state after importing the SCP will be OFF
    choices: ["On", "Off"]
    type: 'str'
    default: "On"
  shutdown_type:
    required: False
    description:
      - if C(Graceful), will gracefully shut down the server
      - if C(Forced), will do a forced shutdown of the server
      - if C(NoReboot), will not reboot the server
    choices: ["Graceful", "Forced", "NoReboot"]
    type: 'str'
    default: "Graceful"
  job_wait:
    required: False
    description:
     - if C(True), wait for the import scp job to be completed and return the status
     - if C(False), return immediately after creating a import scp job
    default: True
    type: 'bool'

requirements: ['Dell EMC OpenManage Python SDK']
author: "anupam.aloke@dell.com"
'''

EXAMPLES = '''
# Import Server Configuration Profile from a local path
# Following play will import a SCP file named 'scp_file.xml' from the local path
# '/home/user' by sending the contents of the file in the https message to iDRAC
- name: Import Server Configuration Profile
  dellemc_idrac_import_scp:
    idrac_ip:              "192.168.1.1"
    idrac_user:            "username"
    idrac_pwd:             "pword"
    share_name:            "/home/user"
    scp_file:              "scp_file.xml"
    scp_components:        "ALL"
    end_host_power_state:  "On"
    shutdown_type:         "Graceful"
    job_wait:              True

# Import Server Configuration Profile from a CIFS Network Share
- name: Import Server Configuration Profile
    dellemc_idrac_import_scp:
      idrac_ip:         "192.168.1.1"
      idrac_user:       "username"
      idrac_pwd:        "pword"
      share_name:       "\\\\192.168.10.10\\share"
      share_user:       "user1"
      share_pwd:        "password"
      share_mnt:        "/mnt/share"
      scp_file:         "scp_file.xml"
      scp_components:   "ALL"
      end_host_power_state: "On"
      shutdown_type:    "Graceful"
      job_wait:         True

# Import Server Configuration Profile from a NFS Network Share
- name: Import Server Configuration Profile
    dellemc_idrac_import_scp:
      idrac_ip:             "192.168.1.1"
      idrac_user:           "username"
      idrac_pwd:            "pword"
      share_name:           "192.168.10.10:/share"
      share_user:           "user1"
      share_pwd:            "password"
      share_mnt:            "/mnt/share"
      scp_file:             "scp_file.xml"
      scp_components:       "ALL"
      end_host_power_state: "On"
      shutdown_type:        "Graceful"
      job_wait:             True
'''

RETURN = '''
---
'''

from ansible.module_utils.dellemc_idrac import iDRACConnection
from ansible.module_utils.basic import AnsibleModule
try:
    from omsdk.sdkcreds import UserCredentials
    from omsdk.sdkfile import FileOnShare, file_share_manager
    from omsdk.sdkcenum import TypeHelper
    from omdrivers.enums.iDRAC.iDRACEnums import (
            EndHostPowerStateEnum, SCPTargetEnum, ShutdownTypeEnum
    )
    HAS_OMSDK = True
except ImportError:
    HAS_OMSDK = False


def import_server_config_profile(idrac, module):
    """
    Import Server Configuration Profile from a network share

    Keyword arguments:
    idrac  -- iDRAC handle
    module -- Ansible module
    """

    msg = {}
    msg['changed'] = False
    msg['failed'] = False
    msg['msg'] = {}
    err = False

    try:
        if module.check_mode:
            msg['changed'] = True
        else:
            myshare = file_share_manager.create_share_obj(
                          share_path=module.params['share_name'],
                          creds=UserCredentials(module.params['share_user'],
                                                module.params['share_pwd']),
                          isFolder=True)
            scp_file_path = myshare.new_file(module.params['scp_file'])

            scp_components = TypeHelper.convert_to_enum(
                                 module.params["scp_components"], SCPTargetEnum)

            host_power_state = TypeHelper.convert_to_enum(
                                   module.params["end_host_power_state"],
                                   EndHostPowerStateEnum)

            shutdown_type = TypeHelper.convert_to_enum(
                                module.params["shutdown_type"], ShutdownTypeEnum)

            msg['msg'] = idrac.config_mgr.scp_import(
                                              share_path=scp_file_path,
                                              target=scp_components,
                                              shutdown_type=shutdown_type,
                                              end_host_power_state=host_power_state,
                                              job_wait=module.params['job_wait'])

            if "Status" in msg['msg']:
                if msg['msg']['Status'] == "Success":
                    msg['changed'] = True
                    if "Message" in msg['msg'] and \
                            "No changes were applied" in msg['msg']['Message']:
                        msg['changed'] = False
                else:
                    msg['failed'] = True

    except Exception as e:
        err = True
        msg['msg'] = "Error: %s" % str(e)
        msg['failed'] = True

    return msg, err

# Main
def main():

    module = AnsibleModule(
        argument_spec=dict(

            # iDRAC handle
            idrac=dict(required=False, type='dict'),

            # iDRAC Credentials
            idrac_ip=dict(required=True, type='str'),
            idrac_user=dict(required=True, type='str'),
            idrac_pwd=dict(required=True, type='str', no_log=True),
            idrac_port=dict(required=False, default=443, type='int'),

            # Network File Share
            share_name=dict(required=True, type='str'),
            share_user=dict(required=False, type='str'),
            share_pwd=dict(required=False, type='str', no_log=True),
            share_mnt=dict(required=False, type='path'),

            scp_file=dict(required=True, type='str'),
            scp_components=dict(required=False,
                                choices=['ALL', 'IDRAC', 'BIOS', 'NIC', 'RAID'],
                                default='ALL'),
            end_host_power_state=dict(required=False, choices=["On", "Off"],
                                      default="On", type='str'),
            shutdown_type=dict(required=False,
                               choices=["Graceful", "Forced", "NoReboot"],
                               default="Graceful", type='str'),
            job_wait=dict(required=False, default=True, type='bool')
        ),

        supports_check_mode=True)

    if not HAS_OMSDK:
        module.fail_json(msg="Dell EMC OpenManage Python SDK required for this module")

    # Connect to iDRAC
    idrac_conn = iDRACConnection(module)
    idrac = idrac_conn.connect()

    msg, err = import_server_config_profile(idrac, module)

    # Disconnect from iDRAC
    idrac_conn.disconnect()

    if err:
        module.fail_json(**msg)
    module.exit_json(**msg)

if __name__ == '__main__':
    main()
