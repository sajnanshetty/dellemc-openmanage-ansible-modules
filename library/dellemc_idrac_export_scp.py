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
module: dellemc_idrac_export_scp
short_description: Export Server Configuration Profile (SCP) to remote network share or local file
version_added: "2.3"
description:
    - Export Server Configuration Profile to a given network share (CIFS, NFS) or local file
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
      - CIFS or NFS Network share
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
  scp_components:
    required: False
    description:
      - if C(ALL), will export all components configurations in SCP file
      - if C(IDRAC), will export iDRAC configuration in SCP file
      - if C(BIOS), will export BIOS configuration in SCP file
      - if C(NIC), will export NIC configuration in SCP file
      - if C(RAID), will export RAID configuration in SCP file
    choices: ['ALL', 'IDRAC', 'BIOS', 'NIC', 'RAID']
    default: 'ALL'
  export_format:
    required: False
    description:
      - if C(XML), will export the SCP in XML format
      - if C(JSON), will export the SCP in JSON format
    choices: ['XML', 'JSON']
    default: 'XML'
  export_use:
    required: False
    description:
      - if C(Default), will export the SCP using default method
      - if C(Clone), will export the SCP using clone method
      - if C(Replace), will export the SCP using Replace method
    choices: ['Default', 'Clone', 'Replace']
    default: 'Default'
  job_wait:
    required: False
    description:
      - if C(True), will wait for the SCP export job to finish and return the job completion status
      - if C(False), will return immediately with a JOB ID after queueing the SCP export jon in LC job queue
    type: 'bool'
    default: True

requirements: ['omsdk']
author: "anupam.aloke@dell.com"
'''

EXAMPLES = '''
# Export SCP to a CIFS network share
- name: Export Server Configuration Profile (SCP)
  dellemc_idrac_export_scp:
    idrac_ip:   "192.168.1.1"
    idrac_user: "username"
    idrac_pwd:  "pword"
    share_name: "\\\\192.168.10.10\\share"
    share_user: "user1"
    share_pwd:  "password"

# Export SCP to a NFS network share
- name: Export Server Configuration Profile (SCP)
  dellemc_idrac_export_scp:
    idrac_ip:   "192.168.1.1"
    idrac_user: "username"
    idrac_pwd:  "pword"
    share_name: "192.168.10.10:/share"
    share_user: "user1"
    share_pwd:  "password"

# Export SCP to a local file
- name: Export Server Configuration Profile (SCP)
  dellemc_idrac_export_scp:
    idrac_ip:   "192.168.1.1"
    idrac_user: "username"
    idrac_pwd:  "pword"
    share_name: "/home/user"
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
        ExportFormatEnum, ExportUseEnum, SCPTargetEnum
    )
    HAS_OMSDK = True
except ImportError:
    HAS_OMSDK = False

def export_server_config_profile(idrac, module):
    """
    Export Server Configuration Profile to a network share

    Keyword arguments:
    idrac  -- iDRAC handle
    module -- Ansible module
    """

    msg = {}
    msg['changed'] = False
    msg['failed'] = False
    err = False

    try:
        scp_file_name_format = "%ip_%Y%m%d_%H%M%S_" + \
                               module.params['scp_components'] + "_SCP"

        export_format = ExportFormatEnum.XML
        if module.params['export_format'] == 'JSON':
            scp_file_name_format += ".{}".format("json")
            export_format = ExportFormatEnum.JSON
        else:
            scp_file_name_format += ".{}".format("xml")

        myshare = file_share_manager.create_share_obj(
                share_path=module.params['share_name'],
                creds=UserCredentials(module.params['share_user'],
                                      module.params['share_pwd']),
                isFolder=True)

        scp_file_name = myshare.new_file(scp_file_name_format)

        target = TypeHelper.convert_to_enum(module.params['scp_components'],
                                            SCPTargetEnum)

        export_use = ExportUseEnum.Default
        if module.params['export_use'] == 'Clone':
            export_use = ExportUseEnum.Clone
        elif module.params['export_use'] == 'Replace':
            export_use = ExportUseEnum.Replace

        msg['msg'] = idrac.config_mgr.scp_export(share_path=scp_file_name,
                                                 target=target,
                                                 export_format=export_format,
                                                 export_use=export_use,
                                                 job_wait=module.params['job_wait'])

        if 'Status' in msg['msg'] and msg['msg']['Status'] != "Success":
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

            # iDRAC Handle
            idrac=dict(required=False, type='dict'),

            # iDRAC credentials
            idrac_ip=dict(required=True, type='str'),
            idrac_user=dict(required=True, type='str'),
            idrac_pwd=dict(required=True, type='str', no_log=True),
            idrac_port=dict(required=False, default=443, type='int'),

            # Network File Share
            share_name=dict(required=True, type='str'),
            share_pwd=dict(required=False, type='str', no_log=True),
            share_user=dict(required=False, type='str'),

            scp_components=dict(required=False,
                                choices=['ALL', 'IDRAC', 'BIOS', 'NIC', 'RAID'],
                                default='ALL', type='str'),
            export_format=dict(required=False, choices=['XML', 'JSON'],
                               default='XML'),
            export_use=dict(required=False,
                            choices=['Default', 'Clone', 'Replace'],
                            default='Default'),
            job_wait=dict(required=False, default=True, type='bool')
        ),

        supports_check_mode=True)

    if not HAS_OMSDK:
        module.fail_json(msg="Dell EMC OpenManage Python SDK required for this module")

    # Connect to iDRAC
    idrac_conn = iDRACConnection(module)
    idrac = idrac_conn.connect()

    # Export Server Configuration Profile
    msg, err = export_server_config_profile(idrac, module)

    # Disconnect from iDRAC
    idrac_conn.disconnect()

    if err:
        module.fail_json(**msg)
    module.exit_json(**msg)


if __name__ == '__main__':
    main()
