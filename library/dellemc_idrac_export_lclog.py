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
module: dellemc_idrac_export_lclog
short_description: Export Lifecycle Controller log file to a network share
version_added: "2.3"
description:
    - Export Lifecycle Controller log file to a given network s/hare
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
    required: True
    description:
      - Network share user in the format 'user@domain' if user is part of a domain else 'user'
    type: 'str'
  share_pwd:
    required: True
    description:
      - Network share user password
    type: 'str'
  job_wait:
    required: False
    description:
      - If C(True), then will wait for Lifecycle Log export job to finish and return the job completion status
      - if C(False), then will return immediately with a JOB ID after queueing tthe Lifecycle Log export job in the LC job queue
    type: 'bool'
    default: True

requirements: ['Dell EMC OpenManage Python SDK']
author: "anupam.aloke@dell.com"
'''

EXAMPLES = '''
---
- name: Export Lifecycle Controller Log
    dellemc_idrac_export_lclog:
      idrac_ip:   "192.168.1.1"
      idrac_user: "username"
      idrac_pwd:  "pword"
      share_name: "\\\\192.168.10.10\\share\\"
      share_user: "user1"
      share_pwd:  "password"
'''

RETURN = '''
---
'''

from ansible.module_utils.dellemc_idrac import iDRACConnection
from ansible.module_utils.basic import AnsibleModule
try:
    from omsdk.sdkcreds import UserCredentials
    from omsdk.sdkfile import FileOnShare, file_share_manager
    HAS_OMSDK = True
except ImportError:
    HAS_OMSDK = False

def export_lc_logs(idrac, module):
    """
    Export Lifecycle Controller Log to the given file share

    Keyword arguments:
    idrac  -- iDRAC handle
    module -- Ansible module
    """

    msg = {}
    msg['changed'] = False
    msg['failed'] = False
    err = False

    try:
        lclog_file_name_format = "%ip_%Y%m%d_%H%M%S_LC_Log.log"

        myshare = file_share_manager.create_share_obj(
                    share_path=module.params['share_name'],
                    creds=UserCredentials(module.params['share_user'],
                                          module.params['share_pwd']),
                    isFolder=True)

        lc_log_file = myshare.new_file(lclog_file_name_format)

        msg['msg'] = idrac.log_mgr.lclog_export(lc_log_file)

        if "Status" in msg['msg'] and msg['msg']['Status'] != "Success":
            msg['failed'] = True

    except Exception as e:
        err = True
        msg['msg'] = "Error: %s" % str(e)
        msg['failed'] = True

    return msg, err

# Main()
def main():

    module = AnsibleModule(
        argument_spec=dict(

            # iDRAC handle
            idrac=dict(required=False, type='dict'),

            # iDRAC credentials
            idrac_ip=dict(required=True, type='str'),
            idrac_user=dict(required=True, type='str'),
            idrac_pwd=dict(required=True, type='str', no_log=True),
            idrac_port=dict(required=False, default=443, type='int'),

            # Network File Share
            share_name=dict(required=True, type='str'),
            share_user=dict(required=True, type='str'),
            share_pwd=dict(required=True, type='str', no_log=True),

            # Job wait
            job_wait=dict(required=False, default=True, type='bool')
        ),
        supports_check_mode=True)

    if not HAS_OMSDK:
        module.fail_json(msg="Dell EMC OpenManage Python SDK required for this module")

    # Connect to iDRAC
    idrac_conn = iDRACConnection(module)
    idrac = idrac_conn.connect()

    # Export LC Logs
    msg, err = export_lc_logs(idrac, module)

    # Disconnect from iDRAC
    idrac_conn.disconnect()

    if err:
        module.fail_json(**msg)
    module.exit_json(**msg)

if __name__ == '__main__':
    main()
