#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell EMC OpenManage Ansible Modules
# Version 2.0
# Copyright (C) 2019 Dell Inc. or its subsidiaries. All Rights reserved.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: idrac_firmware
short_description: Firmware update using a repository hosted on a remote network share (CIFS, NFS) or a URL (HTTP, HTTPS, FTP)
version_added: "2.8"
description:
  - Update the Firmware by connecting to a network repository (CIFS, NFS, HTTP,
    HTTPS, FTP) that contains a catalog of available updates and the Dell EMC
    Update Packages (DUPs).
  - Remote network share or URL should contain a valid repository of Dell EMC
    Update Packages (DUPs) and a catalog file describing the DUPs.
  - All applicable updates described in the catalog file and contained in the
    repository are applied to the system.
  - This feature is only available with iDRAC Enterprise License.
options:
  idrac_ip:
    description:
      - iDRAC IP Address
    required: True
    type: 'str'
  idrac_user:
    description:
      - iDRAC user name
    required: True
    type: 'str'
  idrac_password:
    description:
      - iDRAC user password
    required: True
    type: 'str'
    aliases: ['idrac_pwd']
  idrac_port:
    description:
      - iDRAC port
    required: False
    default: 443
    type: 'int'
  share_name:
    description:
      - Network share (CIFS, NFS, HTTP, HTTPS, FTP) containing the Catalog file
        and Dell EMC Update Packages (DUPs).
    required: True
    type: 'str'
  share_user:
    description:
      - Network share user in the format 'user@domain' or 'domain\\user' if
        user is part of a domain else 'user'. This option is mandatory if
        I(share_name) is a CIFS share.
    required: False
    type: 'str'
  share_password:
    description:
      - Network share user password
    required: False
    type: 'str'
    aliases: ['share_pwd']
  share_mnt:
    description:
      - Local mount path on the ansible controller machine for the remote
        network share (CIFS, NFS) provided in I(share_name). This is not
        applicable for HTTP, HTTPS and FTP share.
      - This option is mandatory only when using firmware update from a network
        repository using Server Configuration Profiles (SCP).
      - SCP based firmware update is only supported for iDRAC firmware
        version >=3.00.00.00.
    required: False
    type: 'path'
  catalog_file_name:
    description:
      - Catalog file name relative to the I(share_name)
    required: False
    type: 'str'
    default: 'Catalog.xml'
  apply_update:
    description:
      - if C(True), the updatable packages from Catalog XML are staged
      - if C(False), do not Install Updates
    required: False
    type: 'bool'
    default: True
  reboot:
    description:
      - if C(True), reboot server for applying the updates
      - if C(False), updates take effect after the system is rebooted the next
        time. If there are update packages in the repository that requires a
        reboot, then please make sure that you don't set the I(reboot) to
        C(False) and I(job_wait) to C(True), otherwise the module will be
        waiting forever for a system reboot and eventually timeout
    required: False
    type: 'bool'
    default: False
  job_wait:
    description:
      - if C(True), will wait for update JOB to get completed
      - if C(False), return immediately after creating the update job in job queue
    required: False
    type: 'bool'
    default: True
  ignore_cert_warning:
    description:
      - Specifies if certificate warnings should be ignored when HTTPS share is used
      - if C(True), certificate warnings are ignored
      - if C(False), certificate warnings are not ignored
    required: False
    type: 'bool'
    default: True

requirements:
  - "omsdk"
  - "python >= 2.7.5"
author:
  - "Anupam Aloke (@anupamaloke)"
  - "Rajeev Arakkal (@rajeevarakkal)"
'''

EXAMPLES = '''
---
# Update firmware from repository on a CIFS Share. '\\\\192.168.20.10\\share' is
# a CIFS share that contains the catalog file and the update packages (DUPs)

- name: Update firmware from repository on a CIFS Share
  idrac_firmware:
    idrac_ip: "192.168.10.1"
    idrac_user: "user_name"
    idrac_password: "user_pwd"
    share_name: '\\\\192.168.20.10\\share'
    share_user: "share_user_name"
    share_password: "share_user_pwd"
    catalog_file_name: "Catalog.xml"
    apply_update: True
    reboot: True
    job_wait: True
  delegate_to: localhost

# Update firmware from repository on a NFS Share. '192.168.20.10:/share' is
# a NFS share that contains the catalog file and the update packages (DUPs)

- name: Update firmware from repository on a NFS Share
  idrac_firmware:
    idrac_ip: "192.168.10.1"
    idrac_user: "user_name"
    idrac_password: "user_pwd"
    share_name: "192.168.20.10:/share"
    share_mnt: "/mnt/nfs_share"
    catalog_file_name: "Catalog.xml"
    apply_update: True
    reboot: True
    job_wait: True
  delegate_to: localhost

# Update firmware from repository on a HTTP/S Share.
# In this example, we are using http://downloads.dell.com/catalog to update
# the server firmware

- name: Update firmware from repository on a HTTP/S Share
  dellemc_install_firmware:
    idrac_ip: "192.168.10.1"
    idrac_user: "user_name"
    idrac_password: "user_pwd"
    share_name: "http://downloads.dell.com/catalog"
    catalog_file_name: "Catalog.xml"
    apply_update: True
    reboot: True
    job_wait: True
  delegate_to: localhost

'''

RETURN = '''
---
msg:
  type: str
  description: Over all firmware update status.
  returned: always
  sample: "Successfully updated the firmware."
update_status:
  type: dict
  description: Firmware Update job and progress details from the iDRAC.
  returned: success
  sample: {
        "ElapsedTimeSinceCompletion": "0",
        "InstanceID": "JID_396919089508",
        "JobStartTime": "NA",
        "JobStatus": "Completed",
        "JobUntilTime": "NA",
        "Message": "Job completed successfully.",
        "MessageArguments": "NA",
        "MessageID": "RED001",
        "Name": "Repository Update",
        "PercentComplete": "100",
        "Status": "Success",
        "file": "http://downloads.dell.com/catalog/Catalog.xml",
        "retval": true
    }

'''

import re
from ansible.module_utils.remote_management.dellemc.dellemc_idrac import iDRACConnection
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import urlparse

try:
    from omsdk.sdkcreds import UserCredentials
    from omsdk.sdkfile import FileOnShare
    HAS_OMSDK = True
except ImportError:
    HAS_OMSDK = False


class iDRACFirmwareModule(object):
    """Configuration class for iDRAC firmware"""

    def __init__(self, module):
        self.idrac = None
        self.module = module
        self.share_name = None
        self.share_user = None
        self.share_password = None
        self.share_mnt = None
        self.catalog_file_name = None
        self.apply_update = None
        self.reboot = None
        self.job_wait = None
        self.ignore_cert_warning = None
        self.url = None

        self._validate_module_args()

    def _validate_module_args(self):
        """Validate module arguments"""

        # catalog file name ends with '.xml' or '.xml.gz'
        extensions = ('.xml', '.xml.gz')
        if not self.module.params['catalog_file_name'].lower().endswith(extensions):
            error = "Invalid catalog file: {0}. Valid extensions are {1}".format(self.module.params['catalog_file_name'], extensions)
            raise ValueError(error)

        # validate URL if a HTTP/HTTPS/FTP share is used
        if self.module.params['share_name'].lower().startswith(('http://', 'https://', 'ftp://')):
            self._validate_url(self.module.params['share_name'])

        return True

    def _validate_url(self, share_name):
        """Validate URL"""

        # unicode letters range (must not be a raw string)
        ul = '\u00a1-\uffff'
        ipv4_re = r'(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}(?=$|(?::(\d{2,5})))'
        hostname_re = r'[a-z' + ul + r'0-9](?:[a-z' + ul + r'0-9-]{0,61}[a-z' + ul + r'0-9])?'
        # Max length for domain name labels is 63 characters per RFC 1034 sec3.1
        domain_re = r'(?:\.(?!-)[a-z' + ul + r'0-9-]{1,63}(?<!-))*'
        tld_re = (
                r'\.'                                # dot
                r'(?!-)'                             # can't start with a dash
                r'(?:[a-z' + ul + '-]{2,63}'         # domain label
                r'|xn--[a-z0-9]{1,59})'              # or punycode label
                r'(?<!-)'                            # can't end with a dash
                r'\.?'                               # may have a trailing dot
            )

        host_re = '(' + hostname_re + domain_re + tld_re + ')'
        regex = re.compile(r'(?:' + ipv4_re + '|' + host_re + ')')

        # URL scheme
        schemes = ["ftp", "http", "https"]

        repo_url = urlparse(share_name)

        if repo_url:
            if repo_url.scheme not in schemes:
                error = "URL scheme must be one of " + str(schemes)
                raise ValueError("Invalid url: {0}. {1}".format(share_name, error))
            elif not (repo_url.netloc and re.match(regex, repo_url.netloc)):
                error = "URL netloc must be a valid hostname or IPv4 address."
                raise ValueError("Invalid url: {0}. {1}".format(share_name, error))
            self.url = repo_url
        else:
            raise ValueError("URL parse failed for: {0}".format(share_name))

        return True

    def update_firmware_from_url(self):
        """Update firmware from a ftp/http/https URL"""

        path = "/" if not self.url.path else self.url.path

        result = self.idrac.update_mgr.update_from_repo_url(
                ipaddress=self.url.netloc, share_type=self.url.scheme,
                share_name=path, share_user=self.share_user,
                share_pwd=self.share_password,
                catalog_file=self.catalog_file_name,
                apply_update=self.apply_update,
                reboot_needed=self.reboot,
                ignore_cert_warning=self.ignore_cert_warning,
                job_wait=self.job_wait)

        return result

    def update_firmware_from_net_share(self):
        """
        Update firmware from a repository on a remote network share (CIFS, NFS)
        """

        net_share_repo = FileOnShare(remote=self.share_name,
                                     mount_point=self.share_mnt,
                                     creds=UserCredentials(self.share_user, self.share_password),
                                     isFolder=True)
        catalog_path = net_share_repo.new_file(self.catalog_file_name)

        result = self.idrac.update_mgr.update_from_repo(
                catalog_path=catalog_path,
                apply_update=self.apply_update,
                reboot_needed=self.reboot,
                job_wait=self.job_wait)

        return result

    def exec_module(self, idrac):

        self.idrac = idrac

        result = {}
        result['update_status'] = {}
        result['changed'] = False

        try:
            for key in list(self.module.argument_spec.keys()):
                setattr(self, key, self.module.params[key])

            if self.url:
                # update from URL location
                result['update_status'] = self.update_firmware_from_url()
            else:
                # update from CIFS or NFS share
                result['update_status'] = self.update_firmware_from_net_share()

        except RuntimeError as e:
            self.module.fail_json(msg=str(e))

        if "Status" in result['update_status']:
            if result['update_status']['Status'] == "Success":
                result['msg'] = 'Successfully created the repository update job.'

                if self.job_wait:
                    result['msg'] = 'Succesfully completed the repository update job.'
                    result['changed'] = True if self.apply_update else False
            else:
                result['msg'] = 'Failed to update firmware.'
                self.module.fail_json(**result)
        else:
            result['msg'] = 'Failed to update firmware.'
            self.module.fail_json(**result)

        return result


def main():

    module = AnsibleModule(
        argument_spec={
            # iDRAC Credentials
            "idrac_ip": {"required": True, "type": 'str'},
            "idrac_user": {"required": True, "type": 'str'},
            "idrac_password": {"required": True, "type": 'str',
                               "aliases": ['idrac_pwd'], "no_log": True},
            "idrac_port": {"required": False, "default": 443, "type": 'int'},

            # Network File Share
            "share_name": {"required": True, "type": 'str'},
            "share_user": {"required": False, "type": 'str', "default": None},
            "share_password": {"required": False, "type": 'str',
                               "aliases": ['share_pwd'], "default": None,
                               "no_log": True},
            "share_mnt": {"required": False, "type": 'path', "default": None},

            # Firmware update parameters
            "catalog_file_name": {"required": False, "default": 'Catalog.xml',
                                  "type": 'str'},
            "apply_update": {"required": False, "default": True, "type": 'bool'},
            "reboot": {"required": False, "default": False, "type": 'bool'},
            "job_wait": {"required": False, "default": True, "type": 'bool'},
            "ignore_cert_warning": {"required": False, "default": True,
                                    "type": 'bool'}
        },

        supports_check_mode=False)

    try:
        idrac_firmware = iDRACFirmwareModule(module)

        # Connect to iDRAC and update firmware
        with iDRACConnection(module.params) as idrac:
            result = idrac_firmware.exec_module(idrac)

    except (ImportError, ValueError, TypeError, RuntimeError) as e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)


if __name__ == '__main__':
    main()
