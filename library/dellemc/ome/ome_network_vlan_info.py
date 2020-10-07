#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell EMC OpenManage Ansible Modules
# Version 2.1.3
# Copyright (C) 2018-2020 Dell Inc. or its subsidiaries. All Rights Reserved.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ome_network_vlan_info
short_description: Retrieves the information about networks VLAN(s) present in OpenManage Enterprise.
version_added: "2.10.0"
description:
    This module allows to retrieve the following
    - A list of all the network VLANs with their detailed information.
    - Information about a specific network VLAN using VLAN I(id) or VLAN I(name).
options:
    hostname:
        description: Target IP Address or hostname.
        type: str
        required: true
    username:
        description: Target username.
        type: str
        required: true
    password:
        description: Target user password.
        type: str
        required: true
    port:
        description: Target HTTPS port.
        type: int
        default: 443
    id:
        description:
            - A unique identifier of the network VLAN available in the device,
            - I(id) and I(name) are mutually exclusive.
        type: int
    name:
        description:
            - A unique name of the network VLAN available in the device.
            - I(name) and I(id) are mutually exclusive.
        type: str

requirements:
    - "python >= 2.7.5"
author: "Deepak Joshi(@deepakjoshishri)"
'''

EXAMPLES = """
---
- name: Retrieve information about all network VLANs(s) available in the device.
  ome_network_vlan_info:
    hostname: "192.168.0.1"
    username: "username"
    password: "password"

- name: Retrieve information about a network VLAN using the VLAN ID.
  ome_network_vlan_info:
    hostname: "192.168.0.1"
    username: "username"
    password: "password"
    id: 12345

- name: Retrieve information about a network VLAN using the VLAN name.
  ome_network_vlan_info:
    hostname: "192.168.0.1"
    username: "username"
    password: "password"
    name: "Network VLAN - 1"
"""

RETURN = '''
---
msg:
  type: dict
  description: Detailed information of the network VLAN(s).
  returned: success
  sample: {
  "msg": "Successfully retrieved the network VLAN information.",
  "network_vlan_info": [
        {
            "CreatedBy": "admin",
            "CreationTime": "2020-09-02 18:48:42.129",
            "Description": "Description of Logical Network - 1",
            "Id": 20057,
            "InternalRefNWUUId": "42b9903d-93f8-4184-adcf-0772e4492f71",
            "Name": "Network VLAN - 1",
            "Type": {
                "Description": "This is the network for general purpose traffic. QOS Priority : Bronze.",
                "Id": 1,
                "Name": "General Purpose (Bronze)",
                "NetworkTrafficType": "Ethernet",
                "QosType": {
                    "Id": 4,
                    "Name": "Bronze"
                },
                "VendorCode": "GeneralPurpose"
            },
            "UpdatedBy": null,
            "UpdatedTime": "2020-09-02 18:48:42.129",
            "VlanMaximum": 111,
            "VlanMinimum": 111
        },
        {
            "CreatedBy": "admin",
            "CreationTime": "2020-09-02 18:49:11.507",
            "Description": "Description of Logical Network - 2",
            "Id": 20058,
            "InternalRefNWUUId": "e46ccb3f-ef57-4617-ac76-46c56594005c",
            "Name": "Network VLAN - 2",
            "Type": {
                "Description": "This is the network for general purpose traffic. QOS Priority : Silver.",
                "Id": 2,
                "Name": "General Purpose (Silver)",
                "NetworkTrafficType": "Ethernet",
                "QosType": {
                    "Id": 3,
                    "Name": "Silver"
                },
                "VendorCode": "GeneralPurpose"
            },
            "UpdatedBy": null,
            "UpdatedTime": "2020-09-02 18:49:11.507",
            "VlanMaximum": 112,
            "VlanMinimum": 112
        }
    ]
}
error_info:
  description: Details of the HTTP Error.
  returned: on HTTP error
  type: dict
  sample: {
    "error": {
      "code": "Base.1.0.GeneralError",
      "message": "A general error has occurred. See ExtendedInfo for more information.",
      "@Message.ExtendedInfo": [
        {
          "MessageId": "GEN1234",
          "RelatedProperties": [],
          "Message": "Unable to process the request because an error occurred.",
          "MessageArgs": [],
          "Severity": "Critical",
          "Resolution": "Retry the operation. If the issue persists, contact your system administrator."
        }
      ]
    }
  }
'''

import json
from ssl import SSLError
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.remote_management.dellemc.ome import RestOME
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError

# Base URI to fetch all logical networks information
NETWORK_VLAN_BASE_URI = "NetworkConfigurationService/Networks"
NETWORK_TYPE_BASE_URI = "NetworkConfigurationService/NetworkTypes"
QOS_TYPE_BASE_URI = "NetworkConfigurationService/QosTypes"

# Module Success Message
MODULE_SUCCESS_MESSAGE = "Successfully retrieved the network VLAN information."

# Module Failure Messages
MODULE_FAILURE_MESSAGE = "Failed to retrieve the network VLAN information."
NETWORK_VLAN_NAME_NOT_FOUND = "Provided network VLAN with name - '{0}' does not exist."


def clean_data(data):
    """
    data: A dictionary.
    return: A data dictionary after removing items that are not required for end user.
    """
    for k in ['@odata.id', '@odata.type', '@odata.context', '@odata.count']:
        data.pop(k, None)
    return data


def get_network_type_and_qos_type_information(rest_obj, network_vlan):
    """
    rest_obj: Object containing information about connection to device.
    network_vlan: A dictionary containing information of network VLAN.
    return: updated dictionary with additional info for "Type" and "QosType" keys.
    """
    network_vlan = clean_data(network_vlan)
    network_types_uri = "{0}({1})".format(NETWORK_TYPE_BASE_URI, network_vlan.get("Type"))
    resp = rest_obj.invoke_request('GET', network_types_uri)
    if resp.status_code == 200:
        network_vlan['Type'] = clean_data(resp.json_data)
        qos_type_uri = "{0}({1})".format(QOS_TYPE_BASE_URI, network_vlan.get("Type").get("QosType"))
        resp = rest_obj.invoke_request('GET', qos_type_uri)
        network_vlan['Type']['QosType'] = clean_data(resp.json_data) if resp.status_code == 200 else \
            network_vlan['Type']['QosType']
    return network_vlan


def main():
    module = AnsibleModule(
        argument_spec={
            "hostname": {"required": True, "type": 'str'},
            "username": {"required": True, "type": 'str'},
            "password": {"required": True, "type": 'str', "no_log": True},
            "port": {"required": False, "default": 443, "type": 'int'},
            "id": {"required": False, "type": 'int'},
            "name": {"required": False, "type": 'str'}
        },
        mutually_exclusive=[["id", "name"]],
        supports_check_mode=False)
    try:
        with RestOME(module.params, req_session=True) as rest_obj:
            # Form URI to fetch network VLAN information
            network_vlan_uri = "{0}({1})".format(NETWORK_VLAN_BASE_URI, module.params.get("id")) if module.params.get(
                "id") else NETWORK_VLAN_BASE_URI
            resp = rest_obj.invoke_request('GET', network_vlan_uri)
            if resp.status_code == 200:
                network_vlan_info = resp.json_data.get('value') if isinstance(resp.json_data.get('value'), list) else [
                    resp.json_data]
                if module.params.get("name"):
                    network_vlan_name = module.params.get("name")
                    network_vlan = []
                    for item in network_vlan_info:
                        if item["Name"] == network_vlan_name.strip():
                            network_vlan = [item]
                            break
                    if not network_vlan:
                        module.fail_json(msg=NETWORK_VLAN_NAME_NOT_FOUND.format(network_vlan_name))
                    network_vlan_info = network_vlan
                complete_network_vlan_info = []
                # Get network type and Qos Type information for each dict in list
                for network_vlan in network_vlan_info:
                    complete_network_vlan_info.append(get_network_type_and_qos_type_information(rest_obj, network_vlan))
                module.exit_json(msg=MODULE_SUCCESS_MESSAGE, network_vlan_info=complete_network_vlan_info)
            else:
                module.fail_json(msg=MODULE_FAILURE_MESSAGE)
    except HTTPError as err:
        if err.getcode() == 404:
            module.fail_json(msg=str(err))
        module.fail_json(msg=str(MODULE_FAILURE_MESSAGE), error_info=json.load(err))
    except URLError as err:
        module.exit_json(msg=str(err), unreachable=True)
    except (IOError, ValueError, SSLError, TypeError, KeyError, ConnectionError, SSLValidationError) as err:
        module.fail_json(msg=str(err))


if __name__ == '__main__':
    main()
