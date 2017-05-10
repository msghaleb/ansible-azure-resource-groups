#!/usr/bin/python
# -*- coding: utf-8 -*-
__version__ = "0.0.1"
DOCUMENTATION = '''
---
module: azure_resource_groups
short_description: Create and delete Azure resource groups
description:
     - This Role allows you to create and delete Azure resource groups
version_added: "0.0.1"
options:
  resource_group_name:
    description:
      - The Resource Group name to be created or deleted
    required: true
    default: null

  state:
    description:
      - Whether to create or delete an Azure role assignment.
    required: false
    default: present
    choices: [ "present", "absent" ]

  location:
    description:
      - resource group location
    required: true
    default: null

  client_id:
    description:
      - Azure clientID. If not set then the value of the AZURE_CLIENT_ID environment variable is used.
    required: false
    default: null
    aliases: [ 'azure_client_id', 'client_id' ]

  client_secret:
    description:
      - Azure Client secret key. If not set then the value of the AZURE_CLIENT_SECRET environment variable is used.
    required: false
    default: null
    aliases: [ 'azure_client_secret', 'client_secret' ]

  subscription_id:
    description:
      - Your Azure subscription id
    required: true
    default: null

  '''.format(__version__)

EXAMPLES = '''
# Basic resource group creation example
tasks:
- name: Azure AD resource groups
  azure_resource_groups:
    resource_group_name : "myresourcegroup"
    location            : "westus"
    tags                :
        Name            : "testgroups"
        Group           : "azure_groups"
    subscription_id     : "000000000-000-0000-00000000000000-0000"
    client_id           : "6359f1g62-6543-6789-124f-398763x98112"
    client_secret       : "HhCDbhsjkuHGiNhe+RE4aQsdjjrdof8cSd/q8F/iEDhx="

'''

class AzureResourceGroups():
    def __init__(self, module):
        self.module = module
        #self.user_name = self.module.params["user_name"]
        self.resource_group_name = self.module.params["resource_group_name"]
        self.state = self.module.params["state"]
        #self.principalId = None
        #self.role_assignment_id = uuid.uuid1()
        #self.role_definition_id = None
        self.subscription_id = self.module.params["subscription_id"]
        self.location = self.module.params["location"]
        self.client_id = self.module.params["client_id"]
        self.client_secret = self.module.params["client_secret"]
        #self.tags = self.module.params["tags"]
        self.management_url = self.module.params["management_url"]
        self.login_url  = self.module.params["login_url"]
        self.tenant_domain = self.module.params["tenant_domain"]
        #self.role_definition_name = self.module.params["role_definition_name"]
        #if not self.graph_url:
        #    self.graph_url = "https://graph.windows.net/{}".format(self.tenant_domain)
        if not self.management_url:
            self.management_url = "https://management.azure.com/subscriptions/{}".format(self.subscription_id)
        if not self.login_url:
            self.login_url = "https://login.windows.net/{}/oauth2/token?api-version=1.0".format(self.tenant_domain)

        # Geting azure cred from ENV if not defined
        if not self.client_id:
            if 'azure_client_id' in os.environ:
                self.client_id = os.environ['azure_client_id']
            elif 'AZURE_CLIENT_ID' in os.environ:
                self.client_id = os.environ['AZURE_CLIENT_ID']
            elif 'client_id' in os.environ:
                self.client_id = os.environ['client_id']
            elif 'CLIENT_ID' in os.environ:
                self.client_id = os.environ['CLIENT_ID']
            else:
                # in case client_id came in as empty string
                self.module.fail_json(msg="Client ID is not defined in module arguments or environment.")

        if not self.client_secret:
            if 'azure_client_secret' in os.environ:
                self.client_secret = os.environ['azure_client_secret']
            elif 'AZURE_CLIENT_SECRET' in os.environ:
                self.client_secret = os.environ['AZURE_CLIENT_SECRET']
            elif 'client_secret' in os.environ:
                self.client_secret = os.environ['client_secret']
            elif 'CLIENT_SECRET' in os.environ:
                self.client_secret = os.environ['CLIENT_SECRET']
            else:
                # in case secret_key came in as empty string
                self.module.fail_json(msg="Client Secret is not defined in module arguments or environment.")
        self.headers = None
        #self.user_headers = None
        self.data = None
        self.azure_version = "api-version=2015-11-01"

    # TODO: might not be needed
    def convert(self, data):
        if isinstance(data, basestring):
            return str(data)
        elif isinstance(data, collections.Mapping):
            return dict(map(self.convert, data.iteritems()))
        elif isinstance(data, collections.Iterable):
            return type(data)(map(self.convert, data))
        else:
            return data

    def resource_group_login(self):
        headers = { 'User-Agent': 'ansible-azure-0.0.1', 'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded' }
        payload = { 'grant_type': 'client_credentials', 'client_id': self.client_id, 'client_secret': self.client_secret, 'resource': 'https://management.core.windows.net/' }
        payload = urllib.urlencode(payload)

        try:
            r = open_url(self.login_url, method="post", headers=headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            self.module.fail_json(msg="Failed to login error code = '{}' and message = {}".format(response_code, response_msg))

        response_msg = r.read()
        # TODO: Should try and catch if failed to seriolize to json
        token_response = json.loads(response_msg)
        token = token_response.get("access_token", False)
        if not token:
            self.module.fail_json(msg="Failed to extract token type from reply")
        token_type = token_response.get("token_type", 'Bearer')
        self.headers = { 'Authorization' : '{} {}'.format(token_type, token),
                         'Accept' : 'application/json', "content-type": "application/json" }

    def get_resource_group(self):
        #https://msdn.microsoft.com/en-us/library/azure/dn758095.aspx
        #Here we check if the resource group is already there or not.
        #self.resource_group_login()
        payload = {
                    "location": "{}".format(self.location),
                    #"tags": "{}".format(self.tags)
                  }
        payload = json.dumps(payload)
        url = self.management_url + "/resourceGroups/{}?{}".format(self.resource_group_name, self.azure_version)
        #print (url)
        try:
            r = open_url(url, method="get", headers=self.headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("error", False) and "could not be found" in response_json.get("error").get("message",{}):#.get("value"):
                #self.module.exit_json(msg="The group you specified is not found, which means you can create it!.", changed=False)
                return False
            else:
                error_msg = response_json.get("error").get("message")
                self.module.fail_json(msg="Error happend while trying to check if the resource group exists. Error code='{}' msg='{}'".format(response_code, error_msg))
                print('Code: ', response_code)
                print('Message: ', response_msg)
                print(response_json)
        return True
        #self.module.exit_json(msg="A Resource Group with the same name in the same location is found, please specify another name or location.", changed=True)

    def create_resource_group(self):
        #https://msdn.microsoft.com/en-us/library/azure/dn906887.aspx
        self.resource_group_login()
        check_resource_group = self.get_resource_group()
        if check_resource_group == True:
            self.module.exit_json(msg="The Resource Group alrady exists.", changed=False)
        #elif check_resource_group == False:
        #    self.module.exit_json(msg="The group you specified is not found, which means you can create it!.", changed=False)
        payload = {
                    "location": "{}".format(self.location),
                    #"tags": "{}".format(self.tags)
                  }
        payload = json.dumps(payload)
        url = self.management_url + "/resourceGroups/{}?{}".format(self.resource_group_name, self.azure_version)
        #print (url)
        try:
            r = open_url(url, method="put", headers=self.headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("error", False) and "The resource group already exists" in response_json.get("error").get("message",{}):#.get("value"):
                self.module.exit_json(msg="The resource group already exists.", changed=False)
            else:
                error_msg = response_json.get("error").get("message")
                self.module.fail_json(msg="Error happend while trying to create the resource group. Error code='{}' msg='{}'".format(response_code, error_msg))
                print('Code: ', response_code)
                print('Message: ', response_msg)
                print(response_json)
        self.module.exit_json(msg="Resource Group Created.", changed=True)

    def delete_resource_group(self):
        #https://msdn.microsoft.com/en-us/library/azure/dn906887.aspx
        self.resource_group_login()
        check_resource_group = self.get_resource_group()
        if check_resource_group == False:
            self.module.exit_json(msg="The Resource Group doesn't exist.", changed=False)
        #elif check_resource_group == False:
        #    self.module.exit_json(msg="The group you specified is not found, which means you can create it!.", changed=False)
        #payload = {
        #            "location": "{}".format(self.location),
        #            #"tags": "{}".format(self.tags)
        #          }
        #payload = json.dumps(payload)
        url = self.management_url + "/resourceGroups/{}?{}".format(self.resource_group_name, self.azure_version)
        #print (url)
        try:
            r = open_url(url, method="delete", headers=self.headers)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("error", False) and "The resource group doesn't exist" in response_json.get("error").get("message",{}):#.get("value"):
                self.module.exit_json(msg="The resource group doesn't exist.", changed=False)
            else:
                error_msg = response_json.get("error").get("message")
                self.module.fail_json(msg="Error happend while trying to delete the resource group. Error code='{}' msg='{}'".format(response_code, error_msg))
                print('Code: ', response_code)
                print('Message: ', response_msg)
                print(response_json)
        self.module.exit_json(msg="Resource Group deleted.", changed=True)

    def main(self):
        if self.state == "present":
        #    if self.name.find('@')==-1 or self.name.find('.')==-1:
        #        self.module.fail_json(msg="Please make sure to enter the username (UPN) in this form e.g. username@tenant_domain.onmicrosoft.com")
            if self.location == None:
                self.module.fail_json(msg="You can't create a resource group without specifing a location!")
        #    if self.tenant_domain == None:
        #        self.module.fail_json(msg="Please specify a Tenant Domain!")
        #    if self.display_name == None:
        #        i = self.name.split('@', 1)
        #        self.display_name = i[0]
        #    if self.mail_nick_name == None:
        #        i = self.name.split('@', 1)
        #        self.mail_nick_name = i[0]


            #self.principalId = self.get_user_id()
            #self.role_definition_id = self.get_role_definition()
            self.create_resource_group()
            #self.get_resource_group()
            #print upn_name

        elif self.state == "absent":
            #self.module.exit_json(msg="Deletion is not supported.", changed=False)
            self.delete_resource_group()

def main():
    module = AnsibleModule(
        argument_spec=dict(
            #user_name=dict(default=None, type="str", required=True),
            #principalId=dict(default=None, alias="principal_id", type="str", required=False),
            #role_definition_name=dict(default=None, type="str", required=True),
            resource_group_name=dict(default=None, type="str", required=True),
            state=dict(default="present", choices=["absent", "present"]),
            location = dict(default=None, type="str", required=False),
            #tags=dict(default=None, type="str", required=False),
            subscription_id=dict(default=None, type="str", required=True),
            client_id = dict(default=None, alias="azure_client_id", type="str", no_log=True),
            client_secret = dict(default=None, alias="azure_client_secret", type="str", no_log=True),
            management_url = dict(default=None, type="str"),
            login_url  = dict(default=None, type="str"),
            tenant_domain = dict(default=None, type="str", required=True),
            #graph_url = dict(default=None, type="str"),

        ),
        #mutually_exclusive=[['ip', 'mask']],
        #required_together=[['ip', 'mask']],
        #required_one_of=[['ip', 'mask']],
        supports_check_mode=False
    )

    AzureResourceGroups(module).main()

import collections # might not be needed
import json
import urllib
import uuid
import urllib2

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
#from azure.mgmt.common import SubscriptionCloudCredentials
#from azure.mgmt.resource import ResourceManagementClient

main()
