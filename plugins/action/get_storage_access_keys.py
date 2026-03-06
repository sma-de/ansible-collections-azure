
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible.errors import AnsibleOptionsError
from ansible.module_utils.six import string_types
##from ansible.utils.display import Display


from ansible_collections.smabot.base.plugins.module_utils.plugins.action_base import BaseAction
from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert


##display = Display()


class ActionModule(BaseAction):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          'account_name': (list(string_types)),
          'account_resoure_group': (list(string_types)),
          'mode': (list(string_types), 'all',
             ['all', 'primary_only', 'secondary_only']
          ),
          'optional': ([bool], False),
        })

        return tmp


    def run_specific(self, result):
        acc_name = self.get_taskparam('account_name')
        acc_grp = self.get_taskparam('account_resoure_group')

        optional = self.get_taskparam('optional')
        mode = self.get_taskparam('mode')

        mod_args = {
          'name': acc_name, 'resource_group': acc_grp,
          'show_connection_string': True,
        }

        mres = self.exec_module(
          'azure.azcollection.azure_rm_storageaccount_info',
          modargs=mod_args, ignore_error=optional,
        )

        acc_info = mres['storageaccounts'][0]

        keys = {}

        if mode == 'all' or mode == 'primary_only':
            if acc_info['status_of_primary'] == 'available':
                keys['primary'] = acc_info['primary_endpoints']['key']
                keys['first_valid'] = keys['primary']

        if mode == 'all' or mode == 'secondary_only':
            if acc_info['status_of_secondary'] == 'available':
                keys['secondary'] = acc_info['secondary_endpoints']['key']
                keys.setdefault('first_valid', keys['secondary'])

        ansible_assert(keys or optional,
          "failed to obtain any access keys for storage account '{}'"\
          " in resource group '{}', if this is an acceptable outcome"\
          " set the optional flag".format(acc_name, acc_grp)
        )

        result['keys'] = keys
        return result

