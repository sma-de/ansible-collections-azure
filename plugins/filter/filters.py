

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}


import collections
import copy
import re

from ansible.errors import AnsibleFilterError, AnsibleOptionsError
from ansible.module_utils.six import string_types
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils._text import to_text, to_native

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META
from ansible_collections.smabot.base.plugins.module_utils.plugins.filter_base import FilterBase

from ansible.utils.display import Display


display = Display()


class AppendAZSecrets(FilterBase):

    FILTER_ID = 'append_az_secrets'


    @property
    def argspec(self):
        tmp = super(AppendAZSecrets, self).argspec

        tmp.update({
          'new_secrets': ([[collections.abc.Mapping]]),
          'secrets_cfg': ([collections.abc.Mapping]),
          'base_cfg': ([collections.abc.Mapping]),
        })

        return tmp


    def run_specific(self, value):
        if not isinstance(value, MutableMapping):
            raise AnsibleOptionsError(
               "input value must be a mapping, but is of"\
               " type '{}'".format(type(value))
            )

        base_cfg = self.get_taskparam('base_cfg')
        match_rgx = base_cfg['matching']

        new_secrets = self.get_taskparam('new_secrets')
        secrets_cfg = self.get_taskparam('secrets_cfg')
        read_all = secrets_cfg['read_all']
        ret_secrets = secrets_cfg['return_secrets']

        for ns in new_secrets:
            # getting the secret name from azure module return structure
            # is surprisingly complicated (no direct field for this)
            sname = ns['sid'].split('/')

            if read_all:
                sname = sname[-1]
            else:
                sname = sname[-2]

            if match_rgx:
                if not re.search(match_rgx, sname):
                    # secret name does not match given pattern, so ignore it
                    continue

            ns['name'] = sname

            if read_all and ret_secrets:
                ## prepare for recursion down to read all secrets one by one
                tmp = copy.deepcopy(secrets_cfg)
                tmp.update(ns)

                ns = tmp

                ns['config']['name'] = ns['name']
                ns['read_all'] = False

            else:

                if secrets_cfg.get('only_value', False):
                    if read_all:
                        ## when all secrets are read at once,
                        ## the actual secrets are nt provided by upstream api
                        ns = None
                    else:
                        ns = ns['secret']

            tmp = value.setdefault('secrets', {})
            tmp[sname] = ns

        return value



# ---- Ansible filters ----
class FilterModule(object):
    ''' very custom filters specific to parent role '''

    def filters(self):
        res = {}

        for f in [AppendAZSecrets]:
            res[f.FILTER_ID] = f()

        return res

