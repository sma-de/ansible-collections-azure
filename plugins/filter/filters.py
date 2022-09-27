

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}


import collections

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
        })

        return tmp


    def run_specific(self, value):
        if not isinstance(value, MutableMapping):
            raise AnsibleOptionsError(
               "input value must be a mapping, but is of"\
               " type '{}'".format(type(value))
            )

        new_secrets = self.get_taskparam('new_secrets')
        secrets_cfg = self.get_taskparam('secrets_cfg')

        for ns in new_secrets:
            # getting the secret name from azure module return structure
            # is surprisingly complicated (no direct field for this)
            sname = ns['sid'].split('/')
            sname = sname[-2]
            ns['name'] = sname

            if secrets_cfg.get('only_value', False):
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

