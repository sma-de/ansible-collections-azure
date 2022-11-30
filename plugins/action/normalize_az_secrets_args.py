
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

from ansible.errors import AnsibleOptionsError
from ansible.plugins.filter.core import to_bool

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import\
  ConfigNormalizerBaseMerger,\
  NormalizerBase,\
  NormalizerNamed,\
  DefaultSetterConstant,\
  SIMPLEKEY_IGNORE_VAL

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.proxy import ConfigNormerProxy
from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import get_subdict, setdefault_none, SUBDICT_METAKEY_ANY
from ansible_collections.smabot.base.plugins.action import command_which

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert



class AZSecretsNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'hide_secrets', DefaultSetterConstant(True)
        )

        self._add_defaultsetter(kwargs,
          'requirements_srcpath', DefaultSetterConstant(
              'ansible_collections/azure/azcollection/requirements-azure.txt'
          )
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormGetSecrets(pluginref),
          NormSetAllSecrets(pluginref),
        ]

        super(AZSecretsNormalizer, self).__init__(pluginref, *args, **kwargs)

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'collections_basepath',
          os.environ.get('ANSIBLE_COLLECTION_DIR', './collections') # on default use cwd
        )

        reqsrc = my_subcfg['requirements_srcpath']

        if not os.path.isabs(reqsrc):
            my_subcfg['requirements_srcpath'] = os.path.join(
              my_subcfg['collections_basepath'], reqsrc
            )

        return my_subcfg


class NormGetSecrets(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'all', DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs,
          'matching', DefaultSetterConstant(None)
        )

        self._add_defaultsetter(kwargs,
          'return_list', DefaultSetterConstant(False)
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormGetAllSecrets(pluginref),
        ]

        super(NormGetSecrets, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['get_secrets']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        matching = my_subcfg['matching']

        if matching:
            my_subcfg['all'] = True

        readall = my_subcfg['all']

        if readall:
            tmp = my_subcfg['secrets']
            t2 = setdefault_none(tmp, NormSecretGetInst.MAGIC_READALL_KEY, None)

            ansible_assert(len(tmp) == 1,
               "Either explicitly list some secrets by name, or use"\
               " the 'all' / 'matching' key to read all secrets, never combine these two"
            )

            if t2 is None:
                t2 = readall

            tmp[NormSecretGetInst.MAGIC_READALL_KEY] = t2

        return my_subcfg


class NormGetAllSecrets(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormSecretGetInst(pluginref),
        ]

        super(NormGetAllSecrets, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['secrets']


class NormSecretGetInst(NormalizerNamed):

    MAGIC_READALL_KEY = '___ALL___'

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'only_value', DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs,
          'return_secrets', DefaultSetterConstant(False)
        )

        self._add_defaultsetter(kwargs,
          'read_all', DefaultSetterConstant(False)
        )

        super(NormSecretGetInst, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        # default name to dict key
        tmp = my_subcfg.setdefault('config', {})
        setdefault_none(tmp, 'name', my_subcfg['name'])

        ## remove unused attributes imported from common get/set defaults
        tmp.pop('tags', None)

        ## handle read-all meta/reference keys
        if my_subcfg['name'].upper() == self.MAGIC_READALL_KEY:
            my_subcfg['read_all'] = True

        if my_subcfg['read_all']:
            ## azure module will read/return all secrets if
            ## no name is specified
            my_subcfg['config'].pop('name')

        return my_subcfg


class NormSetAllSecrets(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormSecretSetInst(pluginref),
        ]

        super(NormSetAllSecrets, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['set_secrets', 'secrets']


class NormSecretSetInst(NormalizerNamed):

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## remove unused attributes imported from common get/set defaults
        my_subcfg.pop('only_value', None)

        # default name to dict key
        tmp = my_subcfg.setdefault('config', {})
        setdefault_none(tmp, 'secret_name', my_subcfg['name'])
        setdefault_none(tmp, 'secret_value', my_subcfg['value'])

        # strangely the uri param is named differently for
        # secret getter module and setter module, support both variants here
        t2 = tmp.pop('vault_uri', None)

        if t2:
            setdefault_none(tmp, 'keyvault_uri', t2)

        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           AZSecretsNormalizer(self), *args,
           default_merge_vars=[
             'smabot_azure_keyvault_secrets_args_defaults',
             'smabot_azure_keyvault_secrets_args_extra_defaults'
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_azure_keyvault_secrets_args'

