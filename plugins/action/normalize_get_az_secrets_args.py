
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

from ansible.errors import AnsibleOptionsError
from ansible.plugins.filter.core import to_bool

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import\
  ConfigNormalizerBaseMerger,\
  NormalizerBase,\
  DefaultSetterConstant

from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.proxy import ConfigNormerProxy
from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import get_subdict, setdefault_none, SUBDICT_METAKEY_ANY
from ansible_collections.smabot.base.plugins.action import command_which

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert



class GetAZSecretsNormalizer(NormalizerBase):

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
          NormSecret(pluginref),
        ]

        super(GetAZSecretsNormalizer, self).__init__(pluginref, *args, **kwargs)

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


class NormSecret(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'only_value', DefaultSetterConstant(False)
        )

        super(NormSecret, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['get_secrets', 'secrets', SUBDICT_METAKEY_ANY]


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        # default name to dict key
        tmp = my_subcfg.setdefault('config', {})
        setdefault_none(tmp, 'name', cfgpath_abs[-1])
        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           GetAZSecretsNormalizer(self), *args,
##           default_merge_vars=['smabot_get_az_secrets_args_defaults'],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_azure_get_keyvault_secrets_args'

