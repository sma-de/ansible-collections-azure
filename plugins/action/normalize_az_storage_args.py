
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



class AZStorageRootNormer(NormalizerBase):

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
          NormStorageAccInst(pluginref),
          NormStorageContInst(pluginref),
        ]

        super(AZStorageRootNormer, self).__init__(pluginref, *args, **kwargs)


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



class NormStorageAccInst(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'name_prefix', DefaultSetterConstant('')
        )

        self._add_defaultsetter(kwargs,
          'name_suffix', DefaultSetterConstant('')
        )

        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormStAccInstResGrp(pluginref),
          NormStAccInstConfig(pluginref),
        ]

        super(NormStorageAccInst, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['storage_accounts', 'accounts', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'short_name'


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## build fullname if not explicitly specified
        fn = my_subcfg.get('full_name', None)

        if not fn:
           fn = my_subcfg['name_prefix'] \
              + my_subcfg['short_name'] + my_subcfg['name_suffix']

           for x in [':', '_', '-', '.']:
             fn.replace(x, '')

           my_subcfg['full_name'] = fn

        return my_subcfg



class NormStAccInstResGrp(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        self._add_defaultsetter(kwargs,
          'auto_create', DefaultSetterConstant(True)
        )

        super(NormStAccInstResGrp, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['resgrp']

    @property
    def simpleform_key(self):
        return 'name'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = setdefault_none(my_subcfg, 'config', {})
        c['name'] = my_subcfg['name']

        return my_subcfg


class NormStAccInstConfig(NormalizerBase):

    @property
    def config_path(self):
        return ['config']


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        my_subcfg['name'] = pcfg['full_name']
        my_subcfg['resource_group'] = pcfg['resgrp']['name']

        return my_subcfg



class NormStorageContInst(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          NormStContInstConfig(pluginref),
        ]

        super(NormStorageContInst, self).__init__(pluginref, *args, **kwargs)


    @property
    def config_path(self):
        return ['storage_containers', 'containers', SUBDICT_METAKEY_ANY]


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        acc_ref = my_subcfg.get('account_ref', None)

        if acc_ref:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)
            refd_acc = pcfg['storage_accounts']['accounts'].get(acc_ref, None)

            ansible_assert(refd_acc,
              "a config for a storage account with id '{}' referenced"\
              " by container config with id '{}' seems not to"\
              " exist".format(acc_ref, cfgpath_abs[-1])
            )

            my_subcfg['account_ref'] = refd_acc

        return my_subcfg



class NormStContInstConfig(NormalizerBase):

    @property
    def config_path(self):
        return ['config']


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        my_subcfg['container'] = pcfg['name']

        accref = pcfg.get('account_ref', None)

        if accref:
            my_subcfg['storage_account_name'] = accref['config']['name']
            my_subcfg['resource_group'] = accref['config']['resource_group']

        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(
           AZStorageRootNormer(self), *args,
           default_merge_vars=[
             'smabot_azure_azure_storage_args_defaults',
             'smabot_azure_azure_storage_args_extra_defaults'
           ],
           **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_azure_azure_storage_args'

