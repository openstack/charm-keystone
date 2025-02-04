# Copyright 2016-2021 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import importlib
import os
import sys

import charmhelpers.contrib.openstack.utils as os_utils

from unittest.mock import call, patch, MagicMock, ANY
from test_utils import CharmTestCase

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
sys.modules['apt'] = MagicMock()

os.environ['JUJU_UNIT_NAME'] = 'keystone'
with patch('charmhelpers.core.hookenv.config') as config, \
        patch('charmhelpers.contrib.openstack.'
              'utils.snap_install_requested') as snap_install_requested:
    snap_install_requested.return_value = False
    config.return_value = 'keystone'
    import keystone_utils as utils
    importlib.reload(utils)

    with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec, \
            patch('keystone_utils.register_configs'), \
            patch('keystone_utils.restart_map'):
        mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                                lambda *args, **kwargs: f(*args, **kwargs))
        with patch.object(utils, 'run_in_apache') as mock_run_in_apache:
            mock_run_in_apache.return_value = True
            import keystone_hooks as hooks
            importlib.reload(hooks)


TO_PATCH = [
    # charmhelpers.core.hookenv
    'Hooks',
    'config',
    'log',
    'filter_installed_packages',
    'relation_ids',
    'relation_set',
    'relation_get',
    'related_units',
    'peer_echo',
    'get_relation_ip',
    'open_port',
    'is_leader',
    # charmhelpers.core.host
    'apt_install',
    'apt_update',
    'service_restart',
    # charmhelpers.contrib.openstack.utils
    'configure_installation_source',
    'snap_install_requested',
    'check_api_application_ready',
    'inform_peers_if_ready',
    # charmhelpers.contrib.openstack.ip
    'resolve_address',
    # charmhelpers.contrib.openstack.ha.utils
    'expect_ha',
    # charmhelpers.contrib.hahelpers.cluster_utils
    'is_elected_leader',
    'is_clustered',
    'enable_memcache',
    # keystone_utils
    'restart_map',
    'register_configs',
    'do_openstack_upgrade_reexec',
    'openstack_upgrade_available',
    'save_script_rc',
    'migrate_database',
    'bootstrap_keystone',
    'ensure_initial_admin',
    'add_service_to_keystone',
    'update_nrpe_config',
    'is_db_ready',
    'create_or_show_domain',
    'get_api_version',
    'fernet_enabled',
    'key_leader_set',
    'key_setup',
    'key_write',
    'remove_old_packages',
    'services',
    # other
    'check_call',
    'execd_preinstall',
    'generate_ha_relation_data',
    # ip
    'is_service_present',
    'delete_service_entry',
    'os_release',
    'service_pause',
    'disable_unused_apache_sites',
    'run_in_apache',
    # unitdata
    'unitdata',
]


class KeystoneRelationTests(CharmTestCase):

    def setUp(self):
        super(KeystoneRelationTests, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.ssh_user = 'juju_keystone'
        self.snap_install_requested.return_value = False

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch.object(hooks, 'maybe_do_policyd_overrides')
    @patch.object(utils, 'os_release')
    @patch.object(hooks, 'service_stop', lambda *args: None)
    @patch.object(hooks, 'service_start', lambda *args: None)
    def test_install_hook(self,
                          os_release,
                          mock_maybe_do_policyd_overrides,
                          mock_get_subordinate_release_packages):
        os_release.return_value = 'havana'
        self.run_in_apache.return_value = False
        repo = 'cloud:precise-grizzly'
        self.test_config.set('openstack-origin', repo)
        mock_get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        hooks.install()
        self.assertTrue(self.execd_preinstall.called)
        self.configure_installation_source.assert_called_with(repo)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(
            ['apache2', 'haproxy', 'keystone', 'openssl', 'pwgen',
             'python-keystoneclient', 'python-mysqldb', 'python-psycopg2',
             'python3-six', 'uuid'], fatal=True)
        self.disable_unused_apache_sites.assert_not_called()
        mock_maybe_do_policyd_overrides.assert_called_once_with(
            ANY, "keystone", restart_handler=ANY)

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch.object(hooks, 'maybe_do_policyd_overrides')
    @patch.object(utils, 'os_release')
    @patch.object(hooks, 'service_stop', lambda *args: None)
    @patch.object(hooks, 'service_start', lambda *args: None)
    def test_install_hook_apache2(self,
                                  os_release,
                                  mock_maybe_do_policyd_overrides,
                                  mock_get_subordinate_release_packages):
        os_release.return_value = 'havana'
        self.run_in_apache.return_value = True
        repo = 'cloud:xenial-newton'
        self.test_config.set('openstack-origin', repo)
        mock_get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        hooks.install()
        self.assertTrue(self.execd_preinstall.called)
        self.configure_installation_source.assert_called_with(repo)
        self.assertTrue(self.apt_update.called)
        self.apt_install.assert_called_with(
            ['apache2', 'haproxy', 'keystone', 'openssl', 'pwgen',
             'python-keystoneclient', 'python-mysqldb', 'python-psycopg2',
             'python3-six', 'uuid'], fatal=True)
        self.disable_unused_apache_sites.assert_called_with()
        mock_maybe_do_policyd_overrides.assert_called_once_with(
            ANY, "keystone", restart_handler=ANY)

    mod_ch_openstack_utils = 'charmhelpers.contrib.openstack.utils'

    @patch.object(utils, 'os_release')
    @patch.object(hooks, 'config')
    @patch('%s.config' % (mod_ch_openstack_utils))
    @patch('%s.relation_set' % (mod_ch_openstack_utils))
    @patch('%s.relation_ids' % (mod_ch_openstack_utils))
    @patch('%s.get_ipv6_addr' % (mod_ch_openstack_utils))
    @patch('%s.sync_db_with_multi_ipv6_addresses' % (mod_ch_openstack_utils))
    def test_db_joined(self, mock_sync_db_with_multi, mock_get_ipv6_addr,
                       mock_relation_ids, mock_relation_set, mock_config,
                       mock_hooks_config, os_release):

        cfg_dict = {'prefer-ipv6': False,
                    'database': 'keystone',
                    'database-user': 'keystone',
                    'vip': None}

        class mock_cls_config():
            def __call__(self, key):
                return cfg_dict[key]

        cfg = mock_cls_config()
        mock_hooks_config.side_effect = cfg
        mock_config.side_effect = cfg

        self.get_relation_ip.return_value = '192.168.20.1'
        hooks.db_joined()
        self.relation_set.assert_called_with(database='keystone',
                                             username='keystone',
                                             hostname='192.168.20.1')

    @patch('keystone_utils.log')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(self, configs,
                                              mock_log):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.db_changed()
        self.log.assert_called_with(
            'shared-db relation incomplete. Peer not ready?'
        )

    @patch.object(hooks, 'update_all_identity_relation_units')
    def _shared_db_test(self, configs, unit_name, mock_update_all):
        self.relation_get.return_value = 'keystone/0 keystone/3'
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['shared-db']
        configs.write = MagicMock()
        hooks.db_changed()

    @patch.object(hooks, 'leader_init_db_if_ready')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed(self, configs, leader_init):
        self.os_release.return_value = 'havana'
        self._shared_db_test(configs, 'keystone/3')
        self.assertEqual([call('/etc/keystone/keystone.conf')],
                         configs.write.call_args_list)
        self.assertTrue(leader_init.called)

    @patch.object(hooks, 'maybe_do_policyd_overrides_on_config_changed')
    @patch.object(hooks, 'notify_middleware_with_release_version')
    @patch.object(hooks, 'update_all_domain_backends')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'run_in_apache')
    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'admin_relation_changed')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_leader(
        self,
        configure_https,
        identity_changed,
        configs,
        mock_cluster_joined,
        admin_relation_changed,
        mock_log,
        mock_is_db_initialised,
        mock_run_in_apache,
        update,
        mock_update_domains,
        mock_notify_middleware,
        mock_maybe_do_policyd_overrides_on_config_changed
    ):
        def fake_relation_ids(relation):
            rids = {'cluster': ['cluster:1'],
                    'identity-service': ['identity-service:0']}
            return rids.get(relation, [])

        self.enable_memcache.return_value = False
        self.os_release.return_value = 'mitaka'
        self.relation_ids.side_effect = fake_relation_ids

        mock_run_in_apache.return_value = False
        mock_is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        self.openstack_upgrade_available.return_value = False
        self.related_units.return_value = ['unit/0']

        hooks.config_changed()

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)
        self.open_port.assert_called_with(5000)

        mock_cluster_joined.assert_called()
        update.assert_called()
        mock_update_domains.assert_called()
        mock_notify_middleware.assert_called_once()

        (mock_maybe_do_policyd_overrides_on_config_changed
         .assert_called_once_with(ANY, "keystone", restart_handler=ANY))

    @patch.object(hooks, 'maybe_do_policyd_overrides_on_config_changed')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'update_all_domain_backends')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'run_in_apache')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_not_leader(
        self,
        configure_https,
        identity_changed,
        configs,
        mock_cluster_joined,
        mock_log,
        mock_run_in_apache, update,
        mock_update_domains,
        mock_is_db_initialised,
        mock_maybe_do_policyd_overrides_on_config_changed
    ):

        def fake_relation_ids(relation):
            rids = {}
            return rids.get(relation, [])

        self.enable_memcache.return_value = False
        self.os_release.return_value = 'mitaka'
        self.relation_ids.side_effect = fake_relation_ids

        mock_run_in_apache.return_value = False
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = True

        hooks.config_changed()

        self.assertFalse(mock_cluster_joined.called)
        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.assertFalse(self.migrate_database.called)
        self.assertTrue(update.called)
        self.assertTrue(mock_update_domains.called)

        (mock_maybe_do_policyd_overrides_on_config_changed
         .assert_called_once_with(ANY, "keystone", restart_handler=ANY))

    @patch.object(hooks, 'maybe_do_policyd_overrides_on_config_changed')
    @patch.object(hooks, 'update_all_domain_backends')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'run_in_apache')
    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'admin_relation_changed')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_with_openstack_upgrade(
        self,
        configure_https,
        identity_changed,
        configs,
        cluster_joined,
        admin_relation_changed,
        mock_log,
        mock_is_db_initialised,
        mock_run_in_apache,
        update,
        mock_update_domains,
        mock_maybe_do_policyd_overrides_on_config_changed
    ):
        def fake_relation_ids(relation):
            rids = {'identity-service': ['identity-service:0']}
            return rids.get(relation, [])

        self.os_release.return_value = 'mitaka'
        self.enable_memcache.return_value = False
        self.relation_ids.side_effect = fake_relation_ids

        mock_run_in_apache.return_value = False
        self.is_db_ready.return_value = True
        mock_is_db_initialised.return_value = True
        self.openstack_upgrade_available.return_value = True
        self.related_units.return_value = ['unit/0']

        hooks.config_changed()

        self.assertTrue(self.do_openstack_upgrade_reexec.called)

        self.save_script_rc.assert_called_with()
        configure_https.assert_called_with()
        self.assertTrue(configs.write_all.called)

        self.assertTrue(update.called)
        self.assertTrue(mock_update_domains.called)

        (mock_maybe_do_policyd_overrides_on_config_changed
         .assert_called_once_with(ANY, "keystone", restart_handler=ANY))

    @patch.object(hooks, 'maybe_do_policyd_overrides_on_config_changed')
    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'run_in_apache')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_with_openstack_upgrade_action(
        self,
        config_https,
        mock_db_init,
        mock_run_in_apache,
        os_release,
        mock_maybe_do_policyd_overrides_on_config_changed
    ):
        self.check_api_application_ready.return_value = (True, 'msg')
        os_release.return_value = 'ocata'
        self.enable_memcache.return_value = False
        mock_run_in_apache.return_value = False

        self.openstack_upgrade_available.return_value = True
        self.test_config.set('action-managed-upgrade', True)

        hooks.config_changed()

        self.assertFalse(self.do_openstack_upgrade_reexec.called)

        (mock_maybe_do_policyd_overrides_on_config_changed
         .assert_called_once_with(ANY, "keystone", restart_handler=ANY))

    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'send_notifications')
    def test_identity_changed_leader(self, mock_send_notifications,
                                     mock_log, mock_is_db_initialised):
        self.expect_ha.return_value = False
        mock_is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        self.is_service_present.return_value = True
        self.relation_get.return_value = {
            'public_url': 'http://dummy.local',
            'admin_url': 'http://dummy.local',
            'internal_url': 'http://dummy.local',
        }
        hooks.identity_changed(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        self.add_service_to_keystone.assert_called_with(
            'identity-service:0',
            'unit/0')
        self.delete_service_entry.assert_called_with(
            'quantum',
            'network')

    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'send_notifications')
    def test_identity_changed_leader_no_neutron(self, mock_send_notifications,
                                                mock_log,
                                                mock_is_db_initialised):
        self.expect_ha.return_value = False
        mock_is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        self.is_service_present.return_value = False
        self.relation_get.return_value = {
            'public_url': 'http://dummy.local',
            'admin_url': 'http://dummy.local',
            'internal_url': 'http://dummy.local',
        }
        hooks.identity_changed(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        self.assertFalse(self.delete_service_entry.called)

    @patch('keystone_utils.log')
    def test_identity_changed_no_leader(self, mock_log):
        self.is_leader.return_value = False
        hooks.identity_changed(
            relation_id='identity-service:0',
            remote_unit='unit/0')
        self.assertFalse(self.add_service_to_keystone.called)
        self.log.assert_called_with(
            'Deferring identity_changed() to service leader.')

    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch('keystone_utils.relation_ids')
    @patch('keystone_utils.config')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'CONFIGS')
    def test_cluster_changed(self, configs,
                             mock_log, mock_config, mock_relation_ids,
                             mock_update_all_identity_relation_units):

        relation_settings = {'foo_passwd': '123',
                             'identity-service:16_foo': 'bar'}

        mock_relation_ids.return_value = []
        self.is_leader.return_value = False

        def fake_rel_get(attribute=None, *args, **kwargs):
            if not attribute:
                return relation_settings

            return relation_settings.get(attribute)

        self.relation_get.side_effect = fake_rel_get

        mock_config.return_value = None

        hooks.cluster_changed()
        whitelist = ['_passwd', 'identity-service:']
        self.peer_echo.assert_called_with(force=True, includes=whitelist)
        self.assertTrue(configs.write_all.called)

    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks.CONFIGS, 'write')
    def test_leader_elected(self, mock_write, mock_update):
        hooks.leader_elected()
        mock_write.assert_has_calls([call(utils.TOKEN_FLUSH_CRON_FILE)])

    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks.CONFIGS, 'write')
    def test_leader_settings_changed(self, mock_write, update):
        self.os_release.return_value = 'mitaka'
        self.relation_ids.return_value = ['identity:1']
        self.related_units.return_value = ['keystone/1']
        hooks.leader_settings_changed()
        mock_write.assert_has_calls(
            [
                call(utils.TOKEN_FLUSH_CRON_FILE),
                call(utils.POLICY_JSON),
            ])
        self.assertTrue(update.called)

    def test_ha_joined(self):
        self.generate_ha_relation_data.return_value = {'rel_data': 'data'}
        hooks.ha_joined(relation_id='rid:23')
        self.relation_set.assert_called_once_with(
            relation_id='rid:23', rel_data='data')

    @patch('keystone_utils.log')
    @patch.object(hooks, 'CONFIGS')
    def test_ha_relation_changed_not_clustered_not_leader(self, configs,
                                                          mock_log):
        self.relation_get.return_value = False

        hooks.ha_changed()
        self.assertTrue(configs.write_all.called)

    @patch.object(hooks, 'relation_ids')
    @patch.object(hooks, 'update_all_fid_backends')
    @patch.object(hooks, 'update_all_domain_backends')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'CONFIGS')
    def test_ha_relation_changed_clustered_leader(self, configs,
                                                  identity_changed,
                                                  mock_log,
                                                  mock_is_db_initialised,
                                                  update_ids,
                                                  update_domains,
                                                  update_fids,
                                                  relation_ids):
        mock_is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        self.relation_get.return_value = True
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']
        relation_ids.return_value = []
        hooks.ha_changed()
        self.assertTrue(configs.write_all.called)
        update_ids.assert_called_once_with()
        update_domains.assert_called_once_with()
        update_fids.assert_called_once_with()

    @patch.object(hooks, 'certs_changed')
    @patch.object(hooks, 'related_units')
    @patch.object(hooks, 'relation_ids')
    @patch.object(hooks, 'update_all_fid_backends')
    @patch.object(hooks, 'update_all_domain_backends')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'CONFIGS')
    def test_ha_relation_changed_clustered_leader_with_certs(
            self,
            configs,
            identity_changed,
            mock_log,
            mock_is_db_initialised,
            update_ids,
            update_domains,
            update_fids,
            relation_ids,
            related_units,
            certs_changed):
        mock_is_db_initialised.return_value = True
        self.is_db_ready.return_value = True
        self.relation_get.return_value = True
        self.relation_ids.return_value = ['identity-service:0']
        self.related_units.return_value = ['unit/0']
        relation_ids.return_value = ['1']
        related_units.return_value = ['2']
        hooks.ha_changed()
        self.assertTrue(configs.write_all.called)
        update_ids.assert_called_once_with()
        update_domains.assert_called_once_with()
        update_fids.assert_called_once_with()
        certs_changed.assert_called_once_with('1', '2')

    @patch('keystone_utils.log')
    @patch.object(hooks, 'CONFIGS')
    def test_configure_https_enable(self, configs, mock_log):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['https']
        configs.write = MagicMock()

        hooks.configure_https()
        self.assertTrue(configs.write_all.called)
        cmd = ['a2ensite', 'openstack_https_frontend']
        self.check_call.assert_called_with(cmd)

    @patch('keystone_utils.log')
    @patch.object(hooks, 'CONFIGS')
    def test_configure_https_disable(self, configs, mock_log):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['']
        configs.write = MagicMock()

        hooks.configure_https()
        self.assertTrue(configs.write_all.called)
        cmd = ['a2dissite', 'openstack_https_frontend']
        self.check_call.assert_called_with(cmd)

    @patch.object(hooks, 'is_bootstrapped')
    @patch.object(utils, 'get_subordinate_release_packages')
    @patch.object(hooks, 'bootstrap_keystone')
    @patch.object(hooks,
                  'ensure_all_service_accounts_protected_for_pci_dss_options')
    @patch.object(hooks, 'maybe_do_policyd_overrides')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(utils, 'os_release')
    @patch.object(hooks, 'is_db_ready')
    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch('keystone_utils.relation_ids')
    @patch.object(hooks, 'stop_manager_instance')
    def test_upgrade_charm_leader(self,
                                  mock_stop_manager_instance,
                                  mock_relation_ids,
                                  mock_log,
                                  mock_is_db_initialised,
                                  mock_is_db_ready,
                                  os_release,
                                  update,
                                  mock_maybe_do_policyd_overrides,
                                  mock_protect_service_accounts,
                                  mock_bootstrap_keystone,
                                  mock_get_subordinate_release_packages,
                                  mock_is_bootstrapped):
        os_release.return_value = 'havana'
        self.os_release.return_value = 'havana'
        mock_is_bootstrapped.return_value = True
        mock_is_db_initialised.return_value = True
        mock_is_db_ready.return_value = True
        mock_relation_ids.return_value = []
        self.remove_old_packages.return_value = True
        self.services.return_value = ['apache2']

        self.filter_installed_packages.return_value = ['something']
        mock_get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        hooks.upgrade_charm()
        self.assertTrue(self.apt_install.called)
        self.assertTrue(update.called)
        self.remove_old_packages.assert_called_once_with()
        self.service_restart.assert_called_with('apache2')
        mock_bootstrap_keystone.assert_called_once_with(configs=ANY)
        mock_stop_manager_instance.assert_called_once_with()
        mock_maybe_do_policyd_overrides.assert_called_once_with(
            ANY, "keystone", restart_handler=ANY)
        mock_protect_service_accounts.assert_called_once_with()

    @patch.object(hooks, 'is_bootstrapped')
    @patch.object(utils, 'get_subordinate_release_packages')
    @patch.object(hooks, 'bootstrap_keystone')
    @patch.object(hooks,
                  'ensure_all_service_accounts_protected_for_pci_dss_options')
    @patch.object(hooks, 'maybe_do_policyd_overrides')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(utils, 'os_release')
    @patch.object(hooks, 'is_db_ready')
    @patch.object(hooks, 'is_db_initialised')
    @patch('keystone_utils.log')
    @patch('keystone_utils.relation_ids')
    @patch.object(hooks, 'stop_manager_instance')
    def test_upgrade_charm_leader_no_packages(
            self,
            mock_stop_manager_instance,
            mock_relation_ids,
            mock_log,
            mock_is_db_initialised,
            mock_is_db_ready,
            os_release,
            update,
            mock_maybe_do_policyd_overrides,
            mock_protect_service_accounts,
            mock_bootstrap_keystone,
            mock_get_subordinate_release_packages,
            mock_is_bootstrapped):
        os_release.return_value = 'havana'
        self.os_release.return_value = 'havana'
        mock_is_db_initialised.return_value = True
        mock_is_db_ready.return_value = True
        mock_is_bootstrapped.return_value = True
        mock_relation_ids.return_value = []
        self.remove_old_packages.return_value = True
        self.services.return_value = ['apache2']

        self.filter_installed_packages.return_value = []
        mock_get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        hooks.upgrade_charm()
        self.assertFalse(self.apt_install.called)
        self.assertTrue(update.called)
        self.remove_old_packages.assert_called_once_with()
        self.service_restart.assert_called_with('apache2')
        mock_bootstrap_keystone.assert_called_once_with(configs=ANY)
        mock_stop_manager_instance.assert_called_once_with()
        mock_maybe_do_policyd_overrides.assert_called_once_with(
            ANY, "keystone", restart_handler=ANY)
        mock_protect_service_accounts.assert_called_once_with()

    @patch.object(hooks, 'is_bootstrapped')
    @patch.object(hooks, 'bootstrap_keystone')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'is_db_initialised')
    def test_leader_init_db_if_ready(self, is_db_initialized,
                                     update, mock_bootstrap_keystone,
                                     is_boostrapped):
        """ Verify leader initilaizes db """
        self.is_elected_leader.return_value = True
        is_db_initialized.return_value = False
        is_boostrapped.return_value = False
        self.is_db_ready.return_value = True
        self.os_release.return_value = 'mitaka'
        hooks.leader_init_db_if_ready()
        self.is_db_ready.assert_called_with(use_current_context=False)
        self.migrate_database.assert_called_with()
        mock_bootstrap_keystone.assert_called_once_with(configs=ANY)
        update.assert_called_with()

    @patch.object(hooks, 'update_all_identity_relation_units')
    def test_leader_init_db_not_leader(self, update):
        """ Verify non-leader does not initilaize db """
        self.is_elected_leader.return_value = False
        hooks.leader_init_db_if_ready()
        self.is_elected_leader.assert_called_with('grp_ks_vips')
        self.log.assert_called_with("Not leader - skipping db init",
                                    level='DEBUG')
        self.assertFalse(self.migrate_database.called)
        self.assertFalse(update.called)

    @patch.object(hooks, 'is_bootstrapped')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'is_db_initialised')
    def test_leader_init_db_not_initilaized(self, is_db_initialized, update,
                                            is_bootstrapped):
        """ Verify leader does not initilaize db when already initialized """
        self.os_release.return_value = 'havana'
        self.is_elected_leader.return_value = True
        is_db_initialized.return_value = True
        is_bootstrapped.return_value = True
        hooks.leader_init_db_if_ready()
        self.assertFalse(self.migrate_database.called)
        self.assertFalse(self.bootstrap_keystone.called)
        self.assertTrue(update.called)

    @patch.object(hooks, 'is_bootstrapped')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'is_db_initialised')
    def test_leader_init_db_not_initilaized_not_bootstrapped(
            self, is_db_initialized, update, is_bootstrapped):
        """ Verify leader does not initilaize db when already initialized """
        self.os_release.return_value = 'havana'
        self.is_elected_leader.return_value = True
        is_db_initialized.return_value = True
        is_bootstrapped.return_value = False
        hooks.leader_init_db_if_ready()
        self.assertFalse(self.migrate_database.called)
        self.assertTrue(self.bootstrap_keystone.called)
        self.assertTrue(update.called)

    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'is_db_initialised')
    def test_leader_init_db_not_ready(self, is_db_initialized, update):
        """ Verify leader does not initilaize db when db not ready """
        self.is_elected_leader.return_value = True
        is_db_initialized.return_value = False
        self.is_db_ready.return_value = False
        hooks.leader_init_db_if_ready()
        self.is_db_ready.assert_called_with(use_current_context=False)
        self.log.assert_called_with('Allowed_units list provided and this '
                                    'unit not present', level='INFO')
        self.assertFalse(self.migrate_database.called)
        self.assertFalse(update.called)

    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'admin_relation_changed')
    @patch.object(hooks, 'identity_credentials_changed')
    @patch.object(hooks, 'identity_changed')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'CONFIGS')
    def test_update_all_identity_relation_units(self, configs,
                                                is_db_initialized,
                                                identity_changed,
                                                identity_credentials_changed,
                                                admin_relation_changed,
                                                configure_https):
        """ Verify all identity relations are updated """
        self.check_api_application_ready.return_value = (True, 'msg')
        is_db_initialized.return_value = True
        self.relation_ids.return_value = ['identity-relation:0']
        self.related_units.return_value = ['unit/0']
        log_calls = [call('Firing identity_changed hook for all related '
                          'services.'),
                     call('Firing admin_relation_changed hook for all related '
                          'services.'),
                     call('Firing identity_credentials_changed hook for all '
                          'related services.')]
        hooks.update_all_identity_relation_units()
        identity_changed.assert_called_with(
            relation_id='identity-relation:0',
            remote_unit='unit/0')
        identity_credentials_changed.assert_called_with(
            relation_id='identity-relation:0',
            remote_unit='unit/0')
        admin_relation_changed.assert_called_with('identity-relation:0')
        self.log.assert_has_calls(log_calls, any_order=True)

    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'CONFIGS')
    def test_update_all_db_not_ready(self, configs, configure_https):
        """ Verify update identity relations when DB is not ready """
        self.check_api_application_ready.return_value = (False, 'msg')
        hooks.update_all_identity_relation_units()
        self.log.assert_called_with(
            ("Keystone charm unit not ready - deferring identity-relation "
             "updates"),
            level='INFO')
        self.assertFalse(self.relation_ids.called)

    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'CONFIGS')
    def test_update_all_leader(self, configs, configure_https):
        """ Verify update identity relations when the leader"""
        self.check_api_application_ready.return_value = (True, 'msg')
        hooks.update_all_identity_relation_units()
        # Still updates relations
        self.assertTrue(self.relation_ids.called)

    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'CONFIGS')
    def test_update_all_not_leader(self, configs, configure_https):
        """ Verify update identity relations when not the leader"""
        self.check_api_application_ready.return_value = (True, 'msg')
        self.is_elected_leader.return_value = False
        hooks.update_all_identity_relation_units()
        self.assertFalse(self.ensure_initial_admin.called)
        # Still updates relations
        self.assertTrue(self.relation_ids.called)

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch.object(hooks, 'bootstrap_keystone')
    @patch.object(hooks, 'maybe_do_policyd_overrides')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(utils, 'os_release')
    @patch('keystone_utils.log')
    @patch('keystone_utils.relation_ids')
    @patch.object(hooks, 'stop_manager_instance')
    def test_upgrade_charm_not_leader(self,
                                      mock_stop_manager_instance,
                                      mock_relation_ids,
                                      mock_log,
                                      os_release, update,
                                      mock_maybe_do_policyd_overrides,
                                      mock_bootstrap_keystone,
                                      mock_get_subordinate_release_packages):
        os_release.return_value = 'havana'

        self.filter_installed_packages.return_value = ['something']
        self.is_elected_leader.return_value = False
        mock_get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        hooks.upgrade_charm()
        self.assertTrue(self.apt_install.called)
        self.assertTrue(self.log.called)
        self.assertFalse(update.called)
        mock_bootstrap_keystone.assert_called_once_with(configs=ANY)
        mock_stop_manager_instance.assert_called_once()
        mock_maybe_do_policyd_overrides.assert_called_once_with(
            ANY, "keystone", restart_handler=ANY)

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch.object(hooks, 'bootstrap_keystone')
    @patch.object(hooks, 'maybe_do_policyd_overrides')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(utils, 'os_release')
    @patch('keystone_utils.log')
    @patch('keystone_utils.relation_ids')
    @patch.object(hooks, 'stop_manager_instance')
    def test_upgrade_charm_not_leader_no_packages(
        self,
        mock_stop_manager_instance,
        mock_relation_ids,
        mock_log,
        os_release,
        update,
        mock_maybe_do_policyd_overrides,
        mock_bootstrap_keystone,
        mock_get_subordinate_release_packages,
    ):
        os_release.return_value = 'havana'

        self.filter_installed_packages.return_value = []
        self.is_elected_leader.return_value = False
        mock_get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        hooks.upgrade_charm()
        self.assertFalse(self.apt_install.called)
        self.assertTrue(self.log.called)
        self.assertFalse(update.called)
        mock_bootstrap_keystone.assert_called_once_with(configs=ANY)
        mock_stop_manager_instance.assert_called_once()
        mock_maybe_do_policyd_overrides.assert_called_once_with(
            ANY, "keystone", restart_handler=ANY)

    def test_domain_backend_changed_v2(self):
        self.get_api_version.return_value = 2
        hooks.domain_backend_changed()
        self.assertTrue(self.get_api_version.called)
        self.assertFalse(self.relation_get.called)

    def test_domain_backend_changed_incomplete(self):
        self.get_api_version.return_value = 3
        self.relation_get.return_value = None
        hooks.domain_backend_changed()
        self.assertTrue(self.get_api_version.called)
        self.relation_get.assert_called_with(
            attribute='domain-name',
            unit=None,
            rid=None
        )
        self.assertFalse(self.is_leader.called)

    @patch.object(hooks, 'is_unit_paused_set')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'restart_pid_check')
    def test_domain_backend_changed_complete(self,
                                             restart_pid_check,
                                             run_in_apache,
                                             is_db_initialised,
                                             is_unit_paused_set):
        run_in_apache.return_value = True
        self.get_api_version.return_value = 3
        self.relation_get.side_effect = ['mydomain', 'nonce2']
        self.is_leader.return_value = True
        self.is_db_ready.return_value = True
        is_db_initialised.return_value = True
        mock_kv = MagicMock()
        mock_kv.get.return_value = None
        self.unitdata.kv.return_value = mock_kv
        is_unit_paused_set.return_value = False

        hooks.domain_backend_changed()

        self.assertTrue(self.get_api_version.called)
        self.relation_get.assert_has_calls([
            call(attribute='domain-name',
                 unit=None,
                 rid=None),
            call(attribute='restart-nonce',
                 unit=None,
                 rid=None),
        ])
        self.create_or_show_domain.assert_called_with('mydomain')
        restart_pid_check.assert_called_with('apache2')
        mock_kv.set.assert_called_with('domain-restart-nonce-mydomain',
                                       'nonce2')
        self.assertTrue(mock_kv.flush.called)

    @patch.object(hooks, 'is_unit_paused_set')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'restart_pid_check')
    def test_domain_backend_changed_complete_follower(self,
                                                      restart_pid_check,
                                                      run_in_apache,
                                                      is_db_initialised,
                                                      is_unit_paused_set):
        run_in_apache.return_value = True
        self.get_api_version.return_value = 3
        self.relation_get.side_effect = ['mydomain', 'nonce2']
        self.is_leader.return_value = False
        self.is_db_ready.return_value = True
        is_db_initialised.return_value = True
        mock_kv = MagicMock()
        mock_kv.get.return_value = None
        self.unitdata.kv.return_value = mock_kv
        is_unit_paused_set.return_value = False

        hooks.domain_backend_changed()

        self.assertTrue(self.get_api_version.called)
        self.relation_get.assert_has_calls([
            call(attribute='domain-name',
                 unit=None,
                 rid=None),
            call(attribute='restart-nonce',
                 unit=None,
                 rid=None),
        ])
        # Only lead unit will create the domain
        self.assertFalse(self.create_or_show_domain.called)
        restart_pid_check.assert_called_with('apache2')
        mock_kv.set.assert_called_with('domain-restart-nonce-mydomain',
                                       'nonce2')
        self.assertTrue(mock_kv.flush.called)

    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'relation_id')
    @patch.object(hooks, 'is_unit_paused_set')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'restart_pid_check')
    def test_fid_service_provider_changed_complete(
            self,
            restart_pid_check,
            run_in_apache,
            is_db_initialised,
            is_unit_paused_set,
            relation_id, os_release):
        os_release.return_value = 'ocata'
        rel = 'keystone-fid-service-provider:0'
        relation_id.return_value = rel
        run_in_apache.return_value = True
        self.get_api_version.return_value = 3
        self.relation_get.side_effect = ['"nonce2"']
        self.is_leader.return_value = True
        self.is_db_ready.return_value = True
        is_db_initialised.return_value = True
        self.resolve_address.return_value = "10.0.0.10"
        mock_kv = MagicMock()
        mock_kv.get.return_value = None
        self.unitdata.kv.return_value = mock_kv
        is_unit_paused_set.return_value = False

        hooks.keystone_fid_service_provider_changed()

        self.assertTrue(self.get_api_version.called)
        self.relation_get.assert_has_calls([
            call('restart-nonce'),
        ])
        restart_pid_check.assert_called_with('apache2')
        mock_kv.set.assert_called_with(
            'fid-restart-nonce-{}'.format(rel), 'nonce2')
        self.assertTrue(mock_kv.flush.called)

    @patch.object(hooks, 'os_release')
    @patch.object(hooks, 'relation_id')
    @patch.object(hooks, 'is_unit_paused_set')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'restart_pid_check')
    def test_fid_service_provider_changed_complete_follower(
            self,
            restart_pid_check,
            run_in_apache,
            is_db_initialised,
            is_unit_paused_set,
            relation_id, os_release):
        os_release.return_value = 'ocata'
        rel = 'keystone-fid-service-provider:0'
        relation_id.return_value = rel
        run_in_apache.return_value = True
        self.get_api_version.return_value = 3
        self.relation_get.side_effect = ['"nonce2"']
        self.is_leader.return_value = False
        self.is_db_ready.return_value = True
        is_db_initialised.return_value = True
        mock_kv = MagicMock()
        mock_kv.get.return_value = None
        self.unitdata.kv.return_value = mock_kv
        is_unit_paused_set.return_value = False
        self.resolve_address.return_value = "10.0.0.10"

        hooks.keystone_fid_service_provider_changed()

        self.assertTrue(self.get_api_version.called)
        self.relation_get.assert_has_calls([
            call('restart-nonce'),
        ])
        restart_pid_check.assert_called_with('apache2')
        mock_kv.set.assert_called_with(
            'fid-restart-nonce-{}'.format(rel),
            'nonce2')
        self.assertTrue(mock_kv.flush.called)

    def test_update_keystone_fid_service_provider_no_tls(self):
        self.relation_ids.return_value = []
        public_addr = "10.0.0.10"
        self.resolve_address.return_value = public_addr
        relation_id = "keystone-fid-service-provider-certificates:5"
        relation_settings = {
            'hostname': '"{}"'.format(public_addr),
            'port': '5000',
            'tls-enabled': 'false'
        }
        hooks.update_keystone_fid_service_provider(relation_id=relation_id)
        self.relation_set.assert_called_once_with(
            relation_id=relation_id, relation_settings=relation_settings)

    def test_update_keystone_fid_service_provider_tls_certificates_relation(
            self):
        self.relation_ids.return_value = ["certficates:9"]
        public_addr = "10.0.0.10"
        self.resolve_address.return_value = public_addr
        relation_id = "keystone-fid-service-provider-certificates:5"
        relation_settings = {
            'hostname': '"{}"'.format(public_addr),
            'port': '5000',
            'tls-enabled': 'true'
        }
        hooks.update_keystone_fid_service_provider(relation_id=relation_id)
        self.relation_set.assert_called_once_with(
            relation_id=relation_id, relation_settings=relation_settings)

    def test_update_keystone_fid_service_provider_ssl_config(self):
        self.test_config.set("ssl_cert", "CERTIFICATE")
        self.test_config.set("ssl_key", "KEY")
        self.relation_ids.return_value = []
        public_addr = "10.0.0.10"
        self.resolve_address.return_value = public_addr
        relation_id = "keystone-fid-service-provider-certificates:5"
        relation_settings = {
            'hostname': '"{}"'.format(public_addr),
            'port': '5000',
            'tls-enabled': 'true'
        }
        hooks.update_keystone_fid_service_provider(relation_id=relation_id)
        self.relation_set.assert_called_once_with(
            relation_id=relation_id, relation_settings=relation_settings)

    @patch.object(hooks, 'relation_set')
    @patch.object(hooks, 'get_certificate_request')
    def test_certs_joined(self, get_certificate_request, relation_set):
        get_certificate_request.return_value = {'cn': 'this-unit'}
        hooks.certs_joined(relation_id='rid:23')
        relation_set.assert_called_once_with(
            relation_id='rid:23',
            relation_settings={'cn': 'this-unit'})

    @patch.object(hooks, 'update_all_fid_backends')
    @patch.object(hooks, 'config')
    @patch.object(hooks, 'update_all_domain_backends')
    @patch.object(hooks, 'update_all_identity_relation_units')
    @patch.object(hooks, 'ensure_initial_admin')
    @patch.object(hooks, 'is_unit_paused_set')
    @patch.object(hooks, 'is_elected_leader')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'process_certificates')
    def test_certs_changed(self, process_certificates, configure_https,
                           is_db_initialised,
                           is_elected_leader, is_unit_paused_set,
                           ensure_initial_admin,
                           update_all_identity_relation_units,
                           update_all_domain_backends, config,
                           update_all_fid_backends):
        is_db_initialised.return_value = True
        is_elected_leader.return_value = True
        is_unit_paused_set.return_value = False
        process_certificates.return_value = False
        hooks.certs_changed()
        process_certificates.assert_called_once_with('keystone', None, None)
        self.assertFalse(configure_https.called)
        self.assertFalse(ensure_initial_admin.called)
        process_certificates.reset_mock()
        process_certificates.return_value = True
        hooks.certs_changed()
        configure_https.assert_called_once_with()
        is_db_initialised.assert_called_once_with()
        is_elected_leader.assert_called_once_with('grp_ks_vips')
        is_unit_paused_set.assert_called_once_with()
        ensure_initial_admin.assert_called_once_with(config)
        update_all_identity_relation_units.assert_called_once_with()
        update_all_domain_backends.assert_called_once_with()
        update_all_fid_backends.assert_called_once_with()

        ensure_initial_admin.reset_mock()
        is_db_initialised.return_value = False
        hooks.certs_changed()
        self.assertFalse(ensure_initial_admin.called)

    @patch.object(hooks, 'relation_set')
    @patch.object(hooks, 'os_release')
    def test_keystone_middleware_notify_release(
            self,
            os_release,
            relation_set):
        self.relation_ids.return_value = ['keystone-middleware:0']
        os_release.return_value = 'Pike'
        hooks.keystone_middleware_joined()
        relation_set.assert_called_once_with(
            relation_id='keystone-middleware:0', release='Pike')

    @patch.object(hooks, 'notify_middleware_with_release_version')
    @patch.object(hooks, 'CONFIGS')
    def test_keystone_middleware_config_changed(
            self,
            configs,
            notify_middleware_with_release_version):
        hooks.keystone_middleware_changed()
        self.assertTrue(configs.write.called)
        self.assertFalse(notify_middleware_with_release_version.called)
