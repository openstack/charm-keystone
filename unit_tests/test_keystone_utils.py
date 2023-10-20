# Copyright 2016 Canonical Ltd
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

import builtins
import collections
import copy
from unittest.mock import ANY, patch, call, MagicMock, mock_open, Mock
import json
import os
import subprocess
import time

import charmhelpers.contrib.openstack.utils as os_utils

from test_utils import CharmTestCase

import keystone_types as ks_types

os.environ['JUJU_UNIT_NAME'] = 'keystone'
with patch('charmhelpers.core.hookenv.config') as config, \
        patch('charmhelpers.contrib.openstack.'
              'utils.snap_install_requested',
              Mock(return_value=False)):
    import importlib
    import keystone_utils as utils
    # we have to force utils to reload as another test module may already have
    # pulled it in, and thus all this fancy patching will just fail
    importlib.reload(utils)

TO_PATCH = [
    'api_port',
    'config',
    'os_release',
    'log',
    'create_role',
    'create_service_entry',
    'create_endpoint_template',
    'get_local_endpoint',
    'get_requested_roles',
    'get_service_password',
    'get_os_codename_install_source',
    'grant_role',
    'configure_installation_source',
    'https',
    'lsb_release',
    'peer_store_and_set',
    'service_stop',
    'service_start',
    'snap_install_requested',
    'relation_get',
    'relation_set',
    'relation_ids',
    'relation_id',
    'local_unit',
    'related_units',
    'https',
    'mkdir',
    'write_file',
    # generic
    'apt_update',
    'apt_upgrade',
    'apt_install',
    'subprocess',
    'time',
    'pwgen',
    'os_application_version_set',
    'os_application_status_set',
    'reset_os_release',
]


class TestKeystoneUtils(CharmTestCase):

    def setUp(self):
        super(TestKeystoneUtils, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.snap_install_requested.return_value = False

        self.ctxt = MagicMock()
        self.rsc_map = {
            '/etc/keystone/keystone.conf': {
                'services': ['keystone'],
                'contexts': [self.ctxt],
            },
            '/etc/apache2/sites-available/openstack_https_frontend': {
                'services': ['apache2'],
                'contexts': [self.ctxt],
            },
            '/etc/apache2/sites-available/openstack_https_frontend.conf': {
                'services': ['apache2'],
                'contexts': [self.ctxt],
            }
        }
        self.get_os_codename_install_source.return_value = 'icehouse'

    @patch('charmhelpers.contrib.openstack.templating.OSConfigRenderer')
    @patch('os.path.exists')
    @patch.object(utils, 'resource_map')
    def test_register_configs_apache(self, resource_map, exists, renderer):
        exists.return_value = False
        self.os_release.return_value = 'havana'
        fake_renderer = MagicMock()
        fake_renderer.register = MagicMock()
        renderer.return_value = fake_renderer

        resource_map.return_value = self.rsc_map
        utils.register_configs()
        renderer.assert_called_with(
            openstack_release='havana', templates_dir='templates/')

        ex_reg = [
            call('/etc/keystone/keystone.conf', [self.ctxt]),
            call(
                '/etc/apache2/sites-available/openstack_https_frontend',
                [self.ctxt]),
            call(
                '/etc/apache2/sites-available/openstack_https_frontend.conf',
                [self.ctxt]),
        ]
        fake_renderer.register.assert_has_calls(ex_reg, any_order=True)

    def test_resource_map_exclude_policy_json_before_liberty(self):
        resources = self._test_resource_map(os_release='kilo')
        self.assertFalse('/etc/keystone/policy.json' in resources.keys())

    def test_resource_map_include_policy_json_from_liberty(self):
        resources = self._test_resource_map(os_release='liberty')
        self.assertTrue('/etc/keystone/policy.json' in resources.keys())

    def test_resource_map_apache24_conf_present_if_conf_avail_present(self):
        resources = self._test_resource_map(os_path_return_value=True)
        self.assertTrue(
            '/etc/apache2/sites-available/openstack_https_frontend.conf'
            in resources.keys())

    def test_resource_map_apache24_conf_absent_if_conf_avail_absent(self):
        resources = self._test_resource_map(os_path_return_value=False)
        self.assertFalse(
            '/etc/apache2/sites-available/openstack_https_frontend.conf'
            in resources.keys())

    def test_resource_map_excludes_apache_files_if_using_snap(self):
        resources = self._test_resource_map(use_snap=True)
        for config_file in (
                '/etc/apache2/sites-available/openstack_https_frontend',
                '/etc/apache2/sites-available/openstack_https_frontend.conf',
        ):
            self.assertFalse(config_file in resources.keys())

    def test_resource_map_ensure_snap_includes_nginx_and_uwsgi(self):
        resources = self._test_resource_map(use_snap=True)
        required_services = ('snap.keystone.nginx', 'snap.keystone.uwsgi')
        for cfile in resources:
            services = resources[cfile]['services']
            self.assertTrue(all(service in services)
                            for service in required_services)

    def test_resource_map_enable_memcache_mitaka(self):
        resources = self._test_resource_map(os_release='mitaka')
        self.assertTrue('/etc/memcached.conf' in resources.keys())

    def test_resource_map_enable_memcache_liberty(self):
        resources = self._test_resource_map(os_release='liberty')
        self.assertFalse('/etc/memcached.conf' in resources.keys())

    @patch.object(utils, 'snap_install_requested')
    @patch.object(utils, 'os')
    def _test_resource_map(self, mock_os, snap_install_requested,
                           os_release='mitaka',
                           use_snap=False,
                           os_path_return_value=False):
        self.os_release.return_value = os_release
        snap_install_requested.return_value = use_snap
        mock_os.path.exists.return_value = os_path_return_value
        resource_map = utils.resource_map()
        return resource_map

    def test_determine_ports(self):
        self.test_config.set('admin-port', '80')
        self.test_config.set('service-port', '81')
        result = utils.determine_ports()
        self.assertEqual(result, ['80', '81'])

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch('charmhelpers.contrib.openstack.utils.config')
    def test_determine_packages(
            self,
            _config,
            _get_subordinate_release_packages):
        self.os_release.return_value = 'havana'
        self.snap_install_requested.return_value = False
        _config.return_value = None
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES + ['keystone', 'python-keystoneclient']
        self.assertEqual(set(ex), set(result))
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(['sub-pkg']), set())
        self.assertIn('sub-pkg', utils.determine_packages())

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch('charmhelpers.contrib.openstack.utils.config')
    def test_determine_packages_queens(
            self,
            _config,
            _get_subordinate_release_packages):
        self.os_release.return_value = 'queens'
        self.snap_install_requested.return_value = False
        _config.return_value = None
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES + [
            'keystone', 'python-keystoneclient', 'memcached',
            'libapache2-mod-wsgi'
        ]
        self.assertEqual(set(ex), set(result))

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch('charmhelpers.contrib.openstack.utils.config')
    def test_determine_packages_rocky(
            self,
            _config,
            _get_subordinate_release_packages):
        self.os_release.return_value = 'rocky'
        self.snap_install_requested.return_value = False
        _config.return_value = None
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        result = utils.determine_packages()
        ex = list(set(
            [p for p in utils.BASE_PACKAGES if not p.startswith('python-')] +
            ['memcached'] + utils.PY3_PACKAGES))
        self.assertEqual(set(ex), set(result))

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch('charmhelpers.contrib.openstack.utils.config')
    def test_determine_packages_snap_install(
            self,
            _config,
            _get_subordinate_release_packages):
        self.os_release.return_value = 'mitaka'
        self.snap_install_requested.return_value = True
        _config.return_value = None
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES_SNAP + ['memcached']
        self.assertEqual(set(ex), set(result))
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(['sub-snap']), set())
        self.assertIn('sub-snap', utils.determine_packages())

    @patch.object(utils, 'get_subordinate_release_packages')
    def test_determine_purge_packages(self, _get_subordinate_release_packages):
        'Ensure no packages are identified for purge prior to rocky'
        self.os_release.return_value = 'queens'
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        self.assertEqual(utils.determine_purge_packages(), [])
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set(['sub-purge']))
        self.assertEqual(utils.determine_purge_packages(), ['sub-purge'])

    @patch.object(utils, 'get_subordinate_release_packages')
    def test_determine_purge_packages_rocky(
            self,
            _get_subordinate_release_packages):
        'Ensure python packages are identified for purge at rocky'
        self.os_release.return_value = 'rocky'
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())
        self.assertEqual(utils.determine_purge_packages(),
                         sorted([p for p in utils.BASE_PACKAGES
                                 if p.startswith('python-')] +
                                ['python-keystone', 'python-memcache']))
        _get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set(['sub-purge']))
        self.assertIn('sub-purge', utils.determine_purge_packages())

    @patch.object(utils, 'get_subordinate_release_packages')
    @patch.object(utils, 'bootstrap_keystone')
    @patch.object(utils, 'is_elected_leader')
    @patch.object(utils, 'disable_unused_apache_sites')
    @patch('os.path.exists')
    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'determine_packages')
    @patch.object(utils, 'migrate_database')
    def test_openstack_upgrade_leader(
            self, migrate_database, determine_packages,
            run_in_apache, os_path_exists, disable_unused_apache_sites,
            mock_is_elected_leader, mock_bootstrap_keystone,
            mock_get_subordinate_release_packages):
        configs = MagicMock()
        self.test_config.set('openstack-origin', 'cloud:xenial-newton')
        self.os_release.return_value = 'ocata'
        determine_packages.return_value = []
        os_path_exists.return_value = True
        run_in_apache.return_value = True
        mock_get_subordinate_release_packages.return_value = \
            os_utils.SubordinatePackages(set(), set())

        utils.do_openstack_upgrade(configs)

        self.get_os_codename_install_source.assert_called_with(
            'cloud:xenial-newton'
        )
        self.configure_installation_source.assert_called_with(
            'cloud:xenial-newton'
        )
        self.assertTrue(self.apt_update.called)

        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        self.apt_upgrade.assert_called_with(
            options=dpkg_opts,
            fatal=True,
            dist=True)
        self.apt_install.assert_called_with(
            packages=[],
            options=dpkg_opts,
            fatal=True)

        self.assertTrue(configs.set_release.called)
        self.assertTrue(configs.write_all.called)
        self.assertTrue(migrate_database.called)
        mock_bootstrap_keystone.assert_called_once_with(configs=ANY)
        disable_unused_apache_sites.assert_called_with()
        self.reset_os_release.assert_called()

    @patch.object(utils, 'leader_get')
    def test_is_db_initialised_true_string(self, _leader_get):
        _leader_get.return_value = "True"
        self.assertTrue(utils.is_db_initialised())

    @patch.object(utils, 'leader_get')
    def test_is_db_initialised_true_bool(self, _leader_get):
        _leader_get.return_value = True
        self.assertTrue(utils.is_db_initialised())

    @patch.object(utils, 'leader_get')
    def test_is_db_initialised_not_set(self, _leader_get):
        _leader_get.return_value = None
        self.assertFalse(utils.is_db_initialised())

    @patch.object(utils, 'stop_manager_instance')
    @patch.object(utils, 'leader_set')
    def test_migrate_database(self, _leader_set, mock_stop_manager_instance):
        self.os_release.return_value = 'havana'
        utils.migrate_database()

        self.service_stop.assert_called_with('keystone')
        cmd = ['sudo', '-u', 'keystone', 'keystone-manage', 'db_sync']
        self.subprocess.check_output.assert_called_with(cmd)
        self.service_start.assert_called_with('keystone')
        _leader_set.assert_called_with({'db-initialised': True})
        mock_stop_manager_instance.assert_called_once_with()

    @patch.object(utils, 'get_real_role_names')
    @patch.object(utils, 'leader_get')
    @patch.object(utils, 'get_api_version')
    @patch.object(utils, 'get_manager')
    @patch.object(utils, 'resolve_address')
    def test_add_service_to_keystone_clustered_https_none_values(
            self, _resolve_address, _get_manager,
            _get_api_version, _leader_get,
            _get_real_role_names):
        _get_real_role_names.return_value = ['Member', 'SpecialRole']
        _get_api_version.return_value = 2
        _leader_get.return_value = None
        relation_id = 'identity-service:0'
        remote_unit = 'unit/0'
        _resolve_address.return_value = '10.10.10.10'
        self.https.return_value = True
        self.test_config.set('vip', '10.10.10.10')
        self.test_config.set('admin-port', 80)
        self.test_config.set('service-port', 81)
        self.get_requested_roles.return_value = ['role1', ]

        self.relation_get.return_value = {'service': 'keystone',
                                          'region': 'RegionOne',
                                          'public_url': 'None',
                                          'admin_url': '10.0.0.2',
                                          'internal_url': '192.168.1.2'}

        utils.add_service_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        self.assertTrue(self.https.called)
        self.assertTrue(self.create_role.called)

        relation_data = {'auth_host': '10.10.10.10',
                         'service_host': '10.10.10.10',
                         'service_protocol': 'https',
                         'auth_port': 80,
                         'auth_protocol': 'https',
                         'service_port': 81,
                         'service_type': 'identity',
                         'internal_host': '10.10.10.10',
                         'internal_protocol': 'https',
                         'internal_port': 81,
                         'region': 'RegionOne',
                         'api_version': 2,
                         'admin_domain_id': None,
                         'created_roles': 'Member,SpecialRole'}
        self.peer_store_and_set.assert_called_with(relation_id=relation_id,
                                                   **relation_data)

    @patch.object(utils, 'get_real_role_names')
    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_set')
    @patch.object(utils, 'leader_get')
    @patch.object(utils, 'get_api_version')
    @patch.object(utils, 'create_user')
    @patch.object(utils, 'resolve_address')
    @patch.object(utils, 'ensure_valid_service')
    @patch.object(utils, 'add_endpoint')
    @patch.object(utils, 'get_manager')
    def test_add_service_to_keystone_no_clustered_no_https_complete_values(
            self, KeystoneManager, add_endpoint, ensure_valid_service,
            _resolve_address, create_user, get_api_version, leader_get,
            leader_set, is_leader, _get_real_role_names, test_api_version=2):
        _get_real_role_names.return_value = ['Member', 'SpecialRole']
        get_api_version.return_value = test_api_version
        leader_get.return_value = None
        is_leader.return_value = True
        relation_id = 'identity-service:0'
        remote_unit = 'unit/0'
        self.get_service_password.return_value = 'password'
        self.test_config.set('service-tenant', 'tenant')
        self.test_config.set('admin-role', 'Admin')
        self.get_requested_roles.return_value = ['role1', ]
        _resolve_address.return_value = '10.0.0.3'
        self.test_config.set('admin-port', 80)
        self.test_config.set('service-port', 81)
        self.https.return_value = False
        self.get_local_endpoint.return_value = 'http://localhost:80/v2.0/'
        self.relation_ids.return_value = ['cluster/0']

        service_domain = None
        service_domain_id = None
        service_role = 'Admin'
        admin_project_id = None
        admin_user_id = None
        if test_api_version > 2:
            service_domain = 'service_domain'
            service_domain_id = '1234567890'
            admin_user_id = 'foobar-user'
            admin_project_id = 'tenant_id'

        mock_keystone = MagicMock()
        mock_keystone.resolve_tenant_id.return_value = 'tenant_id'
        mock_keystone.resolve_domain_id.return_value = service_domain_id
        if test_api_version > 2:
            mock_keystone.resolve_user_id.return_value = admin_user_id
        else:
            mock_keystone.resolve_user_id.return_value = None
        KeystoneManager.return_value = mock_keystone

        self.relation_get.return_value = {'service': 'keystone',
                                          'region': 'RegionOne',
                                          'public_url': '10.0.0.1',
                                          'admin_url': '10.0.0.2',
                                          'internal_url': '192.168.1.2'}

        mock_keystone.user_exists.return_value = False
        utils.add_service_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        ensure_valid_service.assert_called_with('keystone')
        add_endpoint.assert_called_with(region='RegionOne', service='keystone',
                                        publicurl='10.0.0.1',
                                        adminurl='10.0.0.2',
                                        internalurl='192.168.1.2')
        self.get_service_password.assert_called_with('keystone')
        create_user.assert_called_with('keystone', 'password',
                                       domain=service_domain,
                                       tenant='tenant')
        self.grant_role.assert_called_with('keystone', service_role,
                                           project_domain=service_domain,
                                           tenant='tenant',
                                           user_domain=service_domain)
        self.create_role.assert_called_with('role1', user='keystone',
                                            tenant='tenant',
                                            domain=service_domain)

        relation_data = {'admin_domain_id': None,
                         'admin_user_id': admin_user_id,
                         'admin_project_id': admin_project_id,
                         'admin_role': 'Admin',
                         'auth_host': '10.0.0.3',
                         'service_host': '10.0.0.3',
                         'service_port': 81, 'auth_port': 80,
                         'internal_host': '10.0.0.3',
                         'internal_protocol': 'http',
                         'internal_port': 81,
                         'service_username': 'keystone',
                         'service_user_id': admin_user_id,
                         'service_password': 'password',
                         'service_domain': service_domain,
                         'service_domain_id': service_domain_id,
                         'service_tenant': 'tenant',
                         'service_type': 'identity',
                         'https_keystone': '__null__',
                         'ssl_cert': '__null__', 'ssl_key': '__null__',
                         'ca_cert': '__null__',
                         'auth_protocol': 'http', 'service_protocol': 'http',
                         'service_tenant_id': 'tenant_id',
                         'api_version': test_api_version,
                         'created_roles': 'Member,SpecialRole'}

        filtered = collections.OrderedDict()
        for k, v in relation_data.items():
            if v == '__null__':
                filtered[k] = None
            else:
                filtered[k] = v

        self.assertTrue(self.relation_set.called)
        self.peer_store_and_set.assert_called_with(relation_id=relation_id,
                                                   **relation_data)
        self.relation_set.assert_called_with(relation_id=relation_id,
                                             **filtered)
        if test_api_version > 2:
            mock_keystone.resolve_domain_id.assert_called_with(service_domain)

    def test_add_service_to_keystone_no_clustered_no_https_complete_values_v3(
            self):
        return self.\
            test_add_service_to_keystone_no_clustered_no_https_complete_values(
                test_api_version=3)

    @patch.object(utils, 'leader_set')
    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_get')
    @patch('charmhelpers.contrib.openstack.ip.config')
    @patch.object(utils, 'ensure_valid_service')
    @patch.object(utils, 'add_endpoint')
    @patch.object(utils, 'get_manager')
    def test_add_service_to_keystone_nosubset(
            self, KeystoneManager, add_endpoint, ensure_valid_service,
            ip_config, leader_get, is_leader, leader_set):
        relation_id = 'identity-service:0'
        remote_unit = 'unit/0'

        self.relation_get.return_value = {'ec2_service': 'nova',
                                          'ec2_region': 'RegionOne',
                                          'ec2_public_url': '10.0.0.1',
                                          'ec2_admin_url': '10.0.0.2',
                                          'ec2_internal_url': '192.168.1.2'}
        self.get_local_endpoint.return_value = 'http://localhost:80/v2.0/'
        KeystoneManager.resolve_tenant_id.return_value = 'tenant_id'
        KeystoneManager.user_exists.return_value = False
        leader_get.return_value = None

        utils.add_service_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        ensure_valid_service.assert_called_with('nova')
        add_endpoint.assert_called_with(region='RegionOne', service='nova',
                                        publicurl='10.0.0.1',
                                        adminurl='10.0.0.2',
                                        internalurl='192.168.1.2',
                                        list_services=ANY,
                                        list_endpoints=ANY)

    @patch.object(utils, 'get_real_role_names')
    @patch.object(utils, 'get_requested_roles')
    @patch.object(utils, 'create_service_credentials')
    @patch.object(utils, 'leader_get')
    @patch('charmhelpers.contrib.openstack.ip.config')
    @patch.object(utils, 'ensure_valid_service')
    @patch.object(utils, 'add_endpoint')
    @patch.object(utils, 'get_manager')
    def test_add_service_to_keystone_multi_endpoints_bug_1739409(
            self, KeystoneManager, add_endpoint, ensure_valid_service,
            ip_config, leader_get, create_service_credentials,
            get_requested_roles, _get_real_role_names):
        _get_real_role_names.return_value = ['Member', 'SpecialRole']
        relation_id = 'identity-service:8'
        remote_unit = 'nova-cloud-controller/0'
        get_requested_roles.return_value = 'role1'
        self.relation_get.return_value = {
            'ec2_admin_url': 'http://10.5.0.16:8773/services/Cloud',
            'ec2_internal_url': 'http://10.5.0.16:8773/services/Cloud',
            'ec2_public_url': 'http://10.5.0.16:8773/services/Cloud',
            'ec2_region': 'RegionOne',
            'ec2_service': 'ec2',
            'nova_admin_url': 'http://10.5.0.16:8774/v2/$(tenant_id)s',
            'nova_internal_url': 'http://10.5.0.16:8774/v2/$(tenant_id)s',
            'nova_public_url': 'http://10.5.0.16:8774/v2/$(tenant_id)s',
            'nova_region': 'RegionOne',
            'nova_service': 'nova',
            'private-address': '10.5.0.16',
            's3_admin_url': 'http://10.5.0.16:3333',
            's3_internal_url': 'http://10.5.0.16:3333',
            's3_public_url': 'http://10.5.0.16:3333',
            's3_region': 'RegionOne',
            's3_service': 's3'}

        self.get_local_endpoint.return_value = 'http://localhost:80/v2.0/'
        KeystoneManager.resolve_tenant_id.return_value = 'tenant_id'
        leader_get.return_value = None

        utils.add_service_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        create_service_credentials.assert_called_once_with(
            'ec2_nova_s3',
            new_roles='role1')

    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'user_exists')
    @patch.object(utils, 'grant_role')
    @patch.object(utils, 'create_role')
    @patch.object(utils, 'create_user')
    def test_create_user_credentials_no_roles(self, mock_create_user,
                                              mock_create_role,
                                              mock_grant_role,
                                              mock_user_exists,
                                              get_callback, set_callback):
        mock_user_exists.return_value = False
        get_callback.return_value = 'passA'
        utils.create_user_credentials('userA',
                                      get_callback,
                                      set_callback,
                                      tenant='tenantA')
        mock_create_user.assert_has_calls([call('userA', 'passA',
                                                domain=None,
                                                tenant='tenantA')])
        mock_create_role.assert_has_calls([])
        mock_grant_role.assert_has_calls([])

    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'user_exists')
    @patch.object(utils, 'grant_role')
    @patch.object(utils, 'create_role')
    @patch.object(utils, 'create_user')
    def test_create_user_credentials(self, mock_create_user, mock_create_role,
                                     mock_grant_role, mock_user_exists,
                                     get_callback, set_callback):
        mock_user_exists.return_value = False
        get_callback.return_value = 'passA'
        utils.create_user_credentials('userA',
                                      get_callback,
                                      set_callback,
                                      tenant='tenantA',
                                      grants=['roleA'], new_roles=['roleB'])
        mock_create_user.assert_has_calls([call('userA', 'passA',
                                                tenant='tenantA',
                                                domain=None)])
        mock_create_role.assert_has_calls([call('roleB', user='userA',
                                                tenant='tenantA',
                                                domain=None)])
        mock_grant_role.assert_has_calls([call('userA', 'roleA',
                                               tenant='tenantA',
                                               user_domain=None,
                                               project_domain=None)])

    @patch.object(utils, 'is_password_changed', lambda x, y: True)
    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'user_exists')
    @patch.object(utils, 'grant_role')
    @patch.object(utils, 'create_role')
    @patch.object(utils, 'create_user')
    def test_create_user_credentials_user_exists(self, mock_create_user,
                                                 mock_create_role,
                                                 mock_grant_role,
                                                 mock_user_exists,
                                                 mock_update_user_password,
                                                 get_callback, set_callback,
                                                 test_api_version=2):
        domain = None
        if test_api_version > 2:
            domain = 'admin_domain'
        mock_user_exists.return_value = True
        get_callback.return_value = 'passA'
        utils.create_user_credentials('userA',
                                      get_callback,
                                      set_callback,
                                      tenant='tenantA',
                                      grants=['roleA'], new_roles=['roleB'],
                                      domain=domain)
        mock_create_user.assert_has_calls([])
        mock_create_role.assert_has_calls([call('roleB', user='userA',
                                                tenant='tenantA',
                                                domain=domain)])
        mock_grant_role.assert_has_calls([call('userA', 'roleA',
                                               tenant='tenantA',
                                               user_domain=domain,
                                               project_domain=domain)])
        mock_update_user_password.assert_has_calls([call('userA', 'passA',
                                                         domain)])

    def test_create_user_credentials_user_exists_v3(self):
        self.test_create_user_credentials_user_exists(test_api_version=3)

    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'create_user_credentials')
    def test_create_service_credentials(self, mock_create_user_credentials,
                                        get_callback, set_callback):
        get_callback.return_value = 'passA'
        cfg = {'service-tenant': 'tenantA', 'admin-role': 'Admin',
               'preferred-api-version': 2}
        self.config.side_effect = lambda key: cfg.get(key, None)
        calls = [call('serviceA', get_callback, set_callback, domain=None,
                      grants=['Admin'],
                      new_roles=None, tenant='tenantA')]

        utils.create_service_credentials('serviceA')
        mock_create_user_credentials.assert_has_calls(calls)

    @patch.object(utils,
                  'protect_user_account_from_pci_dss_force_change_password')
    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'create_user_credentials')
    def test_create_service_credentials_v3(self,
                                           mock_create_user_credentials,
                                           get_callback,
                                           set_callback,
                                           mock_protect_user_accounts):
        get_callback.return_value = 'passA'
        cfg = {'service-tenant': 'tenantA', 'admin-role': 'Admin',
               'preferred-api-version': 3}
        self.config.side_effect = lambda key: cfg.get(key, None)
        calls = [
            call('serviceA', get_callback, set_callback, domain='default',
                 grants=['Admin'], new_roles=None, tenant='tenantA'),
            call('serviceA', get_callback, set_callback,
                 domain='service_domain', grants=['Admin'], new_roles=None,
                 tenant='tenantA')]

        utils.create_service_credentials('serviceA')
        mock_create_user_credentials.assert_has_calls(calls)
        mock_protect_user_accounts.assert_called_once_with('serviceA')

    @patch.object(utils, 'get_api_version')
    def test_protect_user_account_from_pci_dss_force_change_password_v2(
            self, mock_get_api_version):
        mock_get_api_version.return_value = 2
        utils.protect_user_account_from_pci_dss_force_change_password('u1')
        self.config.assert_not_called()

    @patch.object(utils, 'get_api_version')
    def test_protect_user_account_from_pci_dss_v3_no_tenant(
            self, mock_get_api_version):
        mock_get_api_version.return_value = 3
        cfg = {}
        self.config.side_effect = lambda key: cfg.get(key, None)
        with self.assertRaises(ValueError):
            utils.protect_user_account_from_pci_dss_force_change_password('u1')
        self.config.assert_called_once_with('service-tenant')

    @patch.object(utils, 'update_user')
    @patch.object(utils, 'get_user_dict')
    @patch.object(utils, 'get_api_version')
    def test_protect_user_account_from_pci_dss_v3(
            self,
            mock_get_api_version,
            mock_get_user_dict,
            mock_update_user):
        mock_get_api_version.return_value = 3
        cfg = {'service-tenant': 'tenantA'}
        self.config.side_effect = lambda key: cfg.get(key, None)
        users = {
            'u1': {
                'id': 'u1id',
                'options': {'ignore_change_password_upon_first_use': True,
                            'ignore_password_expiry': True}},
            'u2': {
                'id': 'u2id',
                'options': {'ignore_change_password_upon_first_use': False,
                            'ignore_password_expiry': True}},
            'u3': {'id': 'u3id', 'options': {}},
            'u4': {'id': 'u4id'},
        }
        mock_get_user_dict.side_effect = (
            lambda key, **kwargs: copy.deepcopy(users.get(key, None)))

        # test user exists and option exists and is true
        utils.protect_user_account_from_pci_dss_force_change_password('u1')
        calls = [call('u1', utils.DEFAULT_DOMAIN),
                 call('u1', utils.SERVICE_DOMAIN)]
        mock_get_user_dict.has_calls(calls)
        mock_update_user.assert_not_called()

        # test user exists and option exists and is False
        mock_get_user_dict.reset_mock()
        utils.protect_user_account_from_pci_dss_force_change_password('u2')
        calls = [call('u2id',
                      options={'ignore_change_password_upon_first_use': True,
                               'ignore_password_expiry': True}
                      ),
                 call('u2id',
                      options={'ignore_change_password_upon_first_use': True,
                               'ignore_password_expiry': True}
                      )]
        mock_update_user.assert_has_calls(calls)

        # test user exists and the option doesn't exist
        mock_get_user_dict.reset_mock()
        mock_update_user.reset_mock(calls)
        utils.protect_user_account_from_pci_dss_force_change_password('u3')
        calls = [call('u3id',
                      options={'ignore_change_password_upon_first_use': True,
                               'ignore_password_expiry': True}
                      ),
                 call('u3id',
                      options={'ignore_change_password_upon_first_use': True,
                               'ignore_password_expiry': True}
                      )]
        mock_update_user.assert_has_calls(calls)
        # test user exists and no options exist
        mock_get_user_dict.reset_mock()
        mock_update_user.reset_mock(calls)
        utils.protect_user_account_from_pci_dss_force_change_password('u4')
        calls = [call('u4id',
                      options={'ignore_change_password_upon_first_use': True,
                               'ignore_password_expiry': True}
                      ),
                 call('u4id',
                      options={'ignore_change_password_upon_first_use': True,
                               'ignore_password_expiry': True}
                      )]
        mock_update_user.assert_has_calls(calls)
        # test user doesn't exist
        mock_get_user_dict.reset_mock()
        mock_update_user.reset_mock(calls)
        utils.protect_user_account_from_pci_dss_force_change_password('u5')
        mock_update_user.assert_not_called()

    @patch.object(utils,
                  'protect_user_account_from_pci_dss_force_change_password')
    @patch.object(utils, 'list_users_for_domain')
    @patch.object(utils, 'get_api_version')
    def test_ensure_all_service_accounts_protected_for_pci_dss_options(
        self,
        mock_get_api_version,
        mock_list_users_for_domain,
        mock_protect_service_accounts,
    ):
        # test it does nothing for less that keystone v3
        mock_get_api_version.return_value = 2
        utils.ensure_all_service_accounts_protected_for_pci_dss_options()
        mock_protect_service_accounts.assert_not_called()
        # now check that service accounts get protected.
        mock_get_api_version.return_value = 3
        mock_list_users_for_domain.return_value = [
            {'name': 'u1'}, {'name': 'u2'}]
        utils.ensure_all_service_accounts_protected_for_pci_dss_options()
        mock_protect_service_accounts.assert_has_calls([
            call('u1'), call('u2')])

    def test_ensure_valid_service_incorrect(self):
        utils.ensure_valid_service('fakeservice')
        self.log.assert_called_with("Invalid service requested: 'fakeservice'")
        self.relation_set.assert_called_with(admin_token=-1)

    def test_add_endpoint(self):
        publicurl = '10.0.0.1'
        adminurl = '10.0.0.2'
        internalurl = '10.0.0.3'
        utils.add_endpoint(
            'RegionOne',
            'nova',
            publicurl,
            adminurl,
            internalurl)
        self.create_service_entry.assert_called_with(
            'nova',
            'compute',
            'Nova Compute Service',
            list_services=None)
        self.create_endpoint_template.asssert_called_with(
            region='RegionOne', service='nova',
            publicurl=publicurl, adminurl=adminurl,
            internalurl=internalurl)

    @patch.object(utils, 'uuid')
    @patch.object(utils, 'relation_set')
    @patch.object(utils, 'relation_get')
    @patch.object(utils, 'relation_ids')
    @patch.object(utils, 'is_leader')
    def test_send_id_notifications(self, mock_is_leader,
                                   mock_relation_ids, mock_relation_get,
                                   mock_relation_set, mock_uuid):
        checksums = {'foo-endpoint-changed': 1}
        relation_id = 'testrel:0'
        mock_uuid.uuid4.return_value = '1234'
        mock_relation_ids.return_value = [relation_id]
        mock_is_leader.return_value = False
        utils.send_id_notifications(checksums)
        self.assertFalse(mock_relation_set.called)

        mock_is_leader.return_value = True
        utils.send_id_notifications({})
        self.assertFalse(mock_relation_set.called)

        utils.send_id_notifications(checksums)
        self.assertTrue(mock_relation_set.called)
        mock_relation_set.assert_has_calls([
            call(
                relation_id=relation_id,
                relation_settings=checksums,
                app=True
            ),
            call(
                relation_id=relation_id,
                relation_settings=checksums
            ),
        ], any_order=True)
        mock_relation_set.reset_mock()
        utils.send_id_notifications(checksums, force=True)
        self.assertTrue(mock_relation_set.called)
        checksums['trigger'] = '1234'
        mock_relation_set.assert_has_calls([
            call(
                relation_id=relation_id,
                relation_settings=checksums,
                app=True
            ),
            call(
                relation_id=relation_id,
                relation_settings=checksums
            ),
        ], any_order=True)

    @patch.object(utils, 'service_endpoint_dict')
    @patch.object(utils, 'relation_ids')
    @patch.object(utils, 'related_units')
    @patch.object(utils, 'relation_get')
    @patch.object(utils, 'relation_set')
    def test_send_id_service_notifications(self, mock_relation_set,
                                           mock_relation_get,
                                           mock_related_units,
                                           mock_relation_ids,
                                           mock_service_endpoint_dict):
        id_svc_rel_units = {
            'identity-service:1': ['neutron-gateway/0'],
            'identity-service:2': [
                'nova-cloud-controller/0',
                'nova-cloud-controller/1',
                'nova-cloud-controller/2'],
            'identity-service:3': ['glance/0', 'glance/1', 'glance/2']
        }

        def _related_units(rid):
            return id_svc_rel_units[rid]

        id_svc_rel_data = {
            'neutron-gateway/0': {
                'subscribe_ep_change': 'neutron'},
            'nova-cloud-controller/0': {
                'nova_admin_url': 'http://172.20.0.13:8774/v2.1',
                'subscribe_ep_change': 'placement neutron'},
            'nova-cloud-controller/1': {},
            'nova-cloud-controller/2': {},
            'glance/0': {
                'admin_url': 'http://172.20.0.32:9292'},
            'glance/1': {},
            'glance/2': {},
            'keystone/0': {}
        }

        def _relation_get(unit, rid, attribute):
            return id_svc_rel_data[unit].get(attribute)

        def _service_endpoint_dict(service_name):
            _services = {
                'neutron': {'internal': 'http://neutron.demo.com:9696'}
            }
            return _services.get(service_name)

        mock_relation_ids.return_value = id_svc_rel_units.keys()
        mock_related_units.side_effect = _related_units
        mock_relation_get.side_effect = _relation_get
        mock_service_endpoint_dict.side_effect = _service_endpoint_dict
        self.local_unit.return_value = 'keystone/0'

        # Check all services subscribed to placement changes are notified.
        mock_relation_set.reset_mock()
        utils.send_id_service_notifications(
            {'placement-endpoint-changed': {"internal": "http://demo.com"}})
        mock_relation_set.assert_has_calls([
            call(
                relation_id='identity-service:1',
                relation_settings={
                    'catalog_ttl': 60,
                    'ep_changed':
                        ('{"neutron": {"internal": '
                         '"http://neutron.demo.com:9696"}}')
                },
                app=True
            ),
            call(
                relation_id='identity-service:2',
                relation_settings={
                    'catalog_ttl': 60,
                    'ep_changed':
                        ('{"neutron": {"internal": '
                         '"http://neutron.demo.com:9696"},'
                         ' "placement": {"internal": "http://demo.com"}}')
                },
                app=True
            )
        ], any_order=True)

        # Check all services subscribed to neutron changes are notified.
        mock_relation_set.reset_mock()
        utils.send_id_service_notifications(
            {'neutron-endpoint-changed': {"internal": "http://demo.com"}})
        expected_rel_set_calls = [
            call(
                relation_id='identity-service:1',
                relation_settings={
                    'catalog_ttl': 60,
                    'ep_changed':
                        '{"neutron": {"internal": "http://demo.com"}}'
                },
                app=True
            ),
            call(
                relation_id='identity-service:2',
                relation_settings={
                    'catalog_ttl': 60,
                    'ep_changed':
                        '{"neutron": {"internal": "http://demo.com"}}'
                },
                app=True
            )
        ]
        mock_relation_set.assert_has_calls(
            expected_rel_set_calls,
            any_order=True)

        # Check multiple ep changes with app subscribing to multiple eps
        mock_relation_set.reset_mock()
        utils.send_id_service_notifications(
            {'neutron-endpoint-changed': {"internal": "http://demo.com"},
             'placement-endpoint-changed': {"internal": "http://demo.com"}})
        expected_rel_set_calls = [
            call(
                relation_id='identity-service:1',
                relation_settings={
                    'catalog_ttl': 60,
                    'ep_changed':
                        '{"neutron": {"internal": "http://demo.com"}}'
                },
                app=True
            ),
            call(
                relation_id='identity-service:2',
                relation_settings={
                    'catalog_ttl': 60,
                    'ep_changed': (
                        '{"neutron": {"internal": "http://demo.com"}, '
                        '"placement": {"internal": "http://demo.com"}}'
                    )
                },
                app=True
            )
        ]
        mock_relation_set.assert_has_calls(
            expected_rel_set_calls,
            any_order=True)

    @patch.object(utils, 'get_manager')
    def test_service_endpoint_dict_v3(self, mock_get_manager):
        mock_manager = MagicMock()
        mock_get_manager.return_value = mock_manager
        mock_manager.resolve_service_id.return_value = None

        self.assertIsNone(utils.service_endpoint_dict('dummyservice'))

        mock_manager.reset_mock()

        mock_manager.resolve_service_id.return_value = 'd123456'
        mock_manager.list_endpoints.return_value = [
            {'service_id': 'd123456',
             'interface': 'internal',
             'url': 'http://dummyservice.demo.com'},
            {'service_id': 'd789102',
             'interface': 'internal',
             'url': 'http://anotherservice.demo.com'},
        ]

        self.assertEqual(
            utils.service_endpoint_dict('dummyservice'),
            {'internal': 'http://dummyservice.demo.com'}
        )

        mock_manager.reset_mock()

        mock_manager.resolve_service_id.return_value = 'd123456'
        mock_manager.list_endpoints.return_value = [
            {'service_id': 'd789102',
             'interface': 'public',
             'url': 'http://anotherservice.demo.com'},
            {'service_id': 'd789102',
             'interface': 'internal',
             'url': 'http://anotherservice.demo.com'},
        ]

        self.assertEqual(
            utils.service_endpoint_dict('dummyservice'),
            {}
        )

    @patch.object(utils, 'get_manager')
    def test_service_endpoint_dict_v2(self, mock_get_manager):
        mock_manager = MagicMock()
        mock_get_manager.return_value = mock_manager
        mock_manager.resolve_service_id.return_value = None

        self.assertIsNone(utils.service_endpoint_dict('dummyservice'))

        mock_manager.reset_mock()

        mock_manager.resolve_service_id.return_value = 'd123456'
        mock_manager.list_endpoints.return_value = [
            {'service_id': 'd123456',
             'internalurl': 'http://dummyservice.demo.com',
             'publicurl': 'http://anotherservice.demo.com'},
        ]

        self.assertEqual(
            utils.service_endpoint_dict('dummyservice'),
            {'internal': 'http://dummyservice.demo.com',
             'public': 'http://anotherservice.demo.com'}
        )

        mock_manager.reset_mock()

        mock_manager.resolve_service_id.return_value = 'd123456'
        mock_manager.list_endpoints.return_value = [
            {'service_id': 'd789102',
             'internalurl': 'http://dummyservice.demo.com',
             'publicurl': 'http://anotherservice.demo.com'},
            {'service_id': 'd789102',
             'internalurl': 'http://dummyservice.demo.com',
             'publicurl': 'http://anotherservice.demo.com'},
        ]

        self.assertEqual(
            utils.service_endpoint_dict('dummyservice'),
            {}
        )

    def test_get_admin_passwd_pwd_set(self):
        self.test_config.set('admin-password', 'supersecret')
        self.assertEqual(utils.get_admin_passwd(), 'supersecret')
        self.test_config.set('admin-password', 'supersecret ')
        self.assertEqual(utils.get_admin_passwd(), 'supersecret')
        self.test_config.set('admin-password', 'supersecret\n')
        self.assertEqual(utils.get_admin_passwd(), 'supersecret')

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_get')
    def test_get_admin_passwd_leader_set(self, leader_get, is_leader):
        is_leader.return_value = False
        leader_get.return_value = 'admin'
        self.assertEqual(utils.get_admin_passwd(), 'admin')
        leader_get.assert_called_with('admin_passwd')

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_get')
    def test_get_admin_passwd_leader_set_user_specified(self, leader_get,
                                                        is_leader):
        is_leader.return_value = False
        leader_get.return_value = 'admin'
        self.assertEqual(utils.get_admin_passwd(user='test'), 'admin')
        leader_get.assert_called_with('test_passwd')

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_get')
    def test_get_admin_passwd_leader_set_user_config(self, leader_get,
                                                     is_leader):
        is_leader.return_value = False
        leader_get.return_value = 'admin'
        self.test_config.set('admin-user', 'test')
        self.assertEqual(utils.get_admin_passwd(), 'admin')
        leader_get.assert_called_with('test_passwd')

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_set')
    def test_set_admin_password(self, leader_set, is_leader):
        is_leader.return_value = True
        utils.set_admin_passwd('secret')
        leader_set.assert_called_once_with({'admin_passwd': 'secret'})

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_set')
    def test_set_admin_password_config_username(self, leader_set, is_leader):
        is_leader.return_value = True
        self.test_config.set('admin-user', 'username')
        utils.set_admin_passwd('secret')
        leader_set.assert_called_once_with({'username_passwd': 'secret'})

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_set')
    def test_set_admin_password_username(self, leader_set, is_leader):
        is_leader.return_value = True
        utils.set_admin_passwd('secret', user='username')
        leader_set.assert_called_once_with({'username_passwd': 'secret'})

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_get')
    @patch('os.path.isfile')
    def test_get_admin_passwd_genpass(self, isfile, leader_get, is_leader):
        is_leader.return_value = True
        leader_get.return_value = 'supersecretgen'
        self.test_config.set('admin-password', '')
        isfile.return_value = False
        self.subprocess.check_output.return_value = 'supersecretgen'
        self.assertEqual(utils.get_admin_passwd(), 'supersecretgen')

    def test_is_db_ready(self):
        allowed_units = None

        def fake_rel_get(attribute=None, *args, **kwargs):
            if attribute == 'allowed_units':
                return allowed_units

        self.relation_get.side_effect = fake_rel_get

        self.relation_id.return_value = 'shared-db:0'
        self.relation_ids.return_value = ['shared-db:0']
        self.local_unit.return_value = 'unit/0'
        allowed_units = 'unit/0'
        self.assertTrue(utils.is_db_ready(use_current_context=True))

        self.relation_id.return_value = 'shared-db:0'
        self.relation_ids.return_value = ['shared-db:0']
        self.local_unit.return_value = 'unit/0'
        allowed_units = 'unit/1'
        self.assertFalse(utils.is_db_ready(use_current_context=True))

        self.relation_ids.return_value = ['acme:0']
        with self.assertRaises(Exception):
            utils.is_db_ready(use_current_context=True)

        allowed_units = 'unit/0'
        self.related_units.return_value = ['unit/0']
        self.relation_ids.return_value = ['shared-db:0', 'shared-db:1']
        self.assertTrue(utils.is_db_ready())

        allowed_units = 'unit/1'
        self.assertFalse(utils.is_db_ready())

        self.related_units.return_value = []
        self.assertTrue(utils.is_db_ready())

    @patch.object(utils, 'leader_set')
    @patch.object(utils, 'leader_get')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.is_clustered')
    @patch('charmhelpers.contrib.openstack.ip.config')
    @patch.object(utils, 'create_keystone_endpoint')
    @patch.object(utils, 'create_tenant')
    @patch.object(utils, 'create_user_credentials')
    @patch.object(utils, 'create_service_entry')
    def test_ensure_initial_admin_public_name(self,
                                              _create_service_entry,
                                              _create_user_creds,
                                              _create_tenant,
                                              _create_keystone_endpoint,
                                              _ip_config,
                                              _is_clustered,
                                              _unit_get,
                                              _leader_get,
                                              _leader_set):
        _is_clustered.return_value = False
        _ip_config.side_effect = self.test_config.get
        _unit_get.return_value = '10.0.0.1'
        _leader_get.return_value = None
        self.test_config.set('os-public-hostname', 'keystone.example.com')
        utils.ensure_initial_admin(self.config)
        _create_keystone_endpoint.assert_called_with(
            public_ip='keystone.example.com',
            service_port=5000,
            internal_ip='10.0.0.1',
            admin_ip='10.0.0.1',
            auth_port=35357,
            region='RegionOne',
        )

    @patch.object(utils, 'get_manager')
    def test_is_service_present(self, KeystoneManager):
        mock_keystone = MagicMock()
        mock_keystone.resolve_service_id.return_value = 'sid1'
        KeystoneManager.return_value = mock_keystone
        self.assertTrue(utils.is_service_present('bob', 'bill'))

    @patch.object(utils, 'get_manager')
    def test_is_service_present_false(self, KeystoneManager):
        mock_keystone = MagicMock()
        mock_keystone.resolve_service_id.return_value = None
        KeystoneManager.return_value = mock_keystone
        self.assertFalse(utils.is_service_present('bob', 'bill'))

    @patch.object(utils, 'get_manager')
    def test_delete_service_entry(self, KeystoneManager):
        mock_keystone = MagicMock()
        mock_keystone.resolve_service_id.return_value = 'sid1'
        KeystoneManager.return_value = mock_keystone
        utils.delete_service_entry('bob', 'bill')
        mock_keystone.delete_service_by_id.assert_called_once_with('sid1')

    @patch('os.path.isfile')
    def test_get_file_stored_domain_id(self, isfile_mock):
        isfile_mock.return_value = False
        x = utils.get_file_stored_domain_id('/a/file')
        assert x is None
        with patch.object(builtins, 'open', mock_open(
                read_data="some_data\n")):
            isfile_mock.return_value = True
            x = utils.get_file_stored_domain_id('/a/file')
            self.assertEqual(x, 'some_data')

    @patch.object(utils, 'is_leader')
    def test_assess_status(self, is_leader):
        is_leader.return_value = True
        with patch.object(utils, 'assess_status_func') as asf:
            callee = MagicMock()
            asf.return_value = callee
            utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()
            self.os_application_version_set.assert_called_with(
                utils.VERSION_PACKAGE
            )
            self.assertTrue(self.os_application_status_set.called)

    @patch.object(utils, 'determine_ports')
    @patch.object(utils, 'services')
    @patch.object(utils, 'get_optional_interfaces')
    @patch.object(utils, 'REQUIRED_INTERFACES')
    @patch.object(utils, 'check_extra_for_assess_status')
    @patch.object(utils, 'get_managed_services_and_ports')
    @patch.object(utils, 'make_assess_status_func')
    def test_assess_status_func(self,
                                make_assess_status_func,
                                get_managed_services_and_ports,
                                check_extra_for_assess_status,
                                REQUIRED_INTERFACES,
                                get_optional_interfaces,
                                services,
                                determine_ports):
        services.return_value = ['s1']
        determine_ports.return_value = [200]
        get_managed_services_and_ports.return_value = (['s1'], [200])
        REQUIRED_INTERFACES.copy.return_value = {'int': ['test 1']}
        get_optional_interfaces.return_value = {'opt': ['test 2']}
        utils.assess_status_func('test-config')
        make_assess_status_func.assert_called_once_with(
            'test-config',
            {'int': ['test 1'], 'opt': ['test 2']},
            charm_func=check_extra_for_assess_status,
            services=['s1'],
            ports=[200])

    def test_pause_unit_helper(self):
        with patch.object(utils, '_pause_resume_helper') as prh:
            utils.pause_unit_helper('random-config')
            prh.assert_called_once_with(utils.pause_unit, 'random-config')
        with patch.object(utils, '_pause_resume_helper') as prh:
            utils.resume_unit_helper('random-config')
            prh.assert_called_once_with(utils.resume_unit, 'random-config')

    @patch.object(utils, 'determine_ports')
    @patch.object(utils, 'services')
    @patch.object(utils, 'get_managed_services_and_ports')
    def test_pause_resume_helper(self, get_managed_services_and_ports,
                                 services, determine_ports):
        f = MagicMock()
        get_managed_services_and_ports.return_value = (['s1'], [200])
        with patch.object(utils, 'assess_status_func') as asf:
            asf.return_value = 'assessor'
            utils._pause_resume_helper(f, 'some-config')
            asf.assert_called_once_with('some-config')
            f.assert_called_once_with('assessor', services=['s1'], ports=[200])

    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'restart_keystone')
    def test_restart_function_map(self, restart_keystone, run_in_apache):
        run_in_apache.return_value = True
        self.assertEqual(utils.restart_function_map(),
                         {'apache2': restart_keystone})

    @patch.object(utils, 'stop_manager_instance')
    @patch.object(utils, 'is_unit_paused_set')
    def test_restart_keystone_unit_paused(self,
                                          mock_is_unit_paused_set,
                                          mock_stop_manager_instance):
        mock_is_unit_paused_set.return_value = True
        utils.restart_keystone()
        mock_stop_manager_instance.assert_not_called()

    @patch.object(utils, 'snap_install_requested')
    @patch.object(utils, 'service_restart')
    @patch.object(utils, 'stop_manager_instance')
    @patch.object(utils, 'is_unit_paused_set')
    def test_restart_keystone_unit_not_paused_snap_install(
            self,
            mock_is_unit_paused_set,
            mock_stop_manager_instance,
            mock_service_restart,
            mock_snap_install_requested):
        mock_is_unit_paused_set.return_value = False
        mock_snap_install_requested.return_value = True
        utils.restart_keystone()
        mock_service_restart.assert_called_once_with('snap.keystone.*')
        mock_stop_manager_instance.assert_called_once_with()

    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'snap_install_requested')
    @patch.object(utils, 'service_restart')
    @patch.object(utils, 'stop_manager_instance')
    @patch.object(utils, 'is_unit_paused_set')
    def test_restart_keystone_unit_not_paused_legacy(
            self,
            mock_is_unit_paused_set,
            mock_stop_manager_instance,
            mock_service_restart,
            mock_snap_install_requested,
            mock_run_in_apache):
        mock_is_unit_paused_set.return_value = False
        mock_snap_install_requested.return_value = False
        mock_run_in_apache.return_value = False
        utils.restart_keystone()
        mock_service_restart.assert_called_once_with('keystone')
        mock_stop_manager_instance.assert_called_once_with()

    @patch.object(utils, 'run_in_apache')
    @patch.object(utils, 'snap_install_requested')
    @patch.object(utils, 'restart_pid_check')
    @patch.object(utils, 'stop_manager_instance')
    @patch.object(utils, 'is_unit_paused_set')
    def test_restart_keystone_unit_not_paused(
            self,
            mock_is_unit_paused_set,
            mock_stop_manager_instance,
            mock_restart_pid_check,
            mock_snap_install_requested,
            mock_run_in_apache):
        mock_is_unit_paused_set.return_value = False
        mock_snap_install_requested.return_value = False
        mock_run_in_apache.return_value = True
        utils.restart_keystone()
        mock_restart_pid_check.assert_called_once_with('apache2')
        mock_stop_manager_instance.assert_called_once_with()

    def test_restart_pid_check(self):
        self.subprocess.call.return_value = 1
        utils.restart_pid_check('apache2')
        self.service_stop.assert_called_once_with('apache2')
        self.service_start.assert_called_once_with('apache2')
        self.subprocess.call.assert_called_once_with(
            ['pgrep', 'apache2', '--nslist', 'pid', '--ns', str(os.getpid())]
        )

    def test_restart_pid_check_ptable_string(self):
        self.subprocess.call.return_value = 1
        utils.restart_pid_check('apache2', ptable_string='httpd')
        self.service_stop.assert_called_once_with('apache2')
        self.service_start.assert_called_once_with('apache2')
        self.subprocess.call.assert_called_once_with(
            ['pgrep', 'httpd', '--nslist', 'pid', '--ns', str(os.getpid())]
        )

    # Do not sleep() to speed up manual runs.
    @patch('charmhelpers.core.decorators.time')
    def test_restart_pid_check_ptable_string_retry(self, mock_time):
        call_returns = [1, 0, 0]
        self.subprocess.call.side_effect = lambda x: call_returns.pop()
        utils.restart_pid_check('apache2', ptable_string='httpd')
        self.service_stop.assert_called_once_with('apache2')
        self.service_start.assert_called_once_with('apache2')
#        self.subprocess.call.assert_called_once_with(['pgrep', 'httpd'])
        expected = [
            call(['pgrep', 'httpd', '--nslist', 'pid', '--ns',
                 str(os.getpid())]),
            call(['pgrep', 'httpd', '--nslist', 'pid', '--ns',
                 str(os.getpid())]),
            call(['pgrep', 'httpd', '--nslist', 'pid', '--ns',
                 str(os.getpid())])
        ]
        self.assertEqual(self.subprocess.call.call_args_list, expected)

    def test_get_requested_grants(self):
        settings = {'requested_grants': 'Admin,Member'}
        expected_results = ['Admin', 'Member']
        self.assertEqual(utils.get_requested_grants(settings),
                         expected_results)
        settings = {'not_requsted_grants': 'something else'}
        expected_results = []
        self.assertEqual(utils.get_requested_grants(settings),
                         expected_results)

    @patch.object(utils, 'https')
    def test_get_protocol(self, https):
        # http
        https.return_value = False
        protocol = utils.get_protocol()
        self.assertEqual(protocol, 'http')
        # https
        https.return_value = True
        protocol = utils.get_protocol()
        self.assertEqual(protocol, 'https')

    @patch.object(utils, 'get_manager')
    def test_add_credentials_keystone_not_ready(self, get_manager):
        """ Verify add_credentials_to_keystone when the relation
            data is incomplete """
        relation_id = 'identity-credentials:0'
        remote_unit = 'unit/0'
        self.relation_get.return_value = {}
        utils.add_credentials_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        self.log.assert_called_with('identity-credentials peer has not yet '
                                    'set username')

    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'create_user_credentials')
    @patch.object(utils, 'get_protocol')
    @patch.object(utils, 'resolve_address')
    @patch.object(utils, 'get_api_version')
    @patch.object(utils, 'get_manager')
    def test_add_credentials_keystone_username_only(self, get_manager,
                                                    get_api_version,
                                                    resolve_address,
                                                    get_protocol,
                                                    create_user_credentials,
                                                    get_callback,
                                                    set_callback):
        """ Verify add_credentials with only username """
        manager = MagicMock()
        manager.resolve_tenant_id.return_value = 'abcdef0123456789'
        get_manager.return_value = manager
        remote_unit = 'unit/0'
        relation_id = 'identity-credentials:0'
        get_api_version.return_value = 2
        get_protocol.return_value = 'http'
        resolve_address.return_value = '10.10.10.10'
        create_user_credentials.return_value = 'password'
        self.relation_get.return_value = {'username': 'requester'}
        self.get_service_password.return_value = 'password'
        self.get_requested_roles.return_value = []
        self.test_config.set('admin-port', 80)
        self.test_config.set('service-port', 81)
        self.test_config.set('service-tenant', 'services')
        relation_data = {'auth_host': '10.10.10.10',
                         'credentials_host': '10.10.10.10',
                         'credentials_port': 81,
                         'auth_port': 80,
                         'auth_protocol': 'http',
                         'credentials_username': 'requester',
                         'credentials_protocol': 'http',
                         'credentials_password': 'password',
                         'credentials_project': 'services',
                         'credentials_project_id': 'abcdef0123456789',
                         'region': 'RegionOne',
                         'api_version': 2}

        utils.add_credentials_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        create_user_credentials.assert_called_with('requester',
                                                   get_callback,
                                                   set_callback,
                                                   domain=None,
                                                   new_roles=[],
                                                   grants=['Admin'],
                                                   tenant='services')
        self.peer_store_and_set.assert_called_with(relation_id=relation_id,
                                                   **relation_data)

    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'create_user_credentials')
    @patch.object(utils, 'get_protocol')
    @patch.object(utils, 'resolve_address')
    @patch.object(utils, 'get_api_version')
    @patch.object(utils, 'get_manager')
    def test_add_credentials_keystone_kv3(self, get_manager,
                                          get_api_version,
                                          resolve_address,
                                          get_protocol,
                                          create_user_credentials,
                                          get_callback, set_callback):
        """ Verify add_credentials with Keystone V3 """
        manager = MagicMock()
        manager.resolve_tenant_id.return_value = 'abcdef0123456789'
        manager.resolve_domain_id.return_value = 'a-domain-id'
        get_manager.return_value = manager
        remote_unit = 'unit/0'
        relation_id = 'identity-credentials:0'
        get_api_version.return_value = 3
        get_protocol.return_value = 'http'
        resolve_address.return_value = '10.10.10.10'
        create_user_credentials.return_value = 'password'
        self.relation_get.return_value = {'username': 'requester',
                                          'domain': 'Non-Default'}
        self.get_service_password.return_value = 'password'
        self.get_requested_roles.return_value = []
        self.test_config.set('admin-port', 80)
        self.test_config.set('service-port', 81)
        relation_data = {'auth_host': '10.10.10.10',
                         'credentials_host': '10.10.10.10',
                         'credentials_port': 81,
                         'auth_port': 80,
                         'auth_protocol': 'http',
                         'credentials_username': 'requester',
                         'credentials_protocol': 'http',
                         'credentials_password': 'password',
                         'credentials_project': 'services',
                         'credentials_project_id': 'abcdef0123456789',
                         'credentials_user_domain_id': 'a-domain-id',
                         'credentials_project_domain_id': 'a-domain-id',
                         'credentials_project_domain_name': 'Non-Default',
                         'credentials_user_domain_name': 'Non-Default',
                         'region': 'RegionOne',
                         'domain': 'Non-Default',
                         'api_version': 3}

        utils.add_credentials_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        create_user_credentials.assert_called_with('requester',
                                                   get_callback,
                                                   set_callback,
                                                   domain='Non-Default',
                                                   new_roles=[],
                                                   grants=['Admin'],
                                                   tenant='services')
        self.peer_store_and_set.assert_called_with(relation_id=relation_id,
                                                   **relation_data)

    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'get_service_password')
    @patch.object(utils, 'create_tenant')
    @patch.object(utils, 'create_user_credentials')
    @patch.object(utils, 'get_protocol')
    @patch.object(utils, 'resolve_address')
    @patch.object(utils, 'get_api_version')
    @patch.object(utils, 'get_manager')
    def test_add_credentials_keystone_roles_grants(self, get_manager,
                                                   get_api_version,
                                                   resolve_address,
                                                   get_protocol,
                                                   create_user_credentials,
                                                   create_tenant,
                                                   get_callback, set_callback):
        """ Verify add_credentials with all relation settings """
        manager = MagicMock()
        manager.resolve_tenant_id.return_value = 'abcdef0123456789'
        get_manager.return_value = manager
        remote_unit = 'unit/0'
        relation_id = 'identity-credentials:0'
        get_api_version.return_value = 2
        get_protocol.return_value = 'http'
        resolve_address.return_value = '10.10.10.10'
        create_user_credentials.return_value = 'password'
        self.relation_get.return_value = {'username': 'requester',
                                          'project': 'myproject',
                                          'requested_roles': 'New,Member',
                                          'requested_grants': 'New,Member'}
        self.get_service_password.return_value = 'password'
        self.get_requested_roles.return_value = ['New', 'Member']
        self.test_config.set('admin-port', 80)
        self.test_config.set('service-port', 81)
        relation_data = {'auth_host': '10.10.10.10',
                         'credentials_host': '10.10.10.10',
                         'credentials_port': 81,
                         'auth_port': 80,
                         'auth_protocol': 'http',
                         'credentials_username': 'requester',
                         'credentials_protocol': 'http',
                         'credentials_password': 'password',
                         'credentials_project': 'myproject',
                         'credentials_project_id': 'abcdef0123456789',
                         'region': 'RegionOne',
                         'api_version': 2}

        utils.add_credentials_to_keystone(
            relation_id=relation_id,
            remote_unit=remote_unit)
        create_tenant.assert_called_with('myproject', None)
        create_user_credentials.assert_called_with('requester',
                                                   get_callback,
                                                   set_callback,
                                                   domain=None,
                                                   new_roles=['New', 'Member'],
                                                   grants=['New', 'Member'],
                                                   tenant='myproject')
        self.peer_store_and_set.assert_called_with(relation_id=relation_id,
                                                   **relation_data)

    @patch.object(utils.os, 'remove')
    @patch.object(utils.os.path, 'exists')
    def test_disable_unused_apache_sites(self, os_path_exists, os_remove):
        utils.UNUSED_APACHE_SITE_FILES = ['/path/sitename.conf']

        # Files do not exist
        os_path_exists.return_value = False
        utils.disable_unused_apache_sites()
        self.subprocess.check_call.assert_not_called()

        # Files exist
        os_path_exists.return_value = True
        utils.disable_unused_apache_sites()
        self.subprocess.check_call.assert_called_with(
            ['a2dissite', 'sitename']
        )

        # Force remove
        os_path_exists.return_value = True
        self.subprocess.CalledProcessError = subprocess.CalledProcessError
        self.subprocess.check_call.side_effect = subprocess.CalledProcessError(
            1, 'a2dissite')
        utils.disable_unused_apache_sites()
        os_remove.assert_called_with(utils.UNUSED_APACHE_SITE_FILES[0])

    def test_run_in_apache_kilo(self):
        self.os_release.return_value = 'kilo'
        self.assertFalse(utils.run_in_apache())

    def test_run_in_apache_liberty(self):
        self.os_release.return_value = 'liberty'
        self.assertTrue(utils.run_in_apache())

    def test_run_in_apache_set_release(self):
        self.os_release.return_value = 'kilo'
        self.assertTrue(utils.run_in_apache(release='liberty'))

    def test_get_api_version_icehouse(self):
        self.assertEqual(utils.get_api_version(), 2)

    def test_get_api_version_queens(self):
        self.get_os_codename_install_source.return_value = 'queens'
        self.assertEqual(utils.get_api_version(), 3)

    def test_get_api_version_invalid_option_value(self):
        self.test_config.set('preferred-api-version', 4)
        with self.assertRaises(ValueError):
            utils.get_api_version()

    def test_get_api_version_queens_invalid_option_value(self):
        self.test_config.set('preferred-api-version', 2)
        self.get_os_codename_install_source.return_value = 'queens'
        with self.assertRaises(ValueError):
            utils.get_api_version()

    @patch.object(utils, 'is_leader')
    @patch('os.path.exists')
    def test_key_setup(self, mock_path_exists, mock_is_leader):
        base_cmd = ['sudo', '-u', 'keystone', 'keystone-manage']
        mock_is_leader.return_value = True
        mock_path_exists.return_value = False
        with patch.object(builtins, 'open', mock_open()) as m:
            utils.key_setup()
            m.assert_called_once_with(utils.KEY_SETUP_FILE, "w")
        self.subprocess.check_output.has_calls(
            [
                base_cmd + ['fernet_setup'],
                base_cmd + ['credential_setup'],
                base_cmd + ['credential_migrate'],
            ])
        mock_path_exists.assert_called_once_with(utils.KEY_SETUP_FILE)
        mock_is_leader.assert_called_once_with()

    def test_fernet_rotate(self):
        cmd = ['sudo', '-u', 'keystone', 'keystone-manage', 'fernet_rotate']
        utils.fernet_rotate()
        self.subprocess.check_output.called_with(cmd)

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_get')
    @patch.object(utils, 'leader_set')
    @patch('os.listdir')
    def test_key_leader_set(self, listdir, leader_set, leader_get, is_leader):
        listdir.return_value = ['0', '1']
        is_leader.return_value = True
        leader_get.return_value = None
        self.time.time.return_value = "the-time"
        with patch.object(builtins, 'open', mock_open(
                read_data="some_data")):
            utils.key_leader_set()
        listdir.has_calls([
            call(utils.FERNET_KEY_REPOSITORY),
            call(utils.CREDENTIAL_KEY_REPOSITORY)])
        leader_set.assert_called_with(
            {'key_repository': json.dumps(
                {utils.FERNET_KEY_REPOSITORY:
                    {'0': 'some_data', '1': 'some_data'},
                 utils.CREDENTIAL_KEY_REPOSITORY:
                    {'0': 'some_data', '1': 'some_data'}})
             })

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_get')
    @patch.object(utils, 'leader_set')
    @patch('os.listdir')
    def test_key_leader_set_no_change(
            self, listdir, leader_set, leader_get, is_leader):
        listdir.return_value = ['0', '1']
        is_leader.return_value = True
        leader_get.return_value = json.dumps(
            {utils.FERNET_KEY_REPOSITORY:
                {'0': 'some_data', '1': 'some_data'},
             utils.CREDENTIAL_KEY_REPOSITORY:
                {'0': 'some_data', '1': 'some_data'}})
        self.time.time.return_value = "the-time"
        with patch.object(builtins, 'open', mock_open(
                read_data="some_data")):
            utils.key_leader_set()
        listdir.has_calls([
            call(utils.FERNET_KEY_REPOSITORY),
            call(utils.CREDENTIAL_KEY_REPOSITORY)])
        leader_set.assert_not_called()

    @patch.object(utils, '_file_equal_to')
    @patch.object(utils, "is_leader")
    @patch('os.rename')
    @patch.object(utils, 'leader_get')
    @patch('os.listdir')
    @patch('os.remove')
    def test_key_write(
        self, remove, listdir, leader_get, rename, is_leader,
        mock_file_equal_to
    ):
        mock_file_equal_to.return_value = False
        is_leader.return_value = False
        leader_get.return_value = json.dumps(
            {utils.FERNET_KEY_REPOSITORY:
                {'0': 'key0', '1': 'key1'},
             utils.CREDENTIAL_KEY_REPOSITORY:
                {'0': 'key0', '1': 'key1'}})
        listdir.return_value = ['0', '1', '2']
        with patch.object(builtins, 'open', mock_open()) as m:
            utils.key_write()
            m.assert_called_with(utils.KEY_SETUP_FILE, "w")
        self.mkdir.has_calls([call(utils.CREDENTIAL_KEY_REPOSITORY,
                                   owner='keystone', group='keystone',
                                   perms=0o700),
                              call(utils.FERNET_KEY_REPOSITORY,
                                   owner='keystone', group='keystone',
                                   perms=0o700)])
        tmp_fernet_dir = utils.FERNET_KEY_REPOSITORY + ".tmp"
        tmp_creds_dir = utils.CREDENTIAL_KEY_REPOSITORY + ".tmp"
        # note 'any_order=True' as we are dealing with dictionaries in Py27
        self.write_file.assert_has_calls(
            [
                call(os.path.join(tmp_creds_dir, '0'),
                     u'key0', owner='keystone', group='keystone', perms=0o600),
                call(os.path.join(tmp_creds_dir, '1'),
                     u'key1', owner='keystone', group='keystone', perms=0o600),
                call(os.path.join(tmp_fernet_dir, '0'), u'key0',
                     owner='keystone', group='keystone', perms=0o600),
                call(os.path.join(tmp_fernet_dir, '1'), u'key1',
                     owner='keystone', group='keystone', perms=0o600),
            ], any_order=True)
        rename.assert_has_calls(
            [
                call(os.path.join(tmp_creds_dir, '0'),
                     os.path.join(utils.CREDENTIAL_KEY_REPOSITORY, '0')),
                call(os.path.join(tmp_creds_dir, '1'),
                     os.path.join(utils.CREDENTIAL_KEY_REPOSITORY, '1')),
                call(os.path.join(tmp_fernet_dir, '0'),
                     os.path.join(utils.FERNET_KEY_REPOSITORY, '0')),
                call(os.path.join(tmp_fernet_dir, '1'),
                     os.path.join(utils.FERNET_KEY_REPOSITORY, '1')),
            ], any_order=True)

    @patch.object(utils, 'keystone_context')
    @patch.object(utils, 'fernet_rotate')
    @patch.object(utils, 'key_leader_set')
    @patch.object(utils, 'os')
    @patch.object(utils, 'is_leader')
    def test_fernet_keys_rotate_and_sync(self, mock_is_leader, mock_os,
                                         mock_key_leader_set,
                                         mock_fernet_rotate,
                                         mock_keystone_context):
        self.test_config.set('fernet-max-active-keys', 3)
        self.test_config.set('token-expiration', 60)
        self.time.time.return_value = 0

        # if not leader shouldn't do anything
        mock_is_leader.return_value = False
        utils.fernet_keys_rotate_and_sync()
        mock_os.stat.assert_not_called()
        # shouldn't do anything as the token provider is wrong
        mock_keystone_context.fernet_enabled.return_value = False
        mock_is_leader.return_value = True
        utils.fernet_keys_rotate_and_sync()
        mock_os.stat.assert_not_called()
        # fail gracefully if key repository is not initialized
        mock_keystone_context.fernet_enabled.return_value = True
        mock_os.stat.side_effect = Exception()
        with self.assertRaises(Exception):
            utils.fernet_keys_rotate_and_sync()
        self.time.time.assert_not_called()
        mock_os.stat.side_effect = None
        # now set up the times, so that it still shouldn't be called.
        self.time.time.return_value = 30
        self.time.gmtime = time.gmtime
        self.time.asctime = time.asctime
        _stat = MagicMock()
        _stat.st_mtime = 10
        mock_os.stat.return_value = _stat
        mock_key_leader_set.reset_mock()
        utils.fernet_keys_rotate_and_sync(log_func=self.log)
        self.log.assert_called_once_with(
            'No rotation until at least Thu Jan  1 00:01:10 1970, '
            'but checking keys are set in leader settings.',
            level='DEBUG')
        # key_leader_set is always called once, as even if keys are not rotated
        # it's needs to be certain that they are in the leader settings
        mock_key_leader_set.assert_called_once_with()
        # finally, set it up so that the rotation and sync occur
        self.time.time.return_value = 71
        mock_key_leader_set.reset_mock()
        utils.fernet_keys_rotate_and_sync()
        mock_fernet_rotate.assert_called_once_with()
        mock_key_leader_set.assert_called_once_with()

    @patch.object(utils, 'resource_map')
    @patch.object(utils.os.path, 'isdir')
    def test_restart_map(self, osp_isdir, resource_map):
        rsc_map = collections.OrderedDict([
            ('file1', {
                'services': ['svc1'],
                'contexts': ['ctxt1']})])
        resource_map.return_value = rsc_map
        osp_isdir.return_value = False
        self.assertEqual(
            utils.restart_map(),
            collections.OrderedDict([
                ('file1', ['svc1'])]))
        osp_isdir.return_value = True
        self.assertEqual(
            utils.restart_map(),
            collections.OrderedDict([
                ('file1', ['svc1']),
                ('/etc/apache2/ssl/keystone/*', ['apache2'])]))

    def test_assemble_endpoints(self):
        data = {
            "egress-subnets": "10.5.0.16/32",
            "ingress-address": "10.5.0.16",
            "neutron_admin_url": "http://10.5.0.16:9696",
            "neutron_internal_url": "http://10.5.1.16:9696",
            "neutron_public_url": "http://10.5.2.16:9696",
            "neutron_region": "RegionOne",
            "neutron_service": "neutron",
            "private-address": "10.5.3.16",
            "relation_trigger": "821bd014-3189-4062-a004-5b286335bcef",
        }
        expected = {
            'neutron': {'service': 'neutron',
                        'admin_url': "http://10.5.0.16:9696",
                        'internal_url': "http://10.5.1.16:9696",
                        'public_url': "http://10.5.2.16:9696",
                        'region': 'RegionOne'},
            # these are leftovers which are present in the response
            'egress-subnets': {'': "10.5.0.16/32"},
            'ingress-address': {'': "10.5.0.16"},
            'relation': {'trigger': "821bd014-3189-4062-a004-5b286335bcef"},
            'private-address': {'': "10.5.3.16"}
        }
        endpoints = utils.assemble_endpoints(data)
        self.assertDictEqual(dict(endpoints), expected)

    def test_endpoints_checksum(self):
        settings = {'service': 'neutron',
                    'admin_url': "http://10.5.0.16:9696",
                    'internal_url': "http://10.5.1.16:9696",
                    'public_url': "http://10.5.2.16:9696",
                    'region': 'RegionOne'}
        csum = utils.endpoints_checksum(settings)
        self.assertEqual(csum,
                         ('d938ff5656d3d9b50345e8061b4c73c8'
                          '116a9c7fbc087765ce2e3a4a5df7cb17'))

    @patch.object(utils, 'leader_get')
    def test_get_charm_credentials(self, mock_leader_get):
        expect = ks_types.CharmCredentials(
            '_charm-keystone-admin', 'fakepassword',
            'all', 'admin', 'default', 'default')
        mock_leader_get.return_value = 'fakepassword'
        self.assertEquals(utils.get_charm_credentials(), expect)
        mock_leader_get.assert_called_once_with(expect.username + '_passwd')
        mock_leader_get.retrun_value = None
        mock_leader_get.side_effect = [None]
        with self.assertRaises(RuntimeError):
            utils.get_charm_credentials()

    @patch.object(utils, 'leader_get')
    def test_is_bootstrapped(self, mock_leader_get):
        mock_leader_get.side_effect = [None, None]
        self.assertFalse(utils.is_bootstrapped())
        mock_leader_get.assert_called_once_with('keystone-bootstrapped')
        mock_leader_get.side_effect = [True, None]
        self.assertFalse(utils.is_bootstrapped())
        mock_leader_get.side_effect = [True, 'fakepassword']
        self.assertTrue(utils.is_bootstrapped())
        mock_leader_get.assert_called_with('_charm-keystone-admin_passwd')

    @patch.object(utils, 'get_manager')
    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'leader_set')
    @patch.object(utils, 'resolve_address')
    @patch.object(utils, 'endpoint_url')
    @patch.object(utils, 'pwgen')
    @patch.object(utils, 'leader_get')
    @patch.object(utils, 'get_api_suffix')
    def test_bootstrap_keystone(
            self,
            mock_get_api_suffix,
            mock_leader_get,
            mock_pwgen,
            mock_endpoint_url,
            mock_resolve_address,
            mock_leader_set,
            mock_is_leader,
            mock_get_manager):
        configs = MagicMock()
        mock_get_api_suffix.return_value = 'suffix'
        mock_resolve_address.side_effect = lambda x: x
        mock_endpoint_url.side_effect = (
            lambda x, y, z: 'http://{}:{}/{}'.format(x, y, z))
        mock_leader_get.return_value = 'fakepassword'
        mock_is_leader.return_value = True
        mock_get_manager().resolve_user_id.return_value = 'fakeid'
        self.os_release.return_value = 'queens'
        utils.bootstrap_keystone(configs=configs)
        self.subprocess.check_call.assert_called_once_with(
            ('keystone-manage', 'bootstrap',
             '--bootstrap-username', '_charm-keystone-admin',
             '--bootstrap-password', 'fakepassword',
             '--bootstrap-project-name', 'admin',
             '--bootstrap-role-name', 'Admin',
             '--bootstrap-service-name', 'keystone',
             '--bootstrap-admin-url', 'http://admin:35357/suffix',
             '--bootstrap-public-url', 'http://public:5000/suffix',
             '--bootstrap-internal-url', 'http://int:5000/suffix',
             '--bootstrap-region-id', 'RegionOne'),
        )
        mock_leader_set.assert_called_once_with({
            'keystone-bootstrapped': True,
            '_charm-keystone-admin_passwd': 'fakepassword'})
        self.assertFalse(configs.write_all.called)
        mock_leader_set.reset_mock()
        self.os_release.return_value = 'pike'
        utils.bootstrap_keystone(configs=configs)
        mock_leader_set.assert_has_calls([
            call({'keystone-bootstrapped': True,
                  '_charm-keystone-admin_passwd': 'fakepassword'}),
            call({'transitional_charm_user_id': 'fakeid'}),
        ])
        configs.write_all.assert_called_once_with()

    def test_get_real_role_name(self):

        def _resolve_role_name(role_name):
            roles = {'member': 'Member'}
            return roles.get(role_name)

        manager = MagicMock()
        manager.resolve_role_name.side_effect = _resolve_role_name
        self.assertEqual(
            utils.get_real_role_names(
                ['member', 'MissingRole'],
                manager),
            ['Member'])

    @patch.object(utils, 'get_real_role_names')
    @patch.object(utils, 'grant_role')
    def test_grant_admin_additional_relation_roles(self, grant_role,
                                                   get_real_role_names):
        manager = MagicMock()

        def _real_role_names(roles, manager):
            return [x.capitalize() for x in roles]
        get_real_role_names.side_effect = _real_role_names
        utils.grant_admin_additional_relation_roles(
            manager,
            {
                'add_role_to_admin': ('load-balancer_quota_admin,'
                                      'load-balancer_admin')})
        grant_role.assert_has_calls(
            [
                call(
                    'admin',
                    'Load-balancer_quota_admin',
                    tenant='admin',
                    user_domain='admin_domain',
                    project_domain='admin_domain'),
                call(
                    'admin',
                    'Load-balancer_admin',
                    tenant='admin',
                    user_domain='admin_domain',
                    project_domain='admin_domain')],
            any_order=True)
        grant_role.reset_mock()
        utils.grant_admin_additional_relation_roles(manager, {})
        self.assertFalse(grant_role.called)

    def test_get_add_role_to_admin(self):
        self.assertEqual(
            utils.get_add_role_to_admin({
                'add_role_to_admin': ('load-balancer_quota_admin,'
                                      'load-balancer_admin')}),
            ['load-balancer_quota_admin', 'load-balancer_admin'])
        self.assertEqual(
            utils.get_add_role_to_admin({}),
            [])

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'leader_set')
    @patch.object(utils, 'pwgen')
    @patch.object(utils, 'is_leader')
    def test_rotate_admin_password_without_config(
            self, is_leader, pwgen, leader_set, update_user_password):
        user = 'test-user'
        password = 'password'
        is_leader.return_value = True
        pwgen.return_value = password
        self.test_config.set('admin-user', user)
        self.test_config.set('admin-password', '')

        utils.rotate_admin_passwd()

        pwgen.assert_called_once()
        update_user_password.assert_called_once_with(
            user, password, utils.ADMIN_DOMAIN)
        leader_set.assert_called_once_with({'admin_passwd': password})

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'leader_set')
    @patch.object(utils, 'pwgen')
    @patch.object(utils, 'is_leader')
    def test_rotate_admin_password_with_config(
            self, is_leader, pwgen, leader_set, update_user_password):
        user = 'test-user'
        password = 'password'
        is_leader.return_value = True
        self.test_config.set('admin-user', user)
        self.test_config.set('admin-password', password)

        with self.assertRaises(RuntimeError):
            utils.rotate_admin_passwd()

        pwgen.assert_not_called()
        update_user_password.assert_not_called()
        leader_set.assert_not_called()

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'leader_set')
    @patch.object(utils, 'pwgen')
    @patch.object(utils, 'is_leader')
    def test_rotate_admin_password_outside_leader(
            self, is_leader, pwgen, leader_set, update_user_password):
        is_leader.return_value = False

        with self.assertRaises(RuntimeError):
            utils.rotate_admin_passwd()

        pwgen.assert_not_called()
        update_user_password.assert_not_called()
        leader_set.assert_not_called()

    @patch.object(utils, 'leader_get')
    def test_get_service_usernames(self, leader_get):
        leader_get.return_value = {
            'ignore-me': 'ignored-value',
            'glance_passwd': 'glance-pass',
            'admin_passed': 'ignored-value',
            'head_passwd': 'ignored-value',
            'cinderv2_cinderv3_passwd': 'cinder-pass',
            'cinderv2_other_passwd': 'ignored-value',
            'keystone_passwd': 'ignored-value',
        }
        self.assertEqual(sorted(utils.get_service_usernames()),
                         sorted(['glance', 'cinderv2_cinderv3']))

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'rotate_service_password')
    @patch.object(utils, 'is_service_password_saved')
    @patch.object(utils, 'is_leader')
    def test_rotate_service_user_passwd__not_leader(
        self,
        is_leader,
        is_service_password_saved,
        rotate_service_password,
        update_user_password,
    ):
        is_leader.return_value = False
        with self.assertRaises(utils.NotLeaderError):
            utils.rotate_service_user_passwd('glance')

    def _assert_regex_in_log(self, regex):
        calls = self.log.call_args_list
        self.assertEqual(len(calls), 1)
        args = calls[0][0]
        msg = args[0]
        self.assertRegex(msg, regex)

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'rotate_service_password')
    @patch.object(utils, 'is_service_password_saved')
    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'get_service_usernames')
    def test_rotate_service_user_passwd__not_valid_service(
        self,
        get_service_usernames,
        is_leader,
        is_service_password_saved,
        rotate_service_password,
        update_user_password,
    ):
        is_leader.return_value = True
        get_service_usernames.return_value = ['glance', 'heat']
        with self.assertRaises(utils.InvalidService):
            utils.rotate_service_user_passwd('unknown-service')
        self._assert_regex_in_log(r"^Invalid service.*unknown-service")

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'rotate_service_password')
    @patch.object(utils, 'is_service_password_saved')
    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'get_service_usernames')
    def test_rotate_service_user_passwd__service_not_in_model(
        self,
        get_service_usernames,
        is_leader,
        is_service_password_saved,
        rotate_service_password,
        update_user_password,
    ):
        is_leader.return_value = True
        is_service_password_saved.return_value = False
        get_service_usernames.return_value = ['glance', 'heat']
        with self.assertRaises(utils.InvalidService):
            utils.rotate_service_user_passwd('glance')
        self._assert_regex_in_log(r"^Service requested.*this model")

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'rotate_service_password')
    @patch.object(utils, 'is_service_password_saved')
    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'get_service_usernames')
    def test_rotate_service_user_passwd__service_not_in_relations(
        self,
        get_service_usernames,
        is_leader,
        is_service_password_saved,
        rotate_service_password,
        update_user_password,
    ):
        is_leader.return_value = True
        is_service_password_saved.return_value = True
        get_service_usernames.return_value = ['glance', 'heat']
        self.relation_ids.return_value = []
        rotate_service_password.return_value = 'the-password'
        utils.rotate_service_user_passwd('glance')
        self._assert_regex_in_log(
            r"^Service .*'glance'.*not found.*relations")
        rotate_service_password.assert_called_once_with('glance')
        update_user_password.assert_called_once_with(
            'glance', 'the-password', utils.SERVICE_DOMAIN)
        self.relation_ids.assert_called_once_with('identity-service')

    @patch.object(utils, 'update_user_password')
    @patch.object(utils, 'rotate_service_password')
    @patch.object(utils, 'is_service_password_saved')
    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'get_service_usernames')
    def test_rotate_service_user_passwd__complete(
        self,
        get_service_usernames,
        is_leader,
        is_service_password_saved,
        rotate_service_password,
        update_user_password,
    ):
        is_leader.return_value = True
        is_service_password_saved.return_value = True
        get_service_usernames.return_value = ['glance', 'heat']
        self.relation_ids.return_value = ['relation:4']
        self.relation_get.return_value = 'glance'
        rotate_service_password.return_value = 'the-password'
        self.local_unit.return_value = 'keystone/0'

        utils.rotate_service_user_passwd('glance')
        self.log.assert_not_called()
        rotate_service_password.assert_called_once_with('glance')
        update_user_password.assert_called_once_with(
            'glance', 'the-password', utils.SERVICE_DOMAIN)
        self.relation_ids.assert_called_once_with('identity-service')
        self.relation_get.assert_called_once_with(
            unit='keystone/0', rid='relation:4',
            attribute='service_username')
        self.peer_store_and_set.assert_called_once_with(
            relation_id='relation:4', service_password='the-password')
        self.relation_set.assert_called_once_with(
            relation_id='relation:4', service_password='the-password')

    @patch.object(utils, 'set_service_password')
    @patch.object(utils, 'pwgen')
    def test_rotate_service_password(self, pwgen, set_service_password):
        pwgen.return_value = 'the-password'
        self.assertEqual(utils.rotate_service_password('glance'),
                         'the-password')
        pwgen.assert_called_once_with(length=utils.SERVICE_PASSWD_LENGTH)
        set_service_password.assert_called_once_with('the-password', 'glance')

    @patch.object(utils, 'leader_get')
    def test_is_service_password_saved__true(self, _leader_get):
        _leader_get.return_value = 'a-thing'
        self.assertTrue(utils.is_service_password_saved('glance'))
        _leader_get.assert_called_once_with('glance_passwd')

    @patch.object(utils, 'leader_get')
    def test_is_service_password_saved__false(self, _leader_get):
        _leader_get.return_value = None
        self.assertFalse(utils.is_service_password_saved('glance'))
        _leader_get.assert_called_once_with('glance_passwd')
