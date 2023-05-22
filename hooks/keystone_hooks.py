#!/usr/bin/env python3
#
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

import json
import os
import sys

_path = os.path.dirname(os.path.realpath(__file__))
_root = os.path.abspath(os.path.join(_path, '..'))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_root)

from subprocess import check_call

from charmhelpers.core import unitdata

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    DEBUG,
    INFO,
    WARNING,
    relation_get,
    relation_ids,
    relation_set,
    related_units,
    status_set,
    open_port,
    is_leader,
    relation_id,
    leader_set,
)

from charmhelpers.core.host import (
    service_pause,
    service_stop,
    service_start,
    service_restart,
)

from charmhelpers.fetch import (
    apt_install, apt_update,
    filter_installed_packages
)

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available,
    sync_db_with_multi_ipv6_addresses,
    os_release,
    pausable_restart_on_change as restart_on_change,
    is_unit_paused_set,
    CompareOpenStackReleases,
    snap_install_requested,
    install_os_snaps,
    get_snaps_install_info_from_origin,
    enable_memcache,
    series_upgrade_prepare,
    series_upgrade_complete,
    inform_peers_if_ready,
    check_api_unit_ready,
    check_api_application_ready,
    is_db_ready,
)

from keystone_context import fernet_enabled

from keystone_utils import (
    add_service_to_keystone,
    bootstrap_keystone,
    ensure_all_service_accounts_protected_for_pci_dss_options,
    add_credentials_to_keystone,
    determine_packages,
    disable_unused_apache_sites,
    do_openstack_upgrade_reexec,
    ensure_initial_admin,
    get_admin_passwd,
    migrate_database,
    save_script_rc,
    post_snap_install,
    register_configs,
    restart_map,
    services,
    CLUSTER_RES,
    KEYSTONE_CONF,
    POLICY_JSON,
    TOKEN_FLUSH_CRON_FILE,
    setup_ipv6,
    send_notifications,
    is_db_initialised,
    is_service_present,
    delete_service_entry,
    assess_status,
    run_in_apache,
    restart_function_map,
    WSGI_KEYSTONE_API_CONF,
    restart_pid_check,
    get_api_version,
    ADMIN_DOMAIN,
    ADMIN_PROJECT,
    create_or_show_domain,
    restart_keystone,
    key_leader_set,
    key_setup,
    key_write,
    pause_unit_helper,
    resume_unit_helper,
    remove_old_packages,
    stop_manager_instance,
    assemble_endpoints,
    endpoints_dict,
    endpoints_checksum,
)

from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    https,
    is_clustered,
)

from charmhelpers.contrib.openstack.ha.utils import (
    generate_ha_relation_data,
    expect_ha,
)

from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.peerstorage import (
    peer_echo,
)
from charmhelpers.contrib.openstack.ip import (
    ADMIN,
    PUBLIC,
    resolve_address,
)

from charmhelpers.contrib.network.ip import (
    get_relation_ip,
)
from charmhelpers.contrib.openstack.context import ADDRESS_TYPES

from charmhelpers.contrib.charmsupport import nrpe

from charmhelpers.contrib.hardening.harden import harden

from charmhelpers.contrib.openstack.cert_utils import (
    get_certificate_request,
    process_certificates,
)

from charmhelpers.contrib.openstack.policyd import (
    maybe_do_policyd_overrides,
    maybe_do_policyd_overrides_on_config_changed,
)


hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook('install.real')
@harden()
def install():
    status_set('maintenance', 'Executing pre-install')
    execd_preinstall()
    configure_installation_source(config('openstack-origin'))
    status_set('maintenance', 'Installing apt packages')
    apt_update()
    # (ajkavanagh) LP: #1989538
    # Tactical fix to force openstack-release to match the configured
    # installation source; note that it comes after apt_update().
    apt_install(['openstack-release'], fatal=False, quiet=True)
    apt_install(determine_packages(), fatal=True)

    if snap_install_requested():
        status_set('maintenance', 'Installing keystone snap')
        # NOTE(thedac) Setting devmode until LP#1719636 is fixed
        install_os_snaps(
            get_snaps_install_info_from_origin(
                ['keystone'],
                config('openstack-origin'),
                mode='devmode'))
        post_snap_install()
        service_stop('snap.keystone.*')
    else:
        # unconfigured keystone service will prevent start of haproxy in some
        # circumstances. make sure haproxy runs. LP #1648396
        service_stop('keystone')
        service_start('haproxy')
        if run_in_apache():
            disable_unused_apache_sites()
            service_pause('keystone')
    # call the policy overrides handler which will install any policy overrides
    maybe_do_policyd_overrides(
        os_release('keystone'),
        'keystone',
        restart_handler=lambda: service_restart('apache2'))


@hooks.hook('config-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@harden()
def config_changed():
    # if we are paused, delay doing any config changed hooks.
    # It is forced on the resume.
    if is_unit_paused_set():
        log("Unit is pause or upgrading. Skipping config_changed", "WARN")
        return

    if config('prefer-ipv6'):
        status_set('maintenance', 'configuring ipv6')
        setup_ipv6()
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'))

    if not config('action-managed-upgrade'):
        if openstack_upgrade_available('keystone'):
            status_set('maintenance', 'Running openstack upgrade')
            do_openstack_upgrade_reexec(configs=CONFIGS)

    for r_id in relation_ids('cluster'):
        cluster_joined(rid=r_id)

    # call the policy overrides handler which will install any policy overrides
    maybe_do_policyd_overrides_on_config_changed(
        os_release('keystone'),
        'keystone',
        restart_handler=lambda: service_restart('apache2'))

    config_changed_postupgrade()


@hooks.hook('config-changed-postupgrade')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@harden()
def config_changed_postupgrade():
    save_script_rc()
    release = os_release('keystone')
    if run_in_apache(release=release):
        # Need to ensure mod_wsgi is installed and apache2 is reloaded
        # immediately as charm queries its local keystone before restart
        # decorator can fire
        apt_install(filter_installed_packages(determine_packages()))
        # when deployed from source, init scripts aren't installed
        service_pause('keystone')

        disable_unused_apache_sites()
        if WSGI_KEYSTONE_API_CONF in CONFIGS.templates:
            CONFIGS.write(WSGI_KEYSTONE_API_CONF)
        if not is_unit_paused_set():
            restart_pid_check('apache2')
            stop_manager_instance()

    if enable_memcache(release=release):
        # If charm or OpenStack have been upgraded then the list of required
        # packages may have changed so ensure they are installed.
        apt_install(filter_installed_packages(determine_packages()))

    if is_leader() and fernet_enabled():
        key_setup()
        key_leader_set()

    configure_https()
    open_port(config('service-port'))

    update_nrpe_config()

    CONFIGS.write_all()

    if snap_install_requested() and not is_unit_paused_set():
        service_restart('snap.keystone.*')
        stop_manager_instance()

    if (is_db_initialised() and is_elected_leader(CLUSTER_RES) and not
            is_unit_paused_set()):
        ensure_initial_admin(config)
        if CompareOpenStackReleases(
                os_release('keystone')) >= 'liberty':
            CONFIGS.write(POLICY_JSON)

    update_all_identity_relation_units()
    update_all_domain_backends()
    update_all_fid_backends()

    for r_id in relation_ids('ha'):
        ha_joined(relation_id=r_id)

    notify_middleware_with_release_version()
    inform_peers_if_ready(check_api_unit_ready)


@hooks.hook('shared-db-relation-joined')
def db_joined():
    if config('prefer-ipv6'):
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'))
    else:
        # Avoid churn check for access-network early
        access_network = None
        for unit in related_units():
            access_network = relation_get(unit=unit,
                                          attribute='access-network')
            if access_network:
                break
        host = get_relation_ip('shared-db', cidr_network=access_network)

        relation_set(database=config('database'),
                     username=config('database-user'),
                     hostname=host)


def update_all_identity_relation_units():
    unit_ready, _ = check_api_application_ready()
    if not unit_ready:
        log(
            ("Keystone charm unit not ready - deferring identity-relation "
             "updates"),
            level=INFO)
        return

    log('Firing identity_changed hook for all related services.')
    for rid in relation_ids('identity-service'):
        for unit in related_units(rid):
            identity_changed(relation_id=rid, remote_unit=unit)
    log('Firing admin_relation_changed hook for all related services.')
    for rid in relation_ids('identity-admin'):
        admin_relation_changed(rid)
    log('Firing identity_credentials_changed hook for all related services.')
    for rid in relation_ids('identity-credentials'):
        for unit in related_units(rid):
            identity_credentials_changed(relation_id=rid, remote_unit=unit)


def update_all_domain_backends():
    """Re-trigger hooks for all domain-backend relations/units"""
    for rid in relation_ids('domain-backend'):
        for unit in related_units(rid):
            domain_backend_changed(relation_id=rid, unit=unit)


def update_all_fid_backends():
    if CompareOpenStackReleases(os_release('keystone')) < 'ocata':
        log('Ignoring keystone-fid-service-provider relation as it is'
            ' not supported on releases older than Ocata')
        return
    """If there are any config changes, e.g. for domain or service port
    make sure to update those for all relation-level buckets"""
    for rid in relation_ids('keystone-fid-service-provider'):
        update_keystone_fid_service_provider(relation_id=rid)


@restart_on_change(restart_map(), restart_functions=restart_function_map())
def leader_init_db_if_ready(use_current_context=False):
    """ Initialise the keystone db if it is ready and mark it as initialised.

    NOTE: this must be idempotent.
    """
    if not is_elected_leader(CLUSTER_RES):
        log("Not leader - skipping db init", level=DEBUG)
        return

    if is_db_initialised():
        log("Database already initialised - skipping db init", level=DEBUG)
        update_all_identity_relation_units()
        return

    # Bugs 1353135 & 1187508. Dbs can appear to be ready before the
    # units acl entry has been added. So, if the db supports passing
    # a list of permitted units then check if we're in the list.
    if not is_db_ready(use_current_context=use_current_context):
        log('Allowed_units list provided and this unit not present',
            level=INFO)
        return

    migrate_database()
    bootstrap_keystone(configs=CONFIGS)
    ensure_initial_admin(config)
    if CompareOpenStackReleases(
            os_release('keystone')) >= 'liberty':
        CONFIGS.write(POLICY_JSON)
    # Ensure any existing service entries are updated in the
    # new database backend.
    update_all_identity_relation_units()
    update_all_domain_backends()


@hooks.hook('shared-db-relation-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
def db_changed():
    if 'shared-db' not in CONFIGS.complete_contexts():
        log('shared-db relation incomplete. Peer not ready?')
    else:
        # here we may need to restart keystone's apache2 if the database
        # password has been rotated as otherwise the
        # `update_all_identity_related_units()` function will fail as it need
        # to use keystone to check the database.
        _maybe_config_updated()

        leader_init_db_if_ready(use_current_context=True)
        if CompareOpenStackReleases(
                os_release('keystone')) >= 'liberty':
            CONFIGS.write(POLICY_JSON)
        update_all_identity_relation_units()
        inform_peers_if_ready(check_api_unit_ready)


@restart_on_change(restart_map(),
                   restart_functions=restart_function_map())
def _maybe_config_updated():
    """Restart the keystone service is the configs have been updated."""
    CONFIGS.write(KEYSTONE_CONF)


@hooks.hook('shared-db-relation-departed',
            'shared-db-relation-broken')
def db_departed_or_broken():
    if is_leader():
        leader_set({'db-initialised': None})


@hooks.hook('identity-service-relation-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
def identity_changed(relation_id=None, remote_unit=None):
    notifications_checksums = {}
    notifications_endpoints = {}
    if is_leader():
        if not is_db_ready():
            log("identity-service-relation-changed hook fired before db "
                "ready - deferring until db ready", level=WARNING)
            return

        if not is_db_initialised():
            log("Database not yet initialised - deferring identity-relation "
                "updates", level=INFO)
            return

        if expect_ha() and not is_clustered():
            log("Expected to be HA but no hacluster relation yet", level=INFO)
            return

        add_service_to_keystone(relation_id, remote_unit)
        if is_service_present('neutron', 'network'):
            delete_service_entry('quantum', 'network')
        settings = relation_get(rid=relation_id, unit=remote_unit)

        # If endpoint has changed, notify to units related over the
        # identity-notifications interface. We base the decision to notify on
        # whether admin_url, public_url or internal_url have changed from
        # previous notify.
        service = settings.get('service')
        if service:
            key = '%s-endpoint-changed' % service
            notifications_endpoints[key] = endpoints_dict(settings)
            notifications_checksums[key] = endpoints_checksum(settings)
        else:
            # Some services don't set their name in the 'service' key in the
            # relation, for those their name is calculated from the prefix of
            # keys. See `assemble_endpoints()` for details.
            single = {'service', 'region', 'public_url',
                      'admin_url', 'internal_url'}
            endpoints = assemble_endpoints(settings)
            for ep in endpoints.keys():
                if single.issubset(endpoints[ep]):
                    key = '%s-endpoint-changed' % ep
                    log('endpoint: %s' % ep)
                    notifications_endpoints[key] = (
                        endpoints_dict(endpoints[ep])
                    )
                    notifications_checksums[key] = (
                        endpoints_checksum(endpoints[ep])
                    )
    else:
        log('Deferring identity_changed() to service leader.')

    if notifications_endpoints or notifications_checksums:
        send_notifications(notifications_checksums,
                           notifications_endpoints)


@hooks.hook('identity-credentials-relation-joined',
            'identity-credentials-relation-changed')
def identity_credentials_changed(relation_id=None, remote_unit=None):
    """Update the identity credentials relation on change

    Calls add_credentials_to_keystone

    :param relation_id: Relation id of the relation
    :param remote_unit: Related unit on the relation
    """
    if is_elected_leader(CLUSTER_RES):
        if expect_ha() and not is_clustered():
            log("Expected to be HA but no hacluster relation yet", level=INFO)
            return
        if not is_db_ready():
            log("identity-credentials-relation-changed hook fired before db "
                "ready - deferring until db ready", level=WARNING)
            return

        if not is_db_initialised():
            log("Database not yet initialised - deferring "
                "identity-credentials-relation updates", level=INFO)
            return

        unit_ready, _ = check_api_application_ready()
        if not unit_ready:
            log(
                ("Keystone charm unit not ready - deferring identity-relation "
                 "updates"),
                level=INFO)
            return

        # Create the tenant user
        add_credentials_to_keystone(relation_id, remote_unit)
    else:
        log('Deferring identity_credentials_changed() to service leader.')


@hooks.hook('cluster-relation-joined')
def cluster_joined(rid=None):
    settings = {}

    for addr_type in ADDRESS_TYPES:
        address = get_relation_ip(
            addr_type,
            cidr_network=config('os-{}-network'.format(addr_type)))
        if address:
            settings['{}-address'.format(addr_type)] = address

    settings['private-address'] = get_relation_ip('cluster')

    relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook('cluster-relation-changed')
@restart_on_change(restart_map(), stopstart=True)
def cluster_changed():
    # NOTE(jamespage) re-echo passwords for peer storage
    echo_whitelist = ['_passwd', 'identity-service:']

    log("Peer echo whitelist: {}".format(echo_whitelist), level=DEBUG)
    peer_echo(includes=echo_whitelist, force=True)

    update_all_identity_relation_units()

    CONFIGS.write_all()
    inform_peers_if_ready(check_api_unit_ready)


@hooks.hook('leader-elected')
@restart_on_change(restart_map(), stopstart=True)
def leader_elected():
    log('Unit has been elected leader.', level=DEBUG)
    # When the local unit has been elected the leader, update the cron jobs
    # to ensure that the cron jobs are active on this unit.
    CONFIGS.write(TOKEN_FLUSH_CRON_FILE)

    update_all_identity_relation_units()
    inform_peers_if_ready(check_api_unit_ready)


@hooks.hook('leader-settings-changed')
@restart_on_change(restart_map(), stopstart=True)
def leader_settings_changed():

    # we always want to write the keys on leader-settings-changed regardless of
    # whether the unit is paused or not.
    if fernet_enabled():
        key_write()

    # if we are paused, delay doing any config changed hooks.
    # It is forced on the resume.
    if is_unit_paused_set():
        log("Unit is pause or upgrading. Skipping config_changed", "WARN")
        return

    # Since minions are notified of a regime change via the
    # leader-settings-changed hook, rewrite the token flush cron job to make
    # sure only the leader is running the cron job.
    CONFIGS.write(TOKEN_FLUSH_CRON_FILE)

    # Make sure we keep domain and/or project ids used in templates up to date
    if CompareOpenStackReleases(
            os_release('keystone')) >= 'liberty':
        CONFIGS.write(POLICY_JSON)

    update_all_identity_relation_units()
    inform_peers_if_ready(check_api_unit_ready)


@hooks.hook('ha-relation-joined')
def ha_joined(relation_id=None):
    settings = generate_ha_relation_data('ks')
    relation_set(relation_id=relation_id, **settings)


@hooks.hook('ha-relation-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
def ha_changed():
    CONFIGS.write_all()

    clustered = relation_get('clustered')
    if clustered:
        log('Cluster configured, notifying other services and updating '
            'keystone endpoint configuration')
        for rid in relation_ids('certificates'):
            if related_units(rid):
                for unit in related_units(rid):
                    certs_changed(rid, unit)
        if (is_db_initialised() and is_elected_leader(CLUSTER_RES) and not
                is_unit_paused_set()):
            ensure_initial_admin(config)
            update_all_identity_relation_units()
            update_all_domain_backends()
            update_all_fid_backends()
            inform_peers_if_ready(check_api_unit_ready)


@hooks.hook('identity-admin-relation-changed')
def admin_relation_changed(relation_id=None):
    # TODO: fixup
    if expect_ha() and not is_clustered():
        log("Expected to be HA but no hacluster relation yet", level=INFO)
        return
    relation_data = {
        'service_hostname': resolve_address(ADMIN),
        'service_port': config('service-port'),
        'service_username': config('admin-user'),
        'service_tenant_name': config('admin-role'),
        'service_region': config('region'),
        'service_protocol': 'https' if https() else 'http',
        'api_version': get_api_version(),
    }
    if relation_data['api_version'] > 2:
        relation_data['service_user_domain_name'] = ADMIN_DOMAIN
        relation_data['service_project_domain_name'] = ADMIN_DOMAIN
        relation_data['service_project_name'] = ADMIN_PROJECT
    relation_data['service_password'] = get_admin_passwd()
    relation_set(relation_id=relation_id, **relation_data)


@hooks.hook('domain-backend-relation-changed')
def domain_backend_changed(relation_id=None, unit=None):
    if get_api_version() < 3:
        log('Domain specific backend identity configuration only supported '
            'with Keystone v3 API, skipping domain creation and '
            'restart.')
        return

    domain_name = relation_get(attribute='domain-name',
                               unit=unit,
                               rid=relation_id)
    if domain_name:
        # NOTE(jamespage): Only create domain data from lead
        #                  unit when clustered and database
        #                  is configured and created.
        if is_leader() and is_db_ready() and is_db_initialised():
            create_or_show_domain(domain_name)
        # NOTE(jamespage): Deployment may have multiple domains,
        #                  with different identity backends so
        #                  ensure that a domain specific nonce
        #                  is checked for restarts of keystone
        restart_nonce = relation_get(attribute='restart-nonce',
                                     unit=unit,
                                     rid=relation_id)
        domain_nonce_key = 'domain-restart-nonce-{}'.format(domain_name)
        db = unitdata.kv()
        if restart_nonce != db.get(domain_nonce_key):
            restart_keystone()
            db.set(domain_nonce_key, restart_nonce)
            db.flush()


def configure_https():
    '''
    Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    '''
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haproxy, apache)
    CONFIGS.write_all()
    # NOTE (thedac): When using snaps, nginx is installed, skip any apache2
    # config.
    if snap_install_requested():
        return
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        check_call(cmd)


@hooks.hook('upgrade-charm')
@restart_on_change(restart_map(), stopstart=True)
@harden()
def upgrade_charm():
    packages_to_install = filter_installed_packages(determine_packages())
    if packages_to_install:
        log('Installing apt packages')
        status_set('maintenance', 'Installing apt packages')
        apt_install(packages_to_install)
    packages_removed = remove_old_packages()

    if run_in_apache():
        disable_unused_apache_sites()

    log('Regenerating configuration files')
    status_set('maintenance', 'Regenerating configuration files')
    CONFIGS.write_all()

    # We no longer use the admin_token and need to ensure the charm has
    # credentials.  This call is idempotent and safe to run on existing
    # deployments.
    if is_leader():
        bootstrap_keystone(configs=CONFIGS)

    # See LP bug 1519035
    leader_init_db_if_ready()

    update_nrpe_config()

    if packages_removed:
        status_set('maintenance', 'Restarting services')
        log("Package purge detected, restarting services", "INFO")
        for s in services():
            service_restart(s)
        stop_manager_instance()

    if is_elected_leader(CLUSTER_RES):
        log('Cluster leader - ensuring endpoint configuration is up to '
            'date', level=DEBUG)
        update_all_identity_relation_units()
        # also ensure that the PCI-DSS protection is in place for service
        # accounts.
        ensure_all_service_accounts_protected_for_pci_dss_options()

    # call the policy overrides handler which will install any policy overrides
    maybe_do_policyd_overrides(
        os_release('keystone'),
        'keystone',
        restart_handler=lambda: service_restart('apache2'))
    inform_peers_if_ready(check_api_unit_ready)


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    log('Updating NRPE configuration')
    status_set('maintenance', 'Updating NRPE configuration')
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.copy_nrpe_checks()
    _services = []
    for service in services():
        if service.startswith('snap.'):
            service = service.split('.')[1]
        _services.append(service)
    nrpe.add_init_service_checks(nrpe_setup, _services, current_unit)
    nrpe.add_haproxy_checks(nrpe_setup, current_unit)
    nrpe_setup.write()


@hooks.hook('keystone-fid-service-provider-relation-joined',
            'keystone-fid-service-provider-relation-changed')
def keystone_fid_service_provider_changed():
    if get_api_version() < 3:
        log('Identity federation is only supported with keystone v3')
        return
    if CompareOpenStackReleases(os_release('keystone')) < 'ocata':
        log('Ignoring keystone-fid-service-provider relation as it is'
            ' not supported on releases older than Ocata')
        return
    # for the join case a keystone public-facing hostname and service
    # port need to be set
    update_keystone_fid_service_provider(relation_id=relation_id())

    # handle relation data updates (if any), e.g. remote_id_attribute
    # and a restart will be handled via a nonce, not restart_on_change
    CONFIGS.write(KEYSTONE_CONF)

    # The relation is container-scoped so this keystone unit's unitdata
    # will only contain a nonce of a single fid subordinate for a given
    # fid backend (relation id)
    restart_nonce = relation_get('restart-nonce')
    if restart_nonce:
        nonce = json.loads(restart_nonce)
        # multiplex by relation id for multiple federated identity
        # provider charms
        fid_nonce_key = 'fid-restart-nonce-{}'.format(relation_id())
        db = unitdata.kv()
        if restart_nonce != db.get(fid_nonce_key):
            restart_keystone()
            db.set(fid_nonce_key, nonce)
            db.flush()


@hooks.hook('keystone-fid-service-provider-relation-broken')
def keystone_fid_service_provider_broken():
    if CompareOpenStackReleases(os_release('keystone')) < 'ocata':
        log('Ignoring keystone-fid-service-provider relation as it is'
            ' not supported on releases older than Ocata')
        return

    restart_keystone()


@hooks.hook('websso-trusted-dashboard-relation-joined',
            'websso-trusted-dashboard-relation-changed',
            'websso-trusted-dashboard-relation-broken')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
def websso_trusted_dashboard_changed():
    if get_api_version() < 3:
        log('WebSSO is only supported with keystone v3')
        return
    if CompareOpenStackReleases(os_release('keystone')) < 'ocata':
        log('Ignoring WebSSO relation as it is not supported on'
            ' releases older than Ocata')
        return
    CONFIGS.write(KEYSTONE_CONF)


def update_keystone_fid_service_provider(relation_id=None):
    if relation_ids('certificates'):
        tls_enabled = True
    else:
        tls_enabled = (config('ssl_cert') is not None and
                       config('ssl_key') is not None)
    # NOTE: thedac Use resolve_address which checks host name, VIP  and
    # network bindings. Use PUBLIC for now. Possible TODO make this
    # configurable?
    hostname = resolve_address(endpoint_type=PUBLIC, override=True)
    # reactive endpoints implementation on the other side, hence
    # json-encoded values
    fid_settings = {
        'hostname': json.dumps(hostname),
        'port': json.dumps(config('service-port')),
        'tls-enabled': json.dumps(tls_enabled),
    }

    relation_set(relation_id=relation_id,
                 relation_settings=fid_settings)


@hooks.hook('certificates-relation-joined')
def certs_joined(relation_id=None):
    relation_set(
        relation_id=relation_id,
        relation_settings=get_certificate_request())


@hooks.hook('certificates-relation-changed')
@restart_on_change(restart_map(), stopstart=True)
def certs_changed(relation_id=None, unit=None):
    # update_all_identity_relation_units calls the keystone API
    # so configs need to be written and services restarted
    # before
    @restart_on_change(restart_map(), stopstart=True)
    def write_certs_and_config():
        if process_certificates('keystone', relation_id, unit):
            configure_https()
            return True
        return False
    if not write_certs_and_config():
        log('no certificates for us on the relation yet, deferring.',
            level=INFO)
        return
    # If enabling https the identity endpoints need updating.
    if (is_db_initialised() and is_elected_leader(CLUSTER_RES) and not
            is_unit_paused_set()):
        ensure_initial_admin(config)
    update_all_identity_relation_units()
    update_all_domain_backends()
    update_all_fid_backends()
    inform_peers_if_ready(check_api_unit_ready)


def notify_middleware_with_release_version():
    for rid in relation_ids('keystone-middleware'):
        relation_set(relation_id=rid, release=os_release('keystone'))


@hooks.hook('keystone-middleware-relation-joined')
def keystone_middleware_joined():
    notify_middleware_with_release_version()


@hooks.hook('keystone-middleware-relation-changed',
            'keystone-middleware-relation-broken',
            'keystone-middleware-relation-departed')
@restart_on_change(restart_map())
def keystone_middleware_changed():
    CONFIGS.write(KEYSTONE_CONF)


@hooks.hook('pre-series-upgrade')
def pre_series_upgrade():
    log("Running prepare series upgrade hook", "INFO")
    series_upgrade_prepare(
        pause_unit_helper, CONFIGS)


@hooks.hook('post-series-upgrade')
def post_series_upgrade():
    log("Running complete series upgrade hook", "INFO")
    # if we just upgraded from non systemd then ensure that the new packages of
    # keystone definitely don't run the keystone service if we are a wsgi
    # configured system.
    if run_in_apache():
        disable_unused_apache_sites()
        service_pause('keystone')
    series_upgrade_complete(
        resume_unit_helper, CONFIGS)


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status(CONFIGS)


if __name__ == '__main__':
    main()
