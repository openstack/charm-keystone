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

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import uuid

from itertools import chain
from collections import OrderedDict
from copy import deepcopy

from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    determine_api_port,
    https,
    get_hacluster_config,
    get_managed_services_and_ports,
)

from charmhelpers.contrib.openstack import context, templating
from charmhelpers.contrib.network.ip import (
    is_ipv6,
    get_ipv6_addr
)

from charmhelpers.contrib.openstack.ip import (
    get_invalid_vips,
    resolve_address,
    PUBLIC,
    INTERNAL,
    ADMIN
)

from charmhelpers.contrib.openstack.utils import (
    check_api_unit_ready,
    CompareOpenStackReleases,
    configure_installation_source,
    enable_memcache,
    error_out,
    get_api_application_status,
    get_os_codename_install_source,
    get_snaps_install_info_from_origin,
    get_subordinate_release_packages,
    install_os_snaps,
    is_unit_paused_set,
    make_assess_status_func,
    os_application_status_set,
    os_application_version_set,
    os_release,
    pause_unit,
    reset_os_release,
    resume_unit,
    save_script_rc as _save_script_rc,
    snap_install_requested,
)

from charmhelpers.core.decorators import (
    retry_on_exception,
)

from charmhelpers.core.hookenv import (
    atexit,
    config,
    is_leader,
    leader_get,
    leader_set,
    log,
    local_unit,
    relation_get,
    relation_set,
    relation_id,
    relation_ids,
    related_units,
    DEBUG,
    INFO,
    ERROR,
    WARNING,
    status_set,
)

from charmhelpers.fetch import (
    apt_install,
    apt_update,
    apt_upgrade,
    apt_purge,
    apt_autoremove,
    add_source,
    filter_missing_packages,
)

from charmhelpers.core.host import (
    mkdir,
    service_restart,
    service_stop,
    service_start,
    pwgen,
    lsb_release,
    CompareHostReleases,
    write_file,
)

from charmhelpers.contrib.peerstorage import (
    peer_store_and_set,
)

import keystone_context

import uds_comms as uds

import keystone_types

TEMPLATES = 'templates/'

# removed from original: charm-helper-sh
BASE_PACKAGES = [
    'apache2',
    'haproxy',
    'keystone',
    'openssl',
    'python-keystoneclient',
    'python-mysqldb',
    'python-psycopg2',
    'python3-six',
    'pwgen',
    'uuid',
]

PY3_PACKAGES = [
    'python3-keystone',
    'python3-keystoneclient',
    'python3-memcache',
    'python3-six',
    'libapache2-mod-wsgi-py3',
]

BASE_PACKAGES_SNAP = [
    'haproxy',
    'openssl',
    'python3-six',
    'pwgen',
    'uuid',
]

VERSION_PACKAGE = 'keystone'

if snap_install_requested():
    SNAP_BASE_DIR = "/snap/keystone/current"
    SNAP_COMMON_DIR = "/var/snap/keystone/common"
    SNAP_COMMON_ETC_DIR = "{}/etc".format(SNAP_COMMON_DIR)
    SNAP_COMMON_KEYSTONE_DIR = "{}/keystone".format(SNAP_COMMON_ETC_DIR)
    KEYSTONE_USER = 'root'
    KEYSTONE_CONF = ('{}/keystone.conf.d/keystone.conf'
                     ''.format(SNAP_COMMON_KEYSTONE_DIR))
    KEYSTONE_CONF_DIR = os.path.dirname(KEYSTONE_CONF)
    KEYSTONE_NGINX_SITE_CONF = ("{}/nginx/sites-enabled/keystone-nginx.conf"
                                "".format(SNAP_COMMON_ETC_DIR))
    KEYSTONE_NGINX_CONF = "{}/nginx/nginx.conf".format(SNAP_COMMON_ETC_DIR)
    KEYSTONE_LOGGER_CONF = "{}/logging.conf".format(SNAP_COMMON_KEYSTONE_DIR)
    SNAP_LIB_DIR = '{}/lib'.format(SNAP_COMMON_DIR)
    STORED_PASSWD = "{}/keystone.passwd".format(SNAP_LIB_DIR)
    STORED_ADMIN_DOMAIN_ID = ("{}/keystone.admin_domain_id"
                              "".format(SNAP_LIB_DIR))
    STORED_DEFAULT_DOMAIN_ID = ("{}/keystone.default_domain_id"
                                "".format(SNAP_LIB_DIR))
    SERVICE_PASSWD_PATH = '{}/services.passwd'.format(SNAP_LIB_DIR)
    POLICY_JSON = ('{}/keystone.conf.d/policy.json'
                   ''.format(SNAP_COMMON_KEYSTONE_DIR))
    BASE_SERVICES = ['snap.keystone.uwsgi', 'snap.keystone.nginx']
else:
    APACHE_SSL_DIR = '/etc/apache2/ssl/keystone'
    KEYSTONE_USER = 'keystone'
    KEYSTONE_CONF = "/etc/keystone/keystone.conf"
    KEYSTONE_NGINX_CONF = None
    KEYSTONE_NGINX_SITE_CONF = None
    KEYSTONE_LOGGER_CONF = "/etc/keystone/logging.conf"
    KEYSTONE_CONF_DIR = os.path.dirname(KEYSTONE_CONF)
    STORED_PASSWD = "/var/lib/keystone/keystone.passwd"
    STORED_ADMIN_DOMAIN_ID = "/var/lib/keystone/keystone.admin_domain_id"
    STORED_DEFAULT_DOMAIN_ID = "/var/lib/keystone/keystone.default_domain_id"
    SERVICE_PASSWD_PATH = '/var/lib/keystone/services.passwd'
    POLICY_JSON = '/etc/keystone/policy.json'
    BASE_SERVICES = [
        'keystone',
    ]


HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
APACHE_PORTS_CONF = '/etc/apache2/ports.conf'
APACHE_CONF = '/etc/apache2/sites-available/openstack_https_frontend'
APACHE_24_CONF = '/etc/apache2/sites-available/openstack_https_frontend.conf'
MEMCACHED_CONF = '/etc/memcached.conf'

CHARM_USER = '_charm-keystone-admin'
CLUSTER_RES = 'grp_ks_vips'
ADMIN_DOMAIN = 'admin_domain'
ADMIN_PROJECT = 'admin'
DEFAULT_DOMAIN = 'default'
SERVICE_DOMAIN = 'service_domain'
TOKEN_FLUSH_CRON_FILE = '/etc/cron.d/keystone-token-flush'
KEY_SETUP_FILE = '/etc/keystone/key-setup'
CREDENTIAL_KEY_REPOSITORY = '/etc/keystone/credential-keys/'
FERNET_KEY_REPOSITORY = '/etc/keystone/fernet-keys/'
FERNET_KEY_ROTATE_SYNC_CRON_FILE = '/etc/cron.d/keystone-fernet-rotate-sync'
WSGI_KEYSTONE_API_CONF = '/etc/apache2/sites-enabled/wsgi-openstack-api.conf'
UNUSED_APACHE_SITE_FILES = ['/etc/apache2/sites-enabled/keystone.conf',
                            '/etc/apache2/sites-enabled/wsgi-keystone.conf']
SERVICE_PASSWD_LENGTH = 64
SERVICE_ROLE = "service"

BASE_RESOURCE_MAP = OrderedDict([
    (KEYSTONE_CONF, {
        'services': BASE_SERVICES,
        'contexts': [keystone_context.KeystoneContext(),
                     context.SharedDBContext(ssl_dir=KEYSTONE_CONF_DIR),
                     context.SyslogContext(),
                     keystone_context.HAProxyContext(),
                     context.BindHostContext(),
                     context.WorkerConfigContext(),
                     context.MemcacheContext(package='keystone'),
                     keystone_context.KeystoneFIDServiceProviderContext(),
                     keystone_context.WebSSOTrustedDashboardContext(),
                     keystone_context.context.SubordinateConfigContext(
                         interface=['keystone-middleware'],
                         service='keystone',
                         config_file=KEYSTONE_CONF),
                     keystone_context.MiddlewareContext(),
                     keystone_context.AuthMethods()]
    }),
    (KEYSTONE_LOGGER_CONF, {
        'contexts': [keystone_context.KeystoneLoggingContext()],
        'services': BASE_SERVICES,
    }),
    (HAPROXY_CONF, {
        'contexts': [context.HAProxyContext(singlenode_mode=True),
                     keystone_context.HAProxyContext()],
        'services': ['haproxy'],
    }),
    (KEYSTONE_NGINX_CONF, {
        'services': BASE_SERVICES,
        'contexts': [keystone_context.KeystoneContext(),
                     keystone_context.NginxSSLContext(),
                     context.SharedDBContext(ssl_dir=KEYSTONE_CONF_DIR),
                     context.SyslogContext(),
                     keystone_context.HAProxyContext(),
                     context.BindHostContext(),
                     context.WorkerConfigContext()],
    }),
    (KEYSTONE_NGINX_SITE_CONF, {
        'services': BASE_SERVICES,
        'contexts': [keystone_context.KeystoneContext(),
                     context.SharedDBContext(ssl_dir=KEYSTONE_CONF_DIR),
                     context.SyslogContext(),
                     keystone_context.HAProxyContext(),
                     keystone_context.NginxSSLContext(),
                     context.BindHostContext(),
                     context.WorkerConfigContext()],
    }),
    (APACHE_CONF, {
        'contexts': [keystone_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (APACHE_24_CONF, {
        'contexts': [keystone_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (POLICY_JSON, {
        'contexts': [keystone_context.KeystoneContext()],
        'services': BASE_SERVICES,
    }),
    (TOKEN_FLUSH_CRON_FILE, {
        'contexts': [keystone_context.TokenFlushContext(),
                     context.SyslogContext()],
        'services': [],
    }),
    (FERNET_KEY_ROTATE_SYNC_CRON_FILE, {
        'contexts': [keystone_context.FernetCronContext(),
                     context.SyslogContext()],
        'services': [],
    }),
    (APACHE_PORTS_CONF, {
        'contexts': [],
        'services': ['apache2'],
    }),
])

valid_services = {
    "nova": {
        "type": "compute",
        "desc": "Nova Compute Service"
    },
    "nova-volume": {
        "type": "volume",
        "desc": "Nova Volume Service"
    },
    "cinder": {
        "type": "volume",
        "desc": "Cinder Volume Service v1"
    },
    "cinderv2": {
        "type": "volumev2",
        "desc": "Cinder Volume Service v2"
    },
    "cinderv3": {
        "type": "volumev3",
        "desc": "Cinder Volume Service v3"
    },
    "contrail-api": {
        "type": "ApiServer",
        "desc": "Contrail API Service"
    },
    "contrail-analytics": {
        "type": "OpServer",
        "desc": "Contrail Analytics Service"
    },
    "dmapi": {
        "type": "datamover",
        "desc": "Trilio DataMover API Service"
    },
    "ec2": {
        "type": "ec2",
        "desc": "EC2 Compatibility Layer"
    },
    "glance": {
        "type": "image",
        "desc": "Glance Image Service"
    },
    "s3": {
        "type": "s3",
        "desc": "S3 Compatible object-store"
    },
    "swift": {
        "type": "object-store",
        "desc": "Swift Object Storage Service"
    },
    "quantum": {
        "type": "network",
        "desc": "Quantum Networking Service"
    },
    "neutron": {
        "type": "network",
        "desc": "Neutron Networking Service"
    },
    "oxygen": {
        "type": "oxygen",
        "desc": "Oxygen Cloud Image Service"
    },
    "ceilometer": {
        "type": "metering",
        "desc": "Ceilometer Metering Service"
    },
    "heat": {
        "type": "orchestration",
        "desc": "Heat Orchestration API"
    },
    "heat-cfn": {
        "type": "cloudformation",
        "desc": "Heat CloudFormation API"
    },
    "image-stream": {
        "type": "product-streams",
        "desc": "Ubuntu Product Streams"
    },
    "midonet": {
        "type": "network-overlay",
        "desc": "MidoNet low-level API"
    },
    "cloudkitty": {
        "type": "rating",
        "desc": "CloudKitty Rating API"
    },
    "ironic": {
        "type": "baremetal",
        "desc": "Ironic bare metal provisioning service"
    },
    "designate": {
        "type": "dns",
        "desc": "Designate DNS service"
    },
    "astara": {
        "type": "astara",
        "desc": "Astara Network Orchestration Service",
    },
    "aodh": {
        "type": "alarming",
        "desc": "Aodh Alarming Service",
    },
    "gnocchi": {
        "type": "metric",
        "desc": "Gnocchi Metric Service",
    },
    "panko": {
        "type": "event",
        "desc": "Panko Event Service",
    },
    "barbican": {
        "type": "key-manager",
        "desc": "Barbican secrets management service"
    },
    "congress": {
        "type": "policy",
        "desc": "Congress policy management service"
    },
    "trove": {
        "type": "database",
        "desc": "Database as a service"
    },
    "magnum": {
        "type": "container-infra",
        "desc": "OpenStack Container Infrastructure Management Service",
    },
    "manila": {
        "type": "share",
        "desc": "Shared Filesystem service"
    },
    "manilav2": {
        "type": "sharev2",
        "desc": "Shared Filesystem service v2"
    },
    "murano": {
        "type": "application-catalog",
        "desc": "Application Catalog for OpenStack"
    },
    "mistral": {
        "type": "workflowv2",
        "desc": "Workflow Service for OpenStack"
    },
    "zaqar": {
        "type": "messaging",
        "desc": "Messaging Service for OpenStack"
    },
    "placement": {
        "type": "placement",
        "desc": "Nova Placement Service"
    },
    "octavia": {
        "type": "load-balancer",
        "desc": "Octavia Load Balancer as a Service for OpenStack",
    },
    "masakari": {
        "type": "instance-ha",
        "desc": "Masakari instance HA for Openstack"
    },
    "watcher": {
        "type": "infra-optim",
        "desc": "Infrastructure Optimization Service for Openstack"
    },
    "workloadmgr": {
        "type": "workloads",
        "desc": "TrilioVault Workload Manager Service",
    },
    "keystone": {
        "type": "identity",
        "desc": "Keystone Identity Service",
    },
}

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
    'database': ['shared-db'],
}


def filter_null(settings, null='__null__'):
    """Replace null values with None in provided settings dict.

    When storing values in the peer relation, it might be necessary at some
    future point to flush these values. We therefore need to use a real
    (non-None or empty string) value to represent an unset settings. This value
    then needs to be converted to None when applying to a non-cluster relation
    so that the value is actually unset.
    """
    filtered = {}
    for k, v in settings.items():
        if v == null:
            filtered[k] = None
        else:
            filtered[k] = v

    return filtered


def resource_map():
    """Dynamically generate a map of resources that will be managed for a
    single hook execution.
    """
    resource_map = deepcopy(BASE_RESOURCE_MAP)

    release = os_release('keystone')
    if CompareOpenStackReleases(release) < 'liberty':
        resource_map.pop(POLICY_JSON)
    if os.path.exists('/etc/apache2/conf-available'):
        resource_map.pop(APACHE_CONF)
    else:
        resource_map.pop(APACHE_24_CONF)

    if snap_install_requested():
        if APACHE_CONF in resource_map:
            resource_map.pop(APACHE_CONF)
        if APACHE_24_CONF in resource_map:
            resource_map.pop(APACHE_24_CONF)
    else:
        if KEYSTONE_NGINX_CONF in resource_map:
            resource_map.pop(KEYSTONE_NGINX_CONF)
        if KEYSTONE_NGINX_SITE_CONF in resource_map:
            resource_map.pop(KEYSTONE_NGINX_SITE_CONF)

    if snap_install_requested():
        for cfile in resource_map:
            svcs = resource_map[cfile]['services']
            if 'apache2' in svcs:
                svcs.remove('apache2')
            if 'keystone' in svcs:
                svcs.remove('keystone')
            svcs.append('snap.keystone.nginx')
            svcs.append('snap.keystone.uwsgi')

    if run_in_apache():
        if not snap_install_requested():
            for cfile in resource_map:
                svcs = resource_map[cfile]['services']
                if 'keystone' in svcs:
                    svcs.remove('keystone')
                if 'apache2' not in svcs:
                    svcs.append('apache2')
            resource_map[WSGI_KEYSTONE_API_CONF] = {
                'contexts': [
                    context.WSGIWorkerConfigContext(
                        name="keystone",
                        admin_script='/usr/bin/keystone-wsgi-admin',
                        public_script='/usr/bin/keystone-wsgi-public'),
                    keystone_context.KeystoneContext()],
                'services': ['apache2']
            }

    if enable_memcache(release=release):
        resource_map[MEMCACHED_CONF] = {
            'contexts': [context.MemcacheContext()],
            'services': ['memcached']}

    return resource_map


def restart_pid_check(service_name, ptable_string=None):
    """Stop a service, check the processes are gone, start service
    @param service_name: service name as init system knows it
    @param ptable_string: string to look for in process table to match service
    """

    @retry_on_exception(5, base_delay=3, exc_type=AssertionError)
    def check_pids_gone(svc_string):
        log("Checking no pids for {} exist".format(svc_string), level=INFO)
        assert(subprocess.call(["pgrep", svc_string, "--nslist", "pid",
                               "--ns", str(os.getpid())]) == 1)

    if not ptable_string:
        ptable_string = service_name
    service_stop(service_name)
    check_pids_gone(ptable_string)
    service_start(service_name)


def restart_function_map():
    """Return a dict of services with any custom functions that should be
       used to restart that service

    :returns: dict of {'svc1': restart_func, 'svc2', other_func, ...}
    :rtype: Dict[str, Callable]
    """
    rfunc_map = {}
    rfunc_map[keystone_service()] = restart_keystone
    return rfunc_map


def restart_keystone(*args):
    """Restart the keystone process.

    This will either keystone or apache2 depending on OpenStack version.
    Also stop the ManagerServer (and thus manager.py script) which will
    reconnect to keystone on next usage of the ManagerServer.

    Note, as restart_keystone is used in the restart_functions map, when it is
    called it is passed the service name.  However, this function determines
    the actual service name to call, so that is discarded, hence the *args in
    the function signature.
    """
    if not is_unit_paused_set():
        if snap_install_requested():
            service_restart('snap.keystone.*')
        else:
            if run_in_apache():
                restart_pid_check(keystone_service())
            else:
                service_restart(keystone_service())
        stop_manager_instance()


def run_in_apache(release=None):
    """Return true if keystone API is run under apache2 with mod_wsgi in
    this release.
    """
    release = release or os_release('keystone')
    return (CompareOpenStackReleases(release) >= 'liberty' and
            not snap_install_requested())


def disable_unused_apache_sites():
    """Ensure that unused apache configurations are disabled to prevent them
    from conflicting with the charm-provided version.
    """
    for apache_site_file in UNUSED_APACHE_SITE_FILES:
        apache_site = apache_site_file.split('/')[-1].split('.')[0]
        if os.path.exists(apache_site_file):
            try:
                # Try it cleanly
                log('Disabling unused apache configs')
                status_set('maintenance', 'Disabling unused apache configs')
                subprocess.check_call(['a2dissite', apache_site])
            except subprocess.CalledProcessError:
                # Remove the file
                os.remove(apache_site_file)


def register_configs():
    release = os_release('keystone')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().items():
        configs.register(cfg, rscs['contexts'])
    return configs


def restart_map():
    restart_map = OrderedDict([(cfg, v['services'])
                               for cfg, v in resource_map().items()
                               if v['services']])
    if os.path.isdir(APACHE_SSL_DIR):
        restart_map['{}/*'.format(APACHE_SSL_DIR)] = ['apache2']
    return restart_map


def services():
    """Returns a list of (unique) services associated with this charm"""
    return list(set(chain(*restart_map().values())))


def determine_ports():
    """Assemble a list of API ports for services we are managing"""
    ports = [config('admin-port'), config('service-port')]
    return sorted(list(set(ports)))


def api_port(service):
    return {
        'keystone-admin': config('admin-port'),
        'keystone-public': config('service-port')
    }[service]


def determine_packages():
    release = os_release('keystone')
    cmp_release = CompareOpenStackReleases(release)

    # currently all packages match service names
    if snap_install_requested():
        pkgs = deepcopy(BASE_PACKAGES_SNAP)
        if enable_memcache(release=release):
            pkgs = pkgs + ['memcached']
        pkgs = set(pkgs).union(get_subordinate_release_packages(
            release, package_type='snap').install)
        return sorted(pkgs)
    else:
        packages = set(services()).union(BASE_PACKAGES)
        if cmp_release >= 'rocky':
            packages = [p for p in packages if not p.startswith('python-')]
            packages.extend(PY3_PACKAGES)
        elif run_in_apache():
            packages.add('libapache2-mod-wsgi')
        packages = set(packages).union(get_subordinate_release_packages(
            release).install)
        return sorted(packages)


def determine_purge_packages():
    '''
    Determine list of packages that where previously installed which are no
    longer needed.

    :returns: list of package names
    '''
    release = os_release('keystone')
    cmp_release = CompareOpenStackReleases(release)
    pkgs = []
    if cmp_release >= 'rocky':
        pkgs = [p for p in BASE_PACKAGES if p.startswith('python-')]
        pkgs.extend(['python-keystone', 'python-memcache'])
    pkgs = set(pkgs).union(
        get_subordinate_release_packages(
            release).purge)
    return sorted(pkgs)


def remove_old_packages():
    '''Purge any packages that need to be removed.

    :returns: bool Whether packages were removed.
    '''
    installed_packages = filter_missing_packages(determine_purge_packages())
    if installed_packages:
        log('Removing apt packages')
        status_set('maintenance', 'Removing apt packages')
        apt_purge(installed_packages, fatal=True)
        apt_autoremove(purge=True, fatal=True)
    return bool(installed_packages)


def save_script_rc():
    env_vars = {'OPENSTACK_SERVICE_KEYSTONE': 'keystone',
                'OPENSTACK_PORT_ADMIN': determine_api_port(
                    api_port('keystone-admin'), singlenode_mode=True),
                'OPENSTACK_PORT_PUBLIC': determine_api_port(
                    api_port('keystone-public'),
                    singlenode_mode=True)}
    _save_script_rc(**env_vars)


def do_openstack_upgrade_reexec(configs):
    do_openstack_upgrade(configs)
    log("Re-execing hook to pickup upgraded packages", level=INFO)
    os.execl('/usr/bin/env', 'python3', './hooks/config-changed-postupgrade')


def do_openstack_upgrade(configs):
    new_src = config('openstack-origin')
    new_os_rel = get_os_codename_install_source(new_src)
    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    if not snap_install_requested():
        configure_installation_source(new_src)
        apt_update()
        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
        reset_os_release()
        apt_install(packages=determine_packages(),
                    options=dpkg_opts, fatal=True)

        remove_old_packages()
    else:
        # TODO: Add support for upgrade from deb->snap
        # NOTE(thedac): Setting devmode until LP#1719636 is fixed
        install_os_snaps(
            get_snaps_install_info_from_origin(
                ['keystone'],
                new_src,
                mode='devmode'),
            refresh=True)
        post_snap_install()
        reset_os_release()

    # set CONFIGS to load templates from new release and regenerate config
    configs.set_release(openstack_release=new_os_rel)
    configs.write_all()

    if run_in_apache():
        disable_unused_apache_sites()

    if is_elected_leader(CLUSTER_RES):
        if is_db_ready():
            migrate_database()
            # After an OpenStack upgrade we re-run bootstrap to make sure role
            # assignments are up to date.  One example is the system role
            # assignment support that first appeared at Queens.
            bootstrap_keystone(configs=configs)
        else:
            log("Database not ready - deferring to shared-db relation",
                level=INFO)


def is_db_initialised():
    if leader_get('db-initialised'):
        log("Database is initialised", level=DEBUG)
        return True

    log("Database is NOT initialised", level=DEBUG)
    return False


def keystone_service():
    return {True: 'apache2', False: 'keystone'}[run_in_apache()]


# NOTE(jamespage): Retry deals with sync issues during one-shot HA deploys.
#                  mysql might be restarting or suchlike.
@retry_on_exception(5, base_delay=3, exc_type=subprocess.CalledProcessError)
def migrate_database():
    """Runs keystone-manage to initialize a new database or migrate existing"""
    log('Migrating the keystone database.', level=INFO)
    status_set('maintenance', 'Migrating the keystone database')
    if snap_install_requested():
        service_stop('snap.keystone.*')
    else:
        service_stop(keystone_service())
    # NOTE(jamespage) > icehouse creates a log file as root so use
    # sudo to execute as keystone otherwise keystone won't start
    # afterwards.

    # NOTE(coreycb): Can just use keystone-manage when snap has alias support.
    # Also can run as keystone once snap has drop privs support.
    if snap_install_requested():
        cmd = ['/snap/bin/keystone-manage', 'db_sync']
    else:
        cmd = ['sudo', '-u', 'keystone', 'keystone-manage', 'db_sync']
    subprocess.check_output(cmd)
    if snap_install_requested():
        service_start('snap.keystone.nginx')
        service_start('snap.keystone.uwsgi')
    else:
        service_start(keystone_service())
    time.sleep(10)
    leader_set({'db-initialised': True})
    stop_manager_instance()


def is_bootstrapped():
    """Determines whether Keystone has been bootstrapped.

    :returns: True when Keystone bootstrap has been run, False otherwise.
    :rtype: bool
    """
    return (
        leader_get('keystone-bootstrapped') is True and
        leader_get('{}_passwd'.format(CHARM_USER)) is not None
    )


def bootstrap_keystone(configs=None):
    """Runs ``keystone-manage bootstrap`` to bootstrap keystone.

    The bootstrap command is designed to be idempotent when it needs to be,
    i.e. if nothing has changed it will do nothing.  It is also safe to run
    the bootstrap command on a already deployed Keystone.

    The bootstrap command creates resources in the ``default`` domain.  It
    assigns a system-scoped role to the created user and as such the charm can
    use it to manage any domains resources.

    For successful operation of the ``keystoneclient`` used by the charm, we
    must create initial endpoints at bootstrap time.  For HA deployments these
    will be replaced as soon as HA configuration is complete.

    :param configs: Registered configs
    :type configs: Optional[Dict]
    """
    log('Bootstrapping keystone.', level=INFO)
    status_set('maintenance', 'Bootstrapping keystone')
    # NOTE: The bootstrap process is necessary for the charm to be able to
    # talk to Keystone.  We will still rely on ``ensure_initial_admin`` to
    # maintain Keystone's endpoints and the rest of the CRUD.

    if not os.path.exists(FERNET_KEY_REPOSITORY):
        mkdir(FERNET_KEY_REPOSITORY,
              owner=KEYSTONE_USER,
              group=KEYSTONE_USER,
              perms=0o700)

    api_suffix = get_api_suffix()
    charm_password = leader_get('{}_passwd'.format(CHARM_USER)) or pwgen(64)
    subprocess.check_call((
        'keystone-manage', 'bootstrap',
        '--bootstrap-username', CHARM_USER,
        '--bootstrap-password', charm_password,
        '--bootstrap-project-name', ADMIN_PROJECT,
        '--bootstrap-role-name', config('admin-role'),
        '--bootstrap-service-name', 'keystone',
        '--bootstrap-admin-url', endpoint_url(
            resolve_address(ADMIN),
            config('admin-port'),
            api_suffix),
        '--bootstrap-public-url', endpoint_url(
            resolve_address(PUBLIC),
            config('service-port'),
            api_suffix),
        '--bootstrap-internal-url', endpoint_url(
            resolve_address(INTERNAL),
            config('service-port'),
            api_suffix),
        '--bootstrap-region-id', config('region').split()[0]),
    )
    # TODO: we should consider to add --immutable-roles for supported releases
    # and/or make it configurable.  Saving for a future change as this one is
    # big enough as-is.
    leader_set({
        'keystone-bootstrapped': True,
        '{}_passwd'.format(CHARM_USER): charm_password,
    })

    cmp_release = CompareOpenStackReleases(os_release('keystone'))
    if configs and cmp_release < 'queens':
        # For Mitaka through Pike we need to work around the lack of support
        # for system scope by having a special bootstrap version of the
        # policy.json that ensures the charm has access to retrieve the user ID
        # created for the charm in the bootstrap process.
        #
        # As soon as the user ID is retrieved it will be stored in leader
        # storage which will be picked up by a context and subsequently written
        # to the runtime policy.json.
        #
        # NOTE: Remove this and the associated policy change as soon as
        # support for Mitaka -> Pike is removed.
        manager = get_manager()
        transitional_charm_user_id = manager.resolve_user_id(
            CHARM_USER, user_domain='default')
        leader_set({
            'transitional_charm_user_id': transitional_charm_user_id,
        })
        configs.write_all()

# OLD


def get_api_suffix():
    return 'v2.0' if get_api_version() == 2 else 'v3'


def get_local_endpoint(api_suffix=None):
    """Returns the URL for the local end-point bypassing haproxy/ssl"""
    if not api_suffix:
        api_suffix = get_api_suffix()

    keystone_port = determine_api_port(api_port('keystone-admin'),
                                       singlenode_mode=True)

    if config('prefer-ipv6'):
        ipv6_addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        local_endpoint = 'http://[{}]:{}/{}/'.format(
            ipv6_addr,
            keystone_port,
            api_suffix)
    else:
        local_endpoint = 'http://localhost:{}/{}/'.format(
            keystone_port,
            api_suffix)

    return local_endpoint


def get_charm_credentials():
    """Retrieve credentials for use by charm when managing identity CRUD.

    The bootstrap process creates a user for the charm in the default domain
    and assigns a system level role.  Subsequently the charm authenticates with
    a system-scoped token so it can manage all domain's resources.

    :returns: CharmCredentials with username, password and defaults for scoping
    :rtype: collections.namedtuple[str,str,str,str,str,str]
    :raises: RuntimeError
    """
    charm_password = leader_get('{}_passwd'.format(CHARM_USER))
    if charm_password is None:
        raise RuntimeError('Leader unit has not provided credentials required '
                           'for speaking with Keystone yet.')

    return keystone_types.CharmCredentials(
        CHARM_USER,
        charm_password,
        'all',
        ADMIN_PROJECT,  # For V2 and pre system scope compatibility
        'default',      # For Mitaka -> Pike (pre system scope)
        'default',      # For Mitaka -> Pike (pre system scope)
    )


def is_service_present(service_name, service_type):
    manager = get_manager()
    service_id = manager.resolve_service_id(service_name, service_type)
    return service_id is not None


def delete_service_entry(service_name, service_type):
    """ Delete a service from keystone"""
    manager = get_manager()
    service_id = manager.resolve_service_id(service_name, service_type)
    if service_id:
        manager.delete_service_by_id(service_id)
        log("Deleted service entry '{}'".format(service_name), level=DEBUG)


def create_service_entry(service_name, service_type, service_desc, owner=None,
                         list_services=None):
    """ Add a new service entry to keystone if one does not already exist """
    manager = get_manager()
    if list_services is None:
        list_services = manager.list_services()
    for service in list_services:
        if service['name'] == service_name:
            log("Service entry for '{}' already exists.".format(service_name),
                level=DEBUG)
            return

    manager.create_service(service_name, service_type,
                           description=service_desc)

    log("Created new service entry '{}'".format(service_name), level=DEBUG)


def create_endpoint_template(region, service, publicurl, adminurl,
                             internalurl, list_endpoints=None):
    manager = get_manager()
    # this needs to be a round-trip to the manager.py script to discover what
    # the "current" api_version might be, as it can't just be asserted.
    if manager.resolved_api_version() == 2:
        create_endpoint_template_v2(manager, region, service, publicurl,
                                    adminurl, internalurl,
                                    list_endpoints=list_endpoints)
    else:
        create_endpoint_template_v3(manager, region, service, publicurl,
                                    adminurl, internalurl,
                                    list_endpoints=list_endpoints)


def create_endpoint_template_v2(manager, region, service, publicurl, adminurl,
                                internalurl, list_endpoints=None):
    """ Create a new endpoint template for service if one does not already
        exist matching name *and* region """
    service_id = manager.resolve_service_id(service)
    if list_endpoints is None:
        list_endpoints = manager.list_endpoints()
    for ep in list_endpoints:
        if ep['service_id'] == service_id and ep['region'] == region:
            log("Endpoint template already exists for '%s' in '%s'"
                % (service, region))

            up_to_date = True
            for k in ['publicurl', 'adminurl', 'internalurl']:
                if ep.get(k) != locals()[k]:
                    up_to_date = False

            if up_to_date:
                return
            else:
                # delete endpoint and recreate if endpoint urls need updating.
                log("Updating endpoint template with new endpoint urls.")
                # NOTE: When using the 2.0 API and not using the admin_token
                # the call to delete_endpoint_by_id returns 404.
                # Deleting service works and will cascade delete endpoint.
                svc = manager.get_service_by_id(service_id)
                manager.delete_service_by_id(service_id)
                # NOTE: We do not get the service description in API v2.0
                create_service_entry(svc['name'], svc['type'], '')
                service_id = manager.resolve_service_id(service)

    manager.create_endpoints(region=region,
                             service_id=service_id,
                             publicurl=publicurl,
                             adminurl=adminurl,
                             internalurl=internalurl)
    log("Created new endpoint template for '{}' in '{}'"
        .format(region, service), level=DEBUG)


def create_endpoint_template_v3(manager, region, service, publicurl, adminurl,
                                internalurl, list_endpoints=None):
    service_id = manager.resolve_service_id(service)
    endpoints = {
        'public': publicurl,
        'admin': adminurl,
        'internal': internalurl,
    }
    if list_endpoints is None:
        list_endpoints = manager.list_endpoints()
    # Optimisation: we want to check the list of endpoints with the details and
    # ONLY create an endpoint if it doesn't exist and only update an existing
    # one if the details don't match.  `list_endpoints` is a list of
    # dictionaries of the associated from manager.list_endpoints() as
    # serialised by to_dict()
    # NOTE: ep_type is 'interface' in python_keystoneclient 'speak'.
    for ep_type in endpoints.keys():
        # see if the endpoint exists, but the URL doesn't match
        for ep in list_endpoints:
            if (ep['interface'] == ep_type and
                    ep['service_id'] == service_id and ep['region'] == region):
                # if the url doesn't match then it needs to be modified
                if ep.get('url', None) != endpoints[ep_type]:
                    manager.update_endpoint(ep['id'], url=endpoints[ep_type])
                break
        else:
            # Not found so create the endpoint
            manager.create_endpoint_by_type(
                region=region,
                service_id=service_id,
                interface=ep_type,
                endpoint=endpoints[ep_type],
            )


def create_tenant(name, domain):
    """Creates a tenant if it does not already exist"""
    manager = get_manager()
    tenant = manager.resolve_tenant_id(name, domain=domain)
    if not tenant:
        manager.create_tenant(tenant_name=name,
                              domain=domain,
                              description='Created by Juju')
        log("Created new tenant '{}' in domain '{}'".format(name, domain),
            level=DEBUG)
        return

    log("Tenant '{}' already exists.".format(name), level=DEBUG)


def create_or_show_domain(name):
    """Creates a domain if it does not already exist"""
    manager = get_manager()
    domain_id = manager.resolve_domain_id(name)
    if domain_id:
        log("Domain '{}' already exists.".format(name), level=DEBUG)
    else:
        manager.create_domain(domain_name=name,
                              description='Created by Juju')
        log("Created new domain: {}".format(name), level=DEBUG)
        domain_id = manager.resolve_domain_id(name)
    return domain_id


def user_exists(name, domain=None):
    manager = get_manager()
    return manager.user_exists(name, domain=domain)


def create_user(name, password, tenant=None, domain=None):
    """Creates a user if it doesn't already exist, as a member of tenant"""
    manager = get_manager()
    if user_exists(name, domain=domain):
        log("A user named '{}' already exists in domain '{}'"
            .format(name, domain), level=DEBUG)
        return

    tenant_id = None
    if tenant:
        tenant_id = manager.resolve_tenant_id(tenant, domain=domain)
        if not tenant_id:
            error_out("Could not resolve tenant_id for tenant '{}' in domain "
                      "'{}'".format(tenant, domain))

    domain_id = None
    if domain:
        domain_id = manager.resolve_domain_id(domain)
        if not domain_id:
            error_out('Could not resolve domain_id for domain {} when creating'
                      ' user {}'.format(domain, name))

    manager.create_user(name=name,
                        password=password,
                        email='juju@localhost',
                        tenant_id=tenant_id,
                        domain_id=domain_id)
    log("Created new user '{}' tenant: '{}' domain: '{}'"
        .format(name, tenant_id, domain_id), level=DEBUG)


def get_user_dict(user, **kwargs):
    """Delegate update_user call to the manager

    :param user: the user to fetch
    :type user: str
    :returns: a dictionary of the user keys:values
    :rtype: Optional[Dict[str, ANY]]
    """
    manager = get_manager()
    return manager.get_user_details_dict(user, **kwargs)


def update_user(user, **kwargs):
    """Delegate update_user call to the manager

    :param user: the user to modify
    :type user: str
    :returns: a dictionary of the user keys:values after the update
    :rtype: Dict[str, ANY]
    """
    manager = get_manager()
    return manager.update_user(user, **kwargs)


def list_users_for_domain(domain=None, domain_id=None):
    """Delegate list_users_for_domain to the manager

    :param domain: The domain name.
    :type domain: Optional[str]
    :param domain_id: The domain_id string
    :type domain_id: Optional[str]
    :returns: a list of user dictionaries in the domain
    :rtype: List[Dict[str, ANY]]
    """
    manager = get_manager()
    return manager.list_users_for_domain(domain, domain_id)


def get_manager(api_version=None):
    return KeystoneManagerProxy(api_version=api_version)


class KeystoneManagerProxy(object):

    def __init__(self, api_version=None, path=None):
        self._path = path or []
        self.api_version = api_version

    def __getattribute__(self, attr):
        if attr in ['__class__', '_path', 'api_version']:
            return super().__getattribute__(attr)
        return self.__class__(api_version=self.api_version,
                              path=self._path + [attr])

    def __call__(self, *args, **kwargs):
        # Following line retained commented-out for future debugging
        # print("Called: {} ({}, {})".format(self._path, args, kwargs))
        return _proxy_manager_call(self._path, self.api_version, args, kwargs)


JSON_ENCODE_OPTIONS = dict(
    sort_keys=True,
    allow_nan=False,
    indent=None,
    separators=(',', ':'),
)


class RetryProxyManagerCall(Exception):
    pass


@retry_on_exception(5, base_delay=3, exc_type=RetryProxyManagerCall)
def _proxy_manager_call(path, api_version, args, kwargs):
    package = dict(path=path,
                   api_version=api_version,
                   api_local_endpoint=get_local_endpoint(),
                   charm_credentials=get_charm_credentials(),
                   args=args,
                   kwargs=kwargs)
    serialized = json.dumps(package, **JSON_ENCODE_OPTIONS)
    server = _get_server_instance()
    try:
        server.send(serialized)
        # wait for the reply
        result_str = server.receive()
        result = json.loads(result_str)
        if 'error' in result:
            s = ("The call within manager.py failed with the error: '{}'. "
                 "The call was: path={}, args={}, kwargs={}, api_version={}"
                 .format(result['error'], path, args, kwargs, api_version))
            log(s, level=ERROR)
            if result.get('retry'):
                stop_manager_instance()
                raise RetryProxyManagerCall()
            raise RuntimeError(s)
        return json.loads(result_str)['result']
    except RetryProxyManagerCall:
        # cause a retry
        raise
    except RuntimeError as e:
        raise e
    except Exception as e:
        s = ("Decoding the result from the call to manager.py resulted in "
             "error '{}' (command: path={}, args={}, kwargs={}"
             .format(str(e), path, args, kwargs))
        log(s, level=ERROR)
        raise RuntimeError(s)


# singleton to ensure that there's only one manager instance.
_the_manager_instance = None


def _get_server_instance():
    """Get a SockServer instance and run up the manager to connect to it.
    Ensure that the manager.py is running and is ready to receive messages (i.e
    do the handshake.  Check that it is still running, and if not, start it
    again.  In that instance, restart the SockServer
    """
    global _the_manager_instance
    if _the_manager_instance is None:
        _the_manager_instance = ManagerServer()
    return _the_manager_instance.server


def stop_manager_instance():
    """If a ManagerServer instance exists, then try to kill it, clean-up the
    environment and reset the global singleton for it.
    """
    global _the_manager_instance
    if _the_manager_instance is not None:
        _the_manager_instance.clean_up()
    _the_manager_instance = None


# If a ManagerServer is still running at the end of the charm hook execution
# then kill it off:
atexit(stop_manager_instance)


class ManagerServer():
    """This is a singleton server that launches and kills the manager.py script
    that is used to allow 'calling' into Keystone when it is in a completely
    different process.

    The server() method also ensures that the manager.py script is still
    running, and if not, relaunches it.  This is to try to make the using the
    manager.py methods as transparent, and speedy, as possible.
    """

    def __init__(self):
        self.pvar = None
        self._server = None
        self.socket_file = os.path.join(tempfile.gettempdir(), "keystone-uds")

    @property
    def server(self):
        self._ensure_running()
        return self._server

    def _ensure_running(self):
        if self.pvar is None or self.pvar.poll() is not None:
            if self._server is not None:
                self._server.close()
            self._server = uds.UDSServer(self.socket_file)
            self._launch_manager()
            self._server.wait_for_connection()

    def _launch_manager(self):
        script = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                              'manager.py'))
        release = CompareOpenStackReleases(os_release('keystone'))
        # need to set the environment variable PYTHONPATH to include the
        # payload's directory for the manager.py to find the various keystone
        # clients
        env = os.environ
        _python_path = determine_python_path()
        if _python_path:
            if _python_path not in os.environ.get('PYTHONPATH', ''):
                env['PYTHONPATH'] = ':'.join(
                    os.environ.get('PYTHONPATH', '').split(':') +
                    [_python_path])
        # also ensure that the python executable is available if snap
        # installed.
        if snap_install_requested():
            _bin_path = os.path.join(SNAP_BASE_DIR, 'usr/bin')
            if _bin_path not in os.environ.get('PATH', ''):
                env['PATH'] = ':'.join(
                    os.environ.get('PATH', '').split(':') +
                    [_bin_path])
        # ensure python interpreter matches python version of OpenStack
        if release >= 'rocky':
            python = 'python3'
        else:
            python = 'python2'
        # launch the process and return immediately
        self.pvar = subprocess.Popen([python, script, self.socket_file],
                                     env=env, close_fds=True)

    def clean_up(self):
        if self.pvar is not None and self.pvar.poll() is None:
            self._server.send("QUIT")
            try:
                self.pvar.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.pvar.kill()
            self.pvar = None
        if self._server is not None:
            self._server.close()
            self._server = None
        try:
            os.remove(self.socket_file)
        except OSError:
            pass


def create_role(name, user=None, tenant=None, domain=None):
    """Creates a role if it doesn't already exist. grants role to user"""
    manager = get_manager()
    if not manager.resolve_role_id(name):
        manager.create_role(name=name)
        log("Created new role '{}'".format(name), level=DEBUG)
    else:
        log("A role named '{}' already exists".format(name), level=DEBUG)

    if not user and not tenant:
        return

    # NOTE(adam_g): Keystone client requires id's for add_user_role, not names
    user_id = manager.resolve_user_id(user, user_domain=domain)
    role_id = manager.resolve_role_id(name)

    if None in [user_id, role_id]:
        error_out("Could not resolve [%s, %s] user_domain='%s'" %
                  (user_id, role_id, domain))

    # default to grant role to project
    grant_role(user, name, tenant=tenant, user_domain=domain,
               project_domain=domain)


def grant_role(user, role, tenant=None, domain=None, user_domain=None,
               project_domain=None):
    """Grant user and tenant a specific role"""
    manager = get_manager()
    if domain:
        log("Granting user '%s' role '%s' in domain '%s'" %
            (user, role, domain))
    else:
        log("Granting user '%s' role '%s' on tenant '%s' in domain '%s'" %
            (user, role, tenant, project_domain))

    user_id = manager.resolve_user_id(user, user_domain=user_domain)
    role_id = manager.resolve_role_id(role)
    if None in [user_id, role_id]:
        error_out("Could not resolve [%s, %s] user_domain='%s'" %
                  (user_id, role_id, user_domain))

    tenant_id = None
    if tenant:
        tenant_id = manager.resolve_tenant_id(tenant, domain=project_domain)
        if not tenant_id:
            error_out("Could not resolve tenant_id for tenant '{}' in domain "
                      "'{}'".format(tenant, domain))

    domain_id = None
    if domain:
        domain_id = manager.resolve_domain_id(domain)
        if not domain_id:
            error_out('Could not resolve domain_id for domain %s' % domain)

    cur_roles = manager.roles_for_user(user_id, tenant_id=tenant_id,
                                       domain_id=domain_id)
    if not cur_roles or role_id not in [r['id'] for r in cur_roles]:
        manager.add_user_role(user=user_id,
                              role=role_id,
                              tenant=tenant_id,
                              domain=domain_id)
        if domain_id is None:
            log("Granted user '%s' role '%s' on tenant '%s' in domain '%s'" %
                (user, role, tenant, project_domain), level=DEBUG)
        else:
            log("Granted user '%s' role '%s' in domain '%s'" %
                (user, role, domain), level=DEBUG)
    else:
        if domain_id is None:
            log("User '%s' already has role '%s' on tenant '%s' in domain '%s'"
                % (user, role, tenant, project_domain), level=DEBUG)
        else:
            log("User '%s' already has role '%s' in domain '%s'"
                % (user, role, domain), level=DEBUG)


def store_data(backing_file, data):
    with open(backing_file, 'w+') as fd:
        fd.writelines("{}\n".format(data))


def get_admin_passwd(user=None):
    passwd = config("admin-password")
    if passwd:
        passwd = passwd.strip()
        if passwd.lower() != "none":
            return passwd

    if user is None:
        user = config('admin-user')

    _migrate_admin_password()
    passwd = leader_get('{}_passwd'.format(user))

    if not passwd and is_leader():
        log("Generating new passwd for user: %s" % user)
        cmd = ['pwgen', '-c', '16', '1']
        passwd = str(subprocess.check_output(cmd).decode('UTF-8')).strip()

    return passwd


def set_admin_passwd(passwd, user=None):
    if user is None:
        user = config('admin-user')

    _leader_set_secret({'{}_passwd'.format(user): passwd})


def rotate_admin_passwd():
    if not is_leader():
        raise RuntimeError("This unit is not the leader and therefore can't "
                           "rotate the admin password.")
    admin_passwd = config('admin-password')
    if admin_passwd and admin_passwd.strip().lower() != 'none':
        raise RuntimeError(
            "The 'admin-password' config is present, so the action will be "
            "aborted. To allow randomly generated passwords, unset the "
            "config value.")
    user = config('admin-user')
    new_passwd = pwgen(16)
    update_user_password(user, new_passwd, ADMIN_DOMAIN)
    leader_set({'admin_passwd': new_passwd})


class NotLeaderError(Exception):
    """Raised if not the leader."""
    pass


class InvalidService(Exception):
    """Raised if not the leader."""
    pass


def get_service_usernames():
    """Return the known service usernames that can be password rotated.

    :returns: the list of known service usernames
    :rtype: List[str]
    """
    usernames = [k[:-len('_passwd')] for k in leader_get()
                 if k.endswith('_passwd') and k != 'admin_passwd']
    # now match against the service list.
    valid_service_names = valid_services.keys()
    known_service_usernames = []
    for username in usernames:
        # if a username has '_' in it, then it is a compound name.
        parts = username.split('_')
        if 'keystone' in parts:
            continue
        if not all(p in valid_service_names for p in parts):
            continue
        known_service_usernames.append(username)
    return known_service_usernames


def rotate_service_user_passwd(service):
    """Rotate the password for the specified service user.

    Note that the function checks that the charm is the leader.

    :param service: the service to rotate the password for.  This needs to be
        in the form that it is stored in leader settings.
    :type service: str
    :raises: RuntimeError if the unit is not the leader.
    :raises: ValueError if the service_user doesn't exist.
    :raises: RuntimeError if the password can't be changed.
    """
    if not is_leader():
        msg = (
            "This unit is not the leader and therefore can't rotate the "
            "password for user {}.".format(service))
        log(msg, level=ERROR)
        raise NotLeaderError(msg)
    # validate that the service is actually known about.
    known_usernames = get_service_usernames()
    if service not in known_usernames:
        msg = ("Invalid service requested: '{}' not one of {} services."
               .format(service, ', '.join(known_usernames)))
        log(msg, level=ERROR)
        raise InvalidService(msg)
    # Note that the service is already prefixed as that is how it is stored in
    # the leader-settings
    # check whether the service has been related/saved
    if not is_service_password_saved(service):
        msg = ("Service requested: '{}' is not known in this model."
               .format(service))
        log(msg, level=ERROR)
        raise InvalidService(msg)
    # Rotate the password - note that rotate_service_password is for leader
    # storage, and update_user_password uses the manager to get keystone to
    # update the password in MySQL
    passwd = rotate_service_password(service)
    update_user_password(service, passwd, SERVICE_DOMAIN)
    # Update just the password for the the relation data for the service.
    relation_data = {
        "service_password": passwd,
    }
    # workout what the relation id is?
    id_svc_rel_ids = relation_ids('identity-service')
    _relation_ids = []
    for rid in id_svc_rel_ids:
        rel_service_username = relation_get(unit=local_unit(),
                                            rid=rid,
                                            attribute='service_username')
        if rel_service_username == service:
            _relation_ids.append(rid)
    if not _relation_ids:
        msg = ("Service '{}' not found in relations, so not updating relation "
               "data." .format(service))
        log(msg, level=INFO)
        return
    for rid in _relation_ids:
        peer_store_and_set(relation_id=rid, **relation_data)
        relation_set(relation_id=rid, **relation_data)


def get_api_version():
    api_version = config('preferred-api-version')
    cmp_release = CompareOpenStackReleases(
        get_os_codename_install_source(config('openstack-origin'))
    )
    if not api_version:
        # NOTE(jamespage): Queens dropped support for v2, so default
        #                  to v3.
        if cmp_release >= 'queens':
            api_version = 3
        else:
            api_version = 2
    if ((cmp_release < 'queens' and api_version not in [2, 3]) or
            (cmp_release >= 'queens' and api_version != 3)):
        raise ValueError('Bad preferred-api-version')
    return api_version


def ensure_initial_admin(config):
    # Allow retry on fail since leader may not be ready yet.
    # NOTE(hopem): ks client may not be installed at module import time so we
    # use this wrapped approach instead.
    @retry_on_exception(3, base_delay=3, exc_type=RuntimeError)
    def _ensure_initial_admin(config):
        """Ensures the minimum admin stuff exists in whatever database we're
        using.

        This and the helper functions it calls are meant to be idempotent and
        run during install as well as during db-changed.  This will maintain
        the admin tenant, user, role, service entry and endpoint across every
        datastore we might use.

        TODO: Possibly migrate data from one backend to another after it
        changes?
        """
        if get_api_version() > 2:
            manager = get_manager()
            default_domain_id = create_or_show_domain(DEFAULT_DOMAIN)
            leader_set({'default_domain_id': default_domain_id})
            admin_domain_id = create_or_show_domain(ADMIN_DOMAIN)
            leader_set({'admin_domain_id': admin_domain_id})
            create_or_show_domain(SERVICE_DOMAIN)
            create_tenant("admin", ADMIN_DOMAIN)
            create_tenant(config("service-tenant"), SERVICE_DOMAIN)
            leader_set({'service_tenant_id': manager.resolve_tenant_id(
                config("service-tenant"),
                domain=SERVICE_DOMAIN)})
            create_role('service')
        create_tenant("admin", DEFAULT_DOMAIN)
        create_tenant(config("service-tenant"), DEFAULT_DOMAIN)
        # User is managed by ldap backend when using ldap identity
        if not (config('identity-backend') ==
                'ldap' and config('ldap-readonly')):

            admin_username = config('admin-user')

            # NOTE(lourot): get_admin_passwd() will generate a new password if
            # the juju config or the leader DB doesn't contain already one. The
            # set_admin_passwd() callback will then store that password in the
            # leader DB. So if the leader dies, the new leader will still have
            # access to the password.
            if get_api_version() > 2:
                passwd = create_user_credentials(admin_username,
                                                 get_admin_passwd,
                                                 set_admin_passwd,
                                                 domain=ADMIN_DOMAIN)
                if passwd:
                    create_role('Member')
                    # Grant 'Member' role to user ADMIN_DOMAIN/admin-user in
                    # project ADMIN_DOMAIN/'admin'
                    # ADMIN_DOMAIN
                    grant_role(admin_username, 'Member', tenant='admin',
                               user_domain=ADMIN_DOMAIN,
                               project_domain=ADMIN_DOMAIN)
                    create_role(config('admin-role'))
                    # Grant admin-role to user ADMIN_DOMAIN/admin-user in
                    # project ADMIN_DOMAIN/admin
                    grant_role(admin_username, config('admin-role'),
                               tenant='admin', user_domain=ADMIN_DOMAIN,
                               project_domain=ADMIN_DOMAIN)
                    # Grant domain level admin-role to ADMIN_DOMAIN/admin-user
                    grant_role(admin_username, config('admin-role'),
                               domain=ADMIN_DOMAIN, user_domain=ADMIN_DOMAIN)
            else:
                create_user_credentials(admin_username, get_admin_passwd,
                                        set_admin_passwd, tenant='admin',
                                        new_roles=[config('admin-role')])

        service_type = valid_services['keystone']['type']
        desc = valid_services['keystone']['desc']
        create_service_entry("keystone", service_type, desc)

        for region in config('region').split():
            create_keystone_endpoint(public_ip=resolve_address(PUBLIC),
                                     service_port=config("service-port"),
                                     internal_ip=resolve_address(INTERNAL),
                                     admin_ip=resolve_address(ADMIN),
                                     auth_port=config("admin-port"),
                                     region=region)

    return _ensure_initial_admin(config)


def endpoint_url(ip, port, suffix=None):
    proto = 'http'
    if https():
        proto = 'https'
    if is_ipv6(ip):
        ip = "[{}]".format(ip)
    if suffix:
        ep = "{}://{}:{}/{}".format(proto, ip, port, suffix)
    else:
        ep = "{}://{}:{}".format(proto, ip, port)
    return ep


def create_keystone_endpoint(public_ip, service_port,
                             internal_ip, admin_ip, auth_port, region):
    api_suffix = get_api_suffix()
    create_endpoint_template(
        region, "keystone",
        endpoint_url(public_ip, service_port, suffix=api_suffix),
        endpoint_url(admin_ip, auth_port, suffix=api_suffix),
        endpoint_url(internal_ip, service_port, suffix=api_suffix),
    )


def update_user_password(username, password, domain):
    manager = get_manager()
    log("Updating password for user '{}'".format(username))

    user_id = manager.resolve_user_id(username, user_domain=domain)
    if user_id is None:
        error_out("Could not resolve user id for '{}'".format(username))

    manager.update_password(user=user_id, password=password)
    log("Successfully updated password for user '{}'".format(username))


def load_stored_passwords(path=SERVICE_PASSWD_PATH):
    creds = {}
    if not os.path.isfile(path):
        return creds

    stored_passwd = open(path, 'r')
    for _line in stored_passwd.readlines():
        user, passwd = _line.strip().split(':')
        creds[user] = passwd
    return creds


def _migrate_admin_password():
    """Migrate on-disk admin passwords to leader storage"""
    if is_leader() and os.path.exists(STORED_PASSWD):
        log('Migrating on-disk stored passwords to leader storage')
        with open(STORED_PASSWD) as fd:
            _leader_set_secret({"admin_passwd": fd.readline().strip('\n')})

        os.unlink(STORED_PASSWD)


def _migrate_service_passwords():
    """Migrate on-disk service passwords to leader storage"""
    if is_leader() and os.path.exists(SERVICE_PASSWD_PATH):
        log('Migrating on-disk stored passwords to leader storage')
        creds = load_stored_passwords()
        _leader_set_secret({"{}_passwd".format(k): v
                            for k, v in creds.items()})
        os.unlink(SERVICE_PASSWD_PATH)


def get_service_password(service_username):
    _migrate_service_passwords()
    passwd = leader_get("{}_passwd".format(service_username))
    if passwd is None:
        passwd = pwgen(length=SERVICE_PASSWD_LENGTH)
    return passwd


def set_service_password(passwd, user):
    _leader_set_secret({"{}_passwd".format(user): passwd})


def rotate_service_password(service_username):
    """Create a new service password for a service user and save it.

    It is saved via `set_service_password`.

    :param service_username: The service username to set the password for.
    :type service_username: str
    :returns: the generated password.
    :rtype: str
    """
    passwd = pwgen(length=SERVICE_PASSWD_LENGTH)
    set_service_password(passwd, service_username)
    return passwd


def is_service_password_saved(service_username):
    """Return true if the service_username has been saved.

    :param service_username: The service username to check.
    :type service_username: str
    :returns: True if set
    :rtype: bool
    """
    passwd = leader_get("{}_passwd".format(service_username))
    return passwd is not None


def is_password_changed(username, passwd):
    _passwd = leader_get("{}_passwd".format(username))
    return (_passwd is None or passwd != _passwd)


def create_user_credentials(user, passwd_get_callback, passwd_set_callback,
                            tenant=None, new_roles=None,
                            grants=None, domain=None):
    """Create user credentials.

    Optionally adds role grants to user and/or creates new roles.
    """
    passwd = passwd_get_callback(user)
    if not passwd:
        log("Unable to retrieve password for user '{}'".format(user),
            level=INFO)
        return

    log("Creating service credentials for '{}'".format(user), level=DEBUG)
    if user_exists(user, domain=domain):
        log("User '{}' already exists".format(user), level=DEBUG)
        # NOTE(dosaboy): see LP #1648677
        if is_password_changed(user, passwd):
            update_user_password(user, passwd, domain)
    else:
        create_user(user, passwd, tenant=tenant, domain=domain)

    passwd_set_callback(passwd, user=user)

    if grants:
        for role in grants:
            # grant role on project
            grant_role(user, role, tenant=tenant, user_domain=domain,
                       project_domain=domain)
    else:
        log("No role grants requested for user '{}'".format(user), level=DEBUG)

    if new_roles:
        # Allow the remote service to request creation of any additional roles.
        # Currently used by Swift and Ceilometer.
        for role in new_roles:
            log("Creating requested role '{}'".format(role), level=DEBUG)
            create_role(role, user=user, tenant=tenant, domain=domain)

    return passwd


def create_service_credentials(user, new_roles=None):
    """Create credentials for service with given username.

    For Keystone v2.0 API compatibility services are given a user under
    config('service-tenant') in DEFAULT_DOMAIN and are given the
    config('admin-role') role. Tenant is assumed to already exist.

    For Keystone v3 API compatibility services are given a user in project
    config('service-tenant') in SERVICE_DOMAIN and are given the
    config('admin-role') role.

    Project is assumed to already exist.
    """
    tenant = config('service-tenant')
    if not tenant:
        raise Exception("No service tenant provided in config")

    if get_api_version() < 3:
        passwd = create_user_credentials(user, get_service_password,
                                         set_service_password,
                                         tenant=tenant, new_roles=new_roles,
                                         grants=[config('admin-role')],
                                         domain=None)
    else:
        # api version 3 or above
        create_user_credentials(user, get_service_password,
                                set_service_password,
                                tenant=tenant, new_roles=new_roles,
                                grants=[config('admin-role')],
                                domain=DEFAULT_DOMAIN)
        # Create account in SERVICE_DOMAIN as well using same password
        passwd = create_user_credentials(user, get_service_password,
                                         set_service_password,
                                         tenant=tenant, new_roles=new_roles,
                                         grants=[config('admin-role')],
                                         domain=SERVICE_DOMAIN)
        # Ensure the service have the service role set. In 2024.1 release
        # service such as neutron require the service role for certain
        # operations to function (e.g. update port binding profiles)
        create_role(SERVICE_ROLE, user=user, tenant=tenant,
                    domain=SERVICE_DOMAIN)
        # protect the user from pci_dss password shenanigans
        protect_user_account_from_pci_dss_force_change_password(user)
    return passwd


def protect_user_account_from_pci_dss_force_change_password(user_name):
    """Protect the user account against forcing a password change option

    The PCI-DSS inspired option `change_password_upon_first_use` causes the
    user to have to change their login password on first use.  Obviously, this
    is a disaster for service accounts.  This function sets the option
    `ignore_change_password_upon_first_use` on the specified user account so
    that service accounts do not get locked out of the cloud.
    It also sets the 'ignore_password_expiry' to ensure that passwords do not
    get expired.

    This is only applied in a keystone v3 environment, as the PCI-DSS options
    are only supported on keystone v3 onwards.

    :param user_name: the user to apply the protected option to.
    :type user_name: str
    """
    if get_api_version() < 3:
        return
    tenant = config('service-tenant')
    if not tenant:
        raise ValueError("No service tenant provided in config")
    for domain in (DEFAULT_DOMAIN, SERVICE_DOMAIN):
        user = get_user_dict(user_name, domain=domain)
        if user is None:
            log("User {} in domain {} doesn't exist.  Can't set "
                "'ignore_change_password_upon_first_use' option True for it."
                .format(user_name, domain))
            continue
        options = user.get('options', {})
        ignore_option = options.get('ignore_change_password_upon_first_use',
                                    False)
        ignore_password_option = options.get('ignore_password_expiry', False)
        if ignore_option is False or ignore_password_option is False:
            options['ignore_change_password_upon_first_use'] = True
            options['ignore_password_expiry'] = True
            log("Setting 'ignore_change_password_upon_first_use' and "
                "'ignore_password_expiry' to True for"
                "user {} in domain {}.".format(user_name, domain))
            update_user(user['id'], options=options)


def ensure_all_service_accounts_protected_for_pci_dss_options():
    """This function ensures that the 'ignore_change_password_upon_first_use'
    is set for all of the accounts in the SERVICE_DOMAIN, and then the
    DEFAULT_DOMAIN.
    """
    if get_api_version() < 3:
        return
    log("Ensuring all service users are protected from PCI-DSS options")
    # We want to make sure our own charm credentials are protected too, they
    # only exist in DEFAULT_DOMAIN, but the called function gracefully deals
    # with that.
    users = [{'name': CHARM_USER}]
    users += list_users_for_domain(domain=SERVICE_DOMAIN)
    for user in users:
        protect_user_account_from_pci_dss_force_change_password(user['name'])


def get_real_role_names(roles, manager):
    """Return the name names of the roles.

    Keystone attempts to be case insensitive but not all client code is so
    sometimes the case sensitive role name as it is stored in the DB is
    needed.

    :param roles: List of role names
    :type roles: List[str]
    :param manager: Manager for this keystone api
    :type manager: keystone_utils.KeystoneManagerProxy
    :returns: List of role names
    :rtype: List[str]
    """
    resolved_roles = []
    for role in roles:
        resolved_role = manager.resolve_role_name(role)
        if resolved_role:
            resolved_roles.append(resolved_role)
    return resolved_roles


def grant_admin_additional_relation_roles(manager, settings):
    """Add additional roles to admin if requested by a related charm.

    :param manager: Manager for this keystone api
    :type manager: keystone_utils.KeystoneManagerProxy
    :param settings: Relation data from related unit
    :type settings: Dict[str]
    """
    _additional_admin_roles = get_add_role_to_admin(settings)
    if not _additional_admin_roles:
        log("No requests to grant additional roles to admin", level=DEBUG)
        return
    log(
        "Processing request to grant role {} to admin".format(
            _additional_admin_roles),
        level=INFO)
    additional_admin_roles = get_real_role_names(
        _additional_admin_roles,
        manager)
    log(
        "Matches requested roles to {}".format(additional_admin_roles),
        level=DEBUG)
    for role in additional_admin_roles:
        grant_role(
            config('admin-user'),
            role,
            tenant='admin',
            user_domain=ADMIN_DOMAIN,
            project_domain=ADMIN_DOMAIN)


def add_service_to_keystone(relation_id=None, remote_unit=None):
    manager = get_manager()
    settings = relation_get(rid=relation_id, unit=remote_unit)
    requested_roles = get_requested_roles(settings)
    # the minimum settings needed per endpoint
    single = {'service', 'region', 'public_url', 'admin_url', 'internal_url'}
    https_cns = []

    protocol = get_protocol()

    if single.issubset(settings):
        # other end of relation advertised only one endpoint
        if 'None' in settings.values():
            # Some backend services advertise no endpoint but require a
            # hook execution to update auth strategy.
            relation_data = {}
            # Check if clustered and use vip + haproxy ports if so
            relation_data["auth_host"] = resolve_address(ADMIN)
            relation_data["service_host"] = resolve_address(PUBLIC)
            relation_data["internal_host"] = resolve_address(INTERNAL)

            relation_data["auth_protocol"] = protocol
            relation_data["service_protocol"] = protocol
            relation_data["internal_protocol"] = protocol

            relation_data["auth_port"] = config('admin-port')
            relation_data["service_port"] = config('service-port')
            # the internal URL is bound to the service-port when
            # bootstrapping keystone in the function bootstrap_keystone(), the
            # same config is handed over in the relation.
            relation_data["internal_port"] = config('service-port')

            relation_data["region"] = config('region')
            relation_data["api_version"] = get_api_version()
            relation_data["admin_domain_id"] = leader_get(
                attribute='admin_domain_id')

            if settings.get('service') is not None:
                svc_name = settings['service'].partition('_')[0]
                if svc_name in valid_services:
                    relation_data['service_type'] = \
                        valid_services[svc_name]['type']
                else:
                    log("service '{}' not found in valid_services "
                        "catalog so unable to set service_type on relation".
                        format(svc_name), level=WARNING)

            # Allow the remote service to request creation of any additional
            # roles. Currently used by Horizon
            for role in requested_roles:
                log("Creating requested role: {}".format(role))
                create_role(role)
            relation_data["created_roles"] = ','.join(get_real_role_names(
                requested_roles,
                manager))
            grant_admin_additional_relation_roles(manager, settings)

            peer_store_and_set(relation_id=relation_id, **relation_data)
            return
        else:
            ensure_valid_service(settings['service'])
            add_endpoint(region=settings['region'],
                         service=settings['service'],
                         publicurl=settings['public_url'],
                         adminurl=settings['admin_url'],
                         internalurl=settings['internal_url'])

            # If an admin username prefix is provided, ensure all services use
            # it.
            service_username = settings['service']
            prefix = config('service-admin-prefix')
            if prefix:
                service_username = "{}{}".format(prefix, service_username)

            # NOTE(jamespage) internal IP for backwards compat for SSL certs
            internal_cn = (urllib.parse
                           .urlparse(settings['internal_url']).hostname)
            https_cns.append(internal_cn)
            public_cn = urllib.parse.urlparse(settings['public_url']).hostname
            https_cns.append(public_cn)
            https_cns.append(
                urllib.parse.urlparse(settings['admin_url']).hostname)
    else:
        endpoints = assemble_endpoints(settings)
        _list_services_result = manager.list_services()
        _list_endpoints_result = manager.list_endpoints()

        services = []
        for ep in endpoints:
            # weed out any unrelated relation stuff Juju might have added
            # by ensuring each possible endpoint has appropriate fields
            #  ['service', 'region', 'public_url', 'admin_url', 'internal_url']
            if single.issubset(endpoints[ep]):
                ep = endpoints[ep]
                ensure_valid_service(ep['service'])
                add_endpoint(region=ep['region'], service=ep['service'],
                             publicurl=ep['public_url'],
                             adminurl=ep['admin_url'],
                             internalurl=ep['internal_url'],
                             list_services=_list_services_result,
                             list_endpoints=_list_endpoints_result)
                services.append(ep['service'])
                # NOTE(jamespage) internal IP for backwards compat for
                # SSL certs
                internal_cn = (urllib.parse
                               .urlparse(ep['internal_url']).hostname)
                https_cns.append(internal_cn)
                https_cns.append(
                    urllib.parse.urlparse(ep['public_url']).hostname)
                https_cns.append(
                    urllib.parse.urlparse(ep['admin_url']).hostname)

        service_username = '_'.join(sorted(services))

        # If an admin username prefix is provided, ensure all services use it.
        prefix = config('service-admin-prefix')
        if service_username and prefix:
            service_username = "{}{}".format(prefix, service_username)

    if 'None' in settings.values():
        return

    if not service_username:
        return

    roles = get_requested_roles(settings)
    service_password = create_service_credentials(service_username,
                                                  new_roles=roles)
    grant_admin_additional_relation_roles(manager, settings)
    service_domain = None
    service_domain_id = None
    if get_api_version() > 2:
        service_domain = SERVICE_DOMAIN
        service_domain_id = manager.resolve_domain_id(SERVICE_DOMAIN)

    service_user_id = manager.resolve_user_id(service_username,
                                              user_domain=service_domain)
    service_tenant = config('service-tenant')
    service_tenant_id = manager.resolve_tenant_id(service_tenant,
                                                  domain=service_domain)

    admin_project_id = None
    admin_user_id = None
    if get_api_version() > 2:
        # NOTE(jamespage):
        # Resolve cloud admin project and user ID's
        # which may be used for trusts in consuming
        # services - but don't pass the password
        admin_project_id = manager.resolve_tenant_id(ADMIN_PROJECT,
                                                     domain=ADMIN_DOMAIN)
        admin_user_id = manager.resolve_user_id(config('admin-user'),
                                                user_domain=ADMIN_DOMAIN)

    # NOTE(dosaboy): we use __null__ to represent settings that are to be
    # routed to relations via the cluster relation and set to None.
    relation_data = {
        "auth_host": resolve_address(ADMIN),
        "service_host": resolve_address(PUBLIC),
        "internal_host": resolve_address(INTERNAL),
        "service_port": config("service-port"),
        "internal_port": config("service-port"),
        "auth_port": config("admin-port"),
        "service_username": service_username,
        "service_user_id": service_user_id,
        "service_password": service_password,
        "service_domain": service_domain,
        "service_domain_id": service_domain_id,
        "service_tenant": service_tenant,
        "service_tenant_id": service_tenant_id,
        "https_keystone": '__null__',
        "ssl_cert": '__null__',
        "ssl_key": '__null__',
        "ca_cert": '__null__',
        "auth_protocol": protocol,
        "service_protocol": protocol,
        "internal_protocol": protocol,
        "api_version": get_api_version(),
        "admin_domain_id": leader_get(attribute='admin_domain_id'),
        "admin_project_id": admin_project_id,
        "admin_user_id": admin_user_id,
        "admin_role": config("admin-role"),
        "created_roles": ','.join(
            get_real_role_names(requested_roles, manager))
    }

    # get service key
    svckey = [k for k in settings if k.endswith('_service')] or ['service']
    if svckey[0] in settings:
        relation_data['service_type'] = \
            valid_services[settings[svckey[0]]]['type']

    peer_store_and_set(relation_id=relation_id, **relation_data)
    # NOTE(dosaboy): '__null__' settings are for peer relation only so that
    # settings can flushed so we filter them out for non-peer relation.
    filtered = filter_null(relation_data)
    relation_set(relation_id=relation_id, **filtered)


def add_credentials_to_keystone(relation_id=None, remote_unit=None):
    """Add authentication credentials without a service endpoint

    Creates credentials and then peer stores and relation sets them

    :param relation_id: Relation id of the relation
    :param remote_unit: Related unit on the relation
    """
    manager = get_manager()
    settings = relation_get(rid=relation_id, unit=remote_unit)

    credentials_username = settings.get('username')
    if not credentials_username:
        log("identity-credentials peer has not yet set username")
        return

    if get_api_version() == 2:
        domain = None
    else:
        domain = settings.get('domain') or SERVICE_DOMAIN

    # Use passed project or the service project
    credentials_project = settings.get('project') or config('service-tenant')
    create_tenant(credentials_project, domain)

    # Use passed grants or default grants
    credentials_grants = (get_requested_grants(settings) or
                          [config('admin-role')])

    # Create the user
    credentials_password = create_user_credentials(
        credentials_username,
        get_service_password,
        set_service_password,
        tenant=credentials_project,
        new_roles=get_requested_roles(settings),
        grants=credentials_grants,
        domain=domain)

    protocol = get_protocol()

    relation_data = {
        "auth_host": resolve_address(ADMIN),
        "credentials_host": resolve_address(PUBLIC),
        "credentials_port": config("service-port"),
        "auth_port": config("admin-port"),
        "credentials_username": credentials_username,
        "credentials_password": credentials_password,
        "credentials_project": credentials_project,
        "credentials_project_id":
            manager.resolve_tenant_id(credentials_project, domain=domain),
        "auth_protocol": protocol,
        "credentials_protocol": protocol,
        "api_version": get_api_version(),
        "region": config('region')
    }
    if domain:
        relation_data['domain'] = domain
        # The same domain is used for project and user creation. However, in
        # the future they may not be.
        domain_id = manager.resolve_domain_id(domain)
        relation_data['credentials_user_domain_name'] = domain
        relation_data['credentials_user_domain_id'] = domain_id
        relation_data['credentials_project_domain_name'] = domain
        relation_data['credentials_project_domain_id'] = domain_id

    peer_store_and_set(relation_id=relation_id, **relation_data)


def get_protocol():
    """Determine the HTTP protocol

    :returns: http or https
    """
    if https():
        protocol = 'https'
    else:
        protocol = 'http'
    return protocol


def ensure_valid_service(service):
    if service not in valid_services.keys():
        log("Invalid service requested: '{}'".format(service))
        relation_set(admin_token=-1)
        return


def add_endpoint(region, service, publicurl, adminurl, internalurl,
                 list_services=None,
                 list_endpoints=None):
    status_message = 'Updating endpoint for {}'.format(service)
    log(status_message)
    status_set('maintenance', status_message)
    desc = valid_services[service]["desc"]
    service_type = valid_services[service]["type"]
    create_service_entry(service, service_type, desc,
                         list_services=list_services)
    create_endpoint_template(region=region, service=service,
                             publicurl=publicurl,
                             adminurl=adminurl,
                             internalurl=internalurl,
                             list_endpoints=list_endpoints)


def get_add_role_to_admin(settings):
    """Extract from relation data roles to grant to admin.

    :param settings: Relation data from related unit
    :type settings: Dict[str]
    """
    if ('add_role_to_admin' in settings and
            settings['add_role_to_admin'] not in ['None', None]):
        return settings['add_role_to_admin'].split(',')
    else:
        return []


def get_requested_roles(settings):
    """Retrieve any valid requested_roles from dict settings"""
    if ('requested_roles' in settings and
            settings['requested_roles'] not in ['None', None]):
        return settings['requested_roles'].split(',')
    else:
        return []


def get_requested_grants(settings):
    """Retrieve any valid requested_grants from dict settings

    :param settings: dictionary which may contain key, requested_grants,
                     with comma delimited list of roles to grant.
    :returns: list of roles to grant
    """
    if ('requested_grants' in settings and
            settings['requested_grants'] not in ['None', None]):
        return settings['requested_grants'].split(',')
    else:
        return []


def setup_ipv6():
    """Check ipv6-mode validity and setup dependencies"""
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(ubuntu_rel) < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")

    # Need haproxy >= 1.5.3 for ipv6 so for Trusty if we are <= Kilo we need to
    # use trusty-backports otherwise we can use the UCA.
    if (ubuntu_rel == 'trusty' and
            CompareOpenStackReleases(os_release('keystone')) < 'liberty'):
        add_source('deb http://archive.ubuntu.com/ubuntu trusty-backports '
                   'main')
        apt_update()
        apt_install('haproxy/trusty-backports', fatal=True)


def service_endpoint_dict(service_name):
    """Retrieve endpoint information for a named service

    Build and return a dict of information for the provided service
    (by name) including internal, public and admin URL's if they
    are present in the endpoint catalog.

    :returns: dict of endpoint information or None if not found
    """
    manager = get_manager()
    service_id = manager.resolve_service_id(service_name)
    if not service_id:
        return None

    current_endpoints = manager.list_endpoints()
    endpoint_dict = {}
    for endpoint in current_endpoints:
        if endpoint['service_id'] == service_id:
            if 'interface' in endpoint:
                # NOTE: v3 API response - endpoint per interface
                endpoint_dict[endpoint['interface']] = endpoint['url']
            else:
                # NOTE: v2 API response - endpoint has all interfaces
                for interface in ('public', 'internal', 'admin'):
                    endpoint_url = endpoint.get('{}url'.format(interface))
                    if endpoint_url:
                        endpoint_dict[interface] = endpoint_url
    return endpoint_dict


def send_id_service_notifications(data):
    """Send notification on identity-service relation.

    Services can optionally request notifications of other services endpoint
    changes. They do this by sending a space separated list of service names
    that they wish to be notified of. e.g

        subscribe_ep_change="placement neutron"

    If the endpoints change for any service in the list then a notification is
    sent back with a nonce. e.g. if the neutron ep changes the charm will
    receive a JSON encoded dict of changes:
        'ep_changed': '{"neutron": "1c261658"}'

    :param data: Dict of key=value to use as trigger for notification.
    :type data: dict
    """
    id_svc_rel_ids = relation_ids('identity-service')
    for rid in id_svc_rel_ids:
        changed = relation_get(unit=local_unit(),
                               rid=rid,
                               attribute='ep_changed')
        if changed:
            changed = json.loads(changed)
        else:
            changed = {}
        for unit in related_units(rid):
            service_names = relation_get(
                unit=unit,
                rid=rid,
                attribute='subscribe_ep_change')
            if service_names:
                for service_name in service_names.split():
                    key = '{}-endpoint-changed'.format(service_name)
                    if data.get(key):
                        changed[service_name] = data[key]
                    elif service_name not in changed:
                        service_endpoint = service_endpoint_dict(service_name)
                        if service_endpoint:
                            changed[service_name] = service_endpoint
        if changed:
            relation_set(
                relation_id=rid,
                relation_settings={
                    'catalog_ttl': config('catalog-cache-expiration'),
                    'ep_changed': json.dumps(changed, sort_keys=True)})
            # As a first step in resolving a race condition when updating
            # identity and identity-notifications (LP: #1902264), start sending
            # this data into the application data-bag instead of just the
            # per-unit relation data. The consuming charms will need updating
            # to look in the app data bag as well.
            #
            # After the charms consuming thie relation have been updated,
            # it will be possible to remove the per-relation set above.
            relation_set(
                relation_id=rid,
                relation_settings={
                    'catalog_ttl': config('catalog-cache-expiration'),
                    'ep_changed': json.dumps(changed, sort_keys=True)},
                app=True)


def send_notifications(checksum_data, endpoint_data, force=False):
    send_id_notifications(checksum_data, force=force)
    send_id_service_notifications(endpoint_data)


def send_id_notifications(data, force=False):
    """Send notifications to all units listening on the identity-notifications
    interface.

    Units are expected to ignore notifications that they don't expect.

    NOTE: settings that are not required/in use must always be set to None
          so that they are removed from the relation.

    :param data: Dict of key=value to use as trigger for notification. If the
                 last broadcast is unchanged by the addition of this data, the
                 notification will not be sent.
    :param force: Determines whether a trigger value is set to ensure the
                  remote hook is fired.
    """
    if not data or not is_leader():
        log("Not sending notifications (no data or not leader)", level=INFO)
        return

    rel_ids = relation_ids('identity-notifications')
    if not rel_ids:
        log("No relations on identity-notifications - skipping broadcast",
            level=INFO)
        return

    keys = []
    diff = False

    # Get all settings previously sent
    for rid in rel_ids:
        rs = relation_get(unit=local_unit(), rid=rid)
        if rs:
            keys += list(rs.keys())

        # Don't bother checking if we have already identified a diff
        if diff:
            continue

        # Work out if this notification changes anything
        for k, v in data.items():
            if rs.get(k, None) != v:
                diff = True
                break

    if not diff:
        log("Notifications unchanged by new values so skipping broadcast",
            level=INFO)
        return

    # Set all to None
    _notifications = {k: None for k in set(keys)}

    # Set new values
    for k, v in data.items():
        _notifications[k] = v

    if force:
        _notifications['trigger'] = str(uuid.uuid4())

    # Broadcast
    log("Sending identity-service notifications (trigger={})".format(force),
        level=DEBUG)
    for rid in rel_ids:
        relation_set(relation_id=rid, relation_settings=_notifications)
        # As a first step in resolving a race condition when updating
        # identity and identity-notifications (LP: #1902264), start sending
        # this data into the application data-bag instead of just the
        # per-unit relation data. The consuming charms will need updating
        # to look in the app data bag as well.
        #
        # After the charms consuming thie relation have been updated,
        # it will be possible to remove the per-relation set above.
        relation_set(relation_id=rid,
                     relation_settings=_notifications,
                     app=True)


def is_db_ready(use_current_context=False, db_rel=None):
    """Database relations are expected to provide a list of 'allowed' units to
    confirm that the database is ready for use by those units.

    If db relation has provided this information and local unit is a member,
    returns True otherwise False.
    """
    key = 'allowed_units'
    db_rels = ['shared-db']
    if db_rel:
        db_rels = [db_rel]

    rel_has_units = False

    if use_current_context:
        if not any([relation_id() in relation_ids(r) for r in db_rels]):
            raise Exception("use_current_context=True but not in one of {} "
                            "rel hook contexts (currently in {})."
                            .format(', '.join(db_rels), relation_id()))

        allowed_units = relation_get(attribute=key)
        if allowed_units and local_unit() in allowed_units.split():
            return True

        # We are in shared-db rel but don't yet have permissions
        log("{} does not yet have db permissions".format(local_unit()),
            level=DEBUG)
        return False
    else:
        for rel in db_rels:
            for rid in relation_ids(rel):
                for unit in related_units(rid):
                    allowed_units = relation_get(rid=rid, unit=unit,
                                                 attribute=key)
                    if allowed_units and local_unit() in allowed_units.split():
                        return True

                    rel_has_units = True

    # If neither relation has units then we are probably in sqlite mode so
    # return True.
    return not rel_has_units


def determine_python_path():
    """Return the python-path

    Determine if snap installed and return the appropriate python path.
    Returns None unless the charm if neither condition is true.

    :returns: string python path or None
    """
    _python_path = 'lib/python2.7/site-packages'
    if snap_install_requested():
        return os.path.join(SNAP_BASE_DIR, _python_path)
    else:
        return None


def get_optional_interfaces():
    """Return the optional interfaces that should be checked if the relevant
    relations have appeared.
    :returns: {general_interface: [specific_int1, specific_int2, ...], ...}
    """
    optional_interfaces = {}
    if relation_ids('ha'):
        optional_interfaces = {'ha': ['cluster']}
    return optional_interfaces


def check_extra_for_assess_status(configs):
    """Check that if we have a relation_id for high availability that we can
    get the hacluster config.  If we can't then we are blocked.  This function
    is called from assess_status/set_os_workload_status as the charm_func and
    needs to return either "unknown", "" if there is no problem or the status,
    message if there is a problem.

    :param configs: an OSConfigRender() instance.
    :return 2-tuple: (string, string) = (status, message)
    """
    if relation_ids('ha'):
        try:
            get_hacluster_config()
        except Exception:
            return ('blocked',
                    'hacluster missing configuration: '
                    'vip, vip_iface, vip_cidr')

    # Check if any of the vips are invalid
    invalid_vips = get_invalid_vips()
    if invalid_vips:
        return('blocked', f'Invalid vips: {invalid_vips}')

    # verify that the config item, if set, is actually usable and valid
    conf = config('password-security-compliance')
    if (conf and (keystone_context.KeystoneContext
                  ._decode_password_security_compliance_string(conf) is None)):
        return ('blocked',
                "'password-security-compliance' is invalid")
    unit_ready, msg = check_api_unit_ready()
    if not unit_ready:
        return ('blocked', msg)
    # return 'unknown' as the lowest priority to not clobber an existing
    # status.
    return 'unknown', ''


def assess_status(configs):
    """Assess status of current unit

    Decides what the state of the unit should be based on the current
    configuration.

    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.

    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    assess_status_func(configs)()
    os_application_version_set(VERSION_PACKAGE)
    if is_leader():
        os_application_status_set(get_api_application_status)


def assess_status_func(configs, exclude_ha_resource=False):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE: REQUIRED_INTERFACES is augmented with the optional interfaces
    depending on the current config before being passed to the
    make_assess_status_func() function.

    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    required_interfaces = REQUIRED_INTERFACES.copy()
    required_interfaces.update(get_optional_interfaces())
    _services, _ports = get_managed_services_and_ports(
        services(),
        determine_ports())
    return make_assess_status_func(
        configs, required_interfaces,
        charm_func=check_extra_for_assess_status,
        services=_services,
        ports=_ports)


def get_file_stored_domain_id(backing_file):
    domain_id = None
    if os.path.isfile(backing_file):
        log("Loading stored domain id from {}".format(backing_file),
            level=INFO)
        with open(backing_file, 'r') as fd:
            domain_id = fd.readline().strip('\n')
    return domain_id


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.

    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.

    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit

    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    _services, _ports = get_managed_services_and_ports(
        services(),
        determine_ports())
    f(assess_status_func(configs),
      services=_services,
      ports=_ports)


def post_snap_install():
    """ Specific steps post snap install for this charm

    """
    log("Performing post snap install tasks", INFO)
    PASTE_SRC = ('{}/etc/keystone/keystone-paste.ini'
                 ''.format(SNAP_BASE_DIR))
    PASTE_DST = '{}/keystone-paste.ini'.format(SNAP_COMMON_KEYSTONE_DIR)
    if os.path.exists(PASTE_SRC):
        log("Performing post snap install tasks", INFO)
        shutil.copy(PASTE_SRC, PASTE_DST)


def key_setup():
    """Initialize Fernet and Credential encryption key repositories

    To setup the key repositories, calls (as user "keystone"):

        keystone-manage fernet_setup
        keystone-manage credential_setup

    In addition we migrate any credentials currently stored in database using
    the null key to be encrypted by the new credential key:

        keystone-manage credential_migrate

    Note that we only want to do this once, so we touch an empty file
    (KEY_SETUP_FILE) to indicate that it has been done.

    :raises: `:class:subprocess.CallProcessError` if either of the commands
        fails.
    """
    if os.path.exists(KEY_SETUP_FILE) or not is_leader():
        return
    base_cmd = ['sudo', '-u', 'keystone', 'keystone-manage']
    try:
        log("Setting up key repositories for Fernet tokens and Credential "
            "encryption", level=DEBUG)
        subprocess.check_call(base_cmd + ['fernet_setup'])
        subprocess.check_call(base_cmd + ['credential_setup'])
        subprocess.check_call(base_cmd + ['credential_migrate'])
        # touch the file to create
        open(KEY_SETUP_FILE, "w").close()
    except subprocess.CalledProcessError as e:
        log("Key repository setup failed, will retry in config-changed hook: "
            "{}".format(e), level=ERROR)


def fernet_rotate():
    """Rotate Fernet keys

    To rotate the Fernet tokens, and create a new staging key, it calls (as the
    "keystone" user):

        keystone-manage fernet_rotate

    Note that we do not rotate the Credential encryption keys.

    Note that this does NOT synchronise the keys between the units.  This is
    performed in `:function:`hooks.keystone_utils.fernet_leader_set`

    :raises: `:class:subprocess.CallProcessError` if the command fails.
    """
    log("Rotating Fernet tokens", level=DEBUG)
    cmd = ['sudo', '-u', 'keystone', 'keystone-manage', 'fernet_rotate']
    subprocess.check_call(cmd)


def key_leader_set():
    """Read current key sets and update leader storage

    The keys are read from the `FERNET_KEY_REPOSITORY` and
    `CREDENTIAL_KEY_REPOSITORY` directories.  Note that this function will fail
    if it is called on the unit that is not the leader.

    :raises: :class:`RuntimeError` if the leader_set fails.
    """
    disk_keys = {}
    for key_repository in [FERNET_KEY_REPOSITORY, CREDENTIAL_KEY_REPOSITORY]:
        disk_keys[key_repository] = {}
        for key_number in os.listdir(key_repository):
            with open(os.path.join(key_repository, key_number),
                      'r') as f:
                disk_keys[key_repository][key_number] = f.read()
    # compare current leader_settings of the keys with the current set of keys
    leader_keys_str = leader_get('key_repository') or "{}"
    current_disk_keys = json.loads(leader_keys_str)
    if current_disk_keys != disk_keys:
        _leader_set_secret({'key_repository': json.dumps(disk_keys)})


def key_write(log_func=log):
    """Get keys from leader storage and write out to disk

    The keys are written to the `FERNET_KEY_REPOSITORY` and
    `CREDENTIAL_KEY_REPOSITORY` directories.  Note that the keys are first
    written to a tmp file and then moved to the key to avoid any races.  Any
    'excess' keys are deleted, which may occur if the "number of keys" has been
    reduced on the leader.

    Note: Only the non leaders do this; the leader uses
    fernet_keys_rotate_and_sync() to perform rotations and 'owns' the keys that
    are in use.
    """
    # don't do this on the leader
    if is_leader():
        return
    leader_keys = leader_get('key_repository')
    if not leader_keys:
        log_func('"key_repository" not in leader settings yet...', level=DEBUG)
        return
    leader_keys = json.loads(leader_keys)
    for key_repository in [FERNET_KEY_REPOSITORY,
                           CREDENTIAL_KEY_REPOSITORY]:
        tmp_key_repository = key_repository + ".tmp"
        try:
            if not os.path.exists(key_repository):
                mkdir(key_repository,
                      owner=KEYSTONE_USER,
                      group=KEYSTONE_USER,
                      perms=0o700)
            # order of this mkdir's is important as this is inside the above
            # one.
            mkdir(tmp_key_repository,
                  owner=KEYSTONE_USER,
                  group=KEYSTONE_USER,
                  perms=0o700)
            for key_number, key in leader_keys[key_repository].items():
                tmp_filename = os.path.join(tmp_key_repository,
                                            "{}".format(key_number))
                key_filename = os.path.join(key_repository, key_number)
                if not _file_equal_to(key_filename, key):
                    log_func("Replacing/adding into repository: {}, "
                             "key number: {}"
                             .format(key_repository, key_number),
                             level=DEBUG)
                    # write to tmp file first, move the key into place in an
                    # atomic operation avoiding any races with consumers of the
                    # key files
                    write_file(tmp_filename,
                               key,
                               owner=KEYSTONE_USER,
                               group=KEYSTONE_USER,
                               perms=0o600)
                    os.rename(tmp_filename, key_filename)
            # now delete any keys that shouldn't be there
            for key_number in os.listdir(key_repository):
                if key_number not in leader_keys[key_repository].keys():
                    # ignore if it is not a file
                    if os.path.isfile(
                            os.path.join(key_repository, key_number)):
                        log_func("fernet keys: repository: {}, "
                                 "removing key number: {}"
                                 .format(key_repository, key),
                                 level=DEBUG)
                        os.remove(os.path.join(key_repository, key_number))
        finally:
            if os.path.exists(tmp_key_repository):
                shutil.rmtree(tmp_key_repository, ignore_errors=False,
                              onerror=None)

        # also say that keys have been setup for this system.
        open(KEY_SETUP_FILE, "w").close()


def _file_equal_to(name, contents):
    """Compare a file and a string

    The file is assumed to be small so that they can be compared in memory.  Do
    not use a large file!

    :param name: name of file contents to compare
    :type name: str
    :param contents: contents to compare to
    :type contents: str
    :returns: true if the file's contents is the same as contents
    :rtype: boolean
    """
    try:
        with open(name, "rt") as f1:
            return f1.read() == contents
    except FileNotFoundError:
        return False


def handle_fernet_keys_cron_call(log_func=log):
    """Handle the cronjob which runs on all units (including leader)

    This calls the fernet_keys_rotate_and_sync() on the leader and
    key_write() on the non-leader to ensure that keys are always synced across
    all units regardless of hook execution issues or other failures.

    Note if a unit is in error then it won't get synced keys due to not being
    able to use the leadership settings.

    :param log_func: The log function to use.
    :type log_func: Callable[str, str]
    """
    if is_leader():
        fernet_keys_rotate_and_sync(log_func)
    else:
        key_write(log_func)


def fernet_keys_rotate_and_sync(log_func=log):
    """Rotate and sync the keys if the unit is the leader and the primary key
    has expired.

    The modification time of the staging key (key with index '0') is used,
    along with the config setting "token_expiration" to determine whether to
    rotate the keys, along with the function `fernet_enabled()` to test
    whether to do it at all.

    Note that the reason for using modification time and not change time is
    that the former can be set by the operator as part of restoring the key
    from backup.

    The rotation time = token-expiration / (max-active-keys - 2)

    where max-active-keys has a minimum of 3.

    :param log_func: Function to use for logging
    :type log_func: func
    """
    if not keystone_context.fernet_enabled() or not is_leader():
        return
    if is_unit_paused_set():
        log_func("Fernet key rotation requested but unit is paused",
                 level=INFO)
        return
    # now see if the keys need to be rotated
    try:
        last_rotation = os.stat(
            os.path.join(FERNET_KEY_REPOSITORY, '0')).st_mtime
    except OSError:
        log_func("Fernet key rotation requested but key repository not "
                 "initialized yet", level=WARNING)
        return
    max_keys = max(config('fernet-max-active-keys'), 3)
    expiration = config('token-expiration')
    rotation_time = expiration // (max_keys - 2)
    now = time.time()
    if last_rotation + rotation_time > now:
        # No rotation to do as not reached rotation time
        log_func("No rotation until at least {}, but checking keys are "
                 "set in leader settings."
                 .format(
                     time.asctime(time.gmtime(last_rotation + rotation_time))),
                 level=DEBUG)
        key_leader_set()
        return
    # now rotate the keys and sync them
    fernet_rotate()
    key_leader_set()
    log_func("Rotated and started sync (via leader settings) of fernet keys",
             level=INFO)


def assemble_endpoints(settings):
    """
    Assemble multiple endpoints from relation data. service name
    should be prepended to setting name, i.e.:
     realtion-set ec2_service=$foo ec2_region=$foo ec2_public_url=$foo
     relation-set nova_service=$foo nova_region=$foo nova_public_url=$foo

    Results in a dict that looks like:
    { 'ec2': {
          'service': $foo
          'region': $foo
          'public_url': $foo
      }
      'nova': {
          'service': $foo
          'region': $foo
          'public_url': $foo
      }
    }
    """
    endpoints = OrderedDict()  # for Python3 we need a consistent order
    for k, v in settings.items():
        ep = k.split('_')[0]
        x = '_'.join(k.split('_')[1:])
        if ep not in endpoints:
            endpoints[ep] = {}
        endpoints[ep][x] = v

    return endpoints


def endpoints_checksum(settings):
    """
    Calculate the checksum (sha256) of public_url, admin_url and internal_url
    (in that order)

    :param settings: dict with urls registered in keystone.
    :returns: checksum
    """
    csum = hashlib.sha256()
    log(str(settings))
    csum.update(settings.get('public_url', None).encode('utf-8'))
    csum.update(settings.get('admin_url', None).encode('utf-8'))
    csum.update(settings.get('internal_url', None).encode('utf-8'))
    return csum.hexdigest()


def endpoints_dict(settings):
    """
    Build a dictionary of endpoint types using settings

    :param settings: dict with urls registered in keystone.
    :returns: dict of endpoints from settings
    """
    endpoints = {
        'public': settings.get('public_url', None),
        'admin': settings.get('admin_url', None),
        'internal': settings.get('internal_url', None),
    }

    return endpoints


def _leader_set_secret(secret_dict):
    """Wrapper around leader_set doing its best to prevent leaking secrets."""
    if not is_leader():
        raise RuntimeError("This unit isn't the leader and therefore can't "
                           "call leader_set() with the given secrets")
    try:
        leader_set(secret_dict)
    except subprocess.CalledProcessError as e:
        # Do not log 'e' or 'e.cmd' as this would leak secrets. Raise a
        # different exception to make sure that no one above will leak the
        # secrets by accident.
        raise RuntimeError('leader-set failed with {}: {}'.format(e.returncode,
                                                                  e.output))
