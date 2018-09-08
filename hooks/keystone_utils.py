#!/usr/bin/python
#
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

import json
import os
import shutil
import subprocess
import time
import urlparse
import uuid
import sys

from itertools import chain
from collections import OrderedDict
from copy import deepcopy

from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    determine_api_port,
    https,
    get_hacluster_config,
)

from charmhelpers.contrib.openstack import context, templating
from charmhelpers.contrib.network.ip import (
    is_ipv6,
    get_ipv6_addr
)

from charmhelpers.contrib.openstack.ip import (
    resolve_address,
    PUBLIC,
    INTERNAL,
    ADMIN
)

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    error_out,
    get_os_codename_install_source,
    os_release,
    save_script_rc as _save_script_rc,
    pause_unit,
    resume_unit,
    make_assess_status_func,
    os_application_version_set,
    CompareOpenStackReleases,
    reset_os_release,
    snap_install_requested,
    install_os_snaps,
    get_snaps_install_info_from_origin,
    enable_memcache,
    is_unit_paused_set,
)

from charmhelpers.core.decorators import (
    retry_on_exception,
)

from charmhelpers.core.hookenv import (
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
)

from charmhelpers.fetch import (
    apt_install,
    apt_update,
    apt_upgrade,
    add_source,
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
    'python-six',
    'pwgen',
    'uuid',
]

BASE_PACKAGES_SNAP = [
    'haproxy',
    'openssl',
    'python-six',
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
    STORED_TOKEN = "{}/keystone.token".format(SNAP_LIB_DIR)
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
    STORED_TOKEN = "/var/lib/keystone/keystone.token"
    STORED_ADMIN_DOMAIN_ID = "/var/lib/keystone/keystone.admin_domain_id"
    STORED_DEFAULT_DOMAIN_ID = "/var/lib/keystone/keystone.default_domain_id"
    SERVICE_PASSWD_PATH = '/var/lib/keystone/services.passwd'
    POLICY_JSON = '/etc/keystone/policy.json'
    BASE_SERVICES = [
        'keystone',
    ]


HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
APACHE_CONF = '/etc/apache2/sites-available/openstack_https_frontend'
APACHE_24_CONF = '/etc/apache2/sites-available/openstack_https_frontend.conf'
MEMCACHED_CONF = '/etc/memcached.conf'

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
                     keystone_context.WebSSOTrustedDashboardContext()],
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
    for k, v in settings.iteritems():
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
        assert(subprocess.call(["pgrep", svc_string]) == 1)

    if not ptable_string:
        ptable_string = service_name
    service_stop(service_name)
    check_pids_gone(ptable_string)
    service_start(service_name)


def restart_function_map():
    """Return a dict of services with any custom functions that should be
       used to restart that service
    @returns dict of {'svc1': restart_func, 'svc2', other_func, ...}
    """
    rfunc_map = {}
    if run_in_apache():
        rfunc_map['apache2'] = restart_pid_check
    return rfunc_map


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
                subprocess.check_call(['a2dissite', apache_site])
            except subprocess.CalledProcessError:
                # Remove the file
                os.remove(apache_site_file)


def register_configs():
    release = os_release('keystone')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs


def restart_map():
    return OrderedDict([(cfg, v['services'])
                        for cfg, v in resource_map().iteritems()
                        if v['services']])


def services():
    """Returns a list of (unique) services associated with this charm"""
    return list(set(chain(*restart_map().values())))


def determine_ports():
    """Assemble a list of API ports for services we are managing"""
    ports = [config('admin-port'), config('service-port')]
    return list(set(ports))


def api_port(service):
    return {
        'keystone-admin': config('admin-port'),
        'keystone-public': config('service-port')
    }[service]


def determine_packages():
    # currently all packages match service names
    if snap_install_requested():
        pkgs = deepcopy(BASE_PACKAGES_SNAP)
        if enable_memcache(release=os_release('keystone')):
            pkgs = pkgs + ['memcached']
        return sorted(pkgs)
    else:
        packages = set(services()).union(BASE_PACKAGES)
        if run_in_apache():
            packages.add('libapache2-mod-wsgi')
        return sorted(packages)


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
    os.execl('./hooks/config-changed-postupgrade', '')


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


def set_admin_token(admin_token='None'):
    """Set admin token according to deployment config or use a randomly
       generated token if none is specified (default).
    """
    if admin_token != 'None':
        log('Configuring Keystone to use a pre-configured admin token.')
        token = admin_token
    else:
        log('Configuring Keystone to use a random admin token.')
        if os.path.isfile(STORED_TOKEN):
            msg = 'Loading a previously generated' \
                  ' admin token from %s' % STORED_TOKEN
            log(msg)
            with open(STORED_TOKEN, 'r') as f:
                token = f.read().strip()
        else:
            token = pwgen(length=64)
            with open(STORED_TOKEN, 'w') as out:
                out.write('%s\n' % token)
    return(token)


def get_admin_token():
    """Temporary utility to grab the admin token as configured in
       keystone.conf
    """
    with open(KEYSTONE_CONF, 'r') as f:
        for l in f.readlines():
            if l.split(' ')[0] == 'admin_token':
                try:
                    return l.split('=')[1].strip()
                except:
                    error_out('Could not parse admin_token line from %s' %
                              KEYSTONE_CONF)
    error_out('Could not find admin_token line in %s' % KEYSTONE_CONF)


def is_service_present(service_name, service_type):
    manager = get_manager()
    service_id = manager.resolve_service_id(service_name, service_type)
    return service_id is not None


def delete_service_entry(service_name, service_type):
    """ Delete a service from keystone"""
    manager = get_manager()
    service_id = manager.resolve_service_id(service_name, service_type)
    if service_id:
        manager.api.services.delete(service_id)
        log("Deleted service entry '%s'" % service_name, level=DEBUG)


def create_service_entry(service_name, service_type, service_desc, owner=None):
    """ Add a new service entry to keystone if one does not already exist """
    manager = get_manager()
    for service in [s._info for s in manager.api.services.list()]:
        if service['name'] == service_name:
            log("Service entry for '%s' already exists." % service_name,
                level=DEBUG)
            return

    manager.api.services.create(service_name,
                                service_type,
                                description=service_desc)
    log("Created new service entry '%s'" % service_name, level=DEBUG)


def create_endpoint_template(region, service, publicurl, adminurl,
                             internalurl):
    manager = get_manager()
    if manager.api_version == 2:
        create_endpoint_template_v2(manager, region, service, publicurl,
                                    adminurl, internalurl)
    else:
        create_endpoint_template_v3(manager, region, service, publicurl,
                                    adminurl, internalurl)


def create_endpoint_template_v2(manager, region, service, publicurl, adminurl,
                                internalurl):
    """ Create a new endpoint template for service if one does not already
        exist matching name *and* region """
    service_id = manager.resolve_service_id(service)
    for ep in [e._info for e in manager.api.endpoints.list()]:
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
                manager.api.endpoints.delete(ep['id'])

    manager.create_endpoints(region=region,
                             service_id=service_id,
                             publicurl=publicurl,
                             adminurl=adminurl,
                             internalurl=internalurl)
    log("Created new endpoint template for '%s' in '%s'" % (region, service),
        level=DEBUG)


def create_endpoint_template_v3(manager, region, service, publicurl, adminurl,
                                internalurl):
    service_id = manager.resolve_service_id(service)
    endpoints = {
        'public': publicurl,
        'admin': adminurl,
        'internal': internalurl,
    }
    for ep_type in endpoints.keys():
        # Delete endpoint if its has changed
        ep_deleted = manager.delete_old_endpoint_v3(
            ep_type,
            service_id,
            region,
            endpoints[ep_type]
        )
        ep_exists = manager.find_endpoint_v3(
            ep_type,
            service_id,
            region
        )
        if ep_deleted or not ep_exists:
            manager.api.endpoints.create(
                service_id,
                endpoints[ep_type],
                interface=ep_type,
                region=region
            )


def create_tenant(name, domain):
    """Creates a tenant if it does not already exist"""
    manager = get_manager()
    tenant = manager.resolve_tenant_id(name, domain=domain)
    if not tenant:
        manager.create_tenant(tenant_name=name,
                              domain=domain,
                              description='Created by Juju')
        log("Created new tenant '%s' in domain '%s'" % (name, domain),
            level=DEBUG)
        return

    log("Tenant '%s' already exists." % name, level=DEBUG)


def create_or_show_domain(name):
    """Creates a domain if it does not already exist"""
    manager = get_manager()
    domain_id = manager.resolve_domain_id(name)
    if domain_id:
        log("Domain '%s' already exists." % name, level=DEBUG)
    else:
        manager.create_domain(domain_name=name,
                              description='Created by Juju')
        log("Created new domain: %s" % name, level=DEBUG)
        domain_id = manager.resolve_domain_id(name)
    return domain_id


def user_exists(name, domain=None):
    manager = get_manager()
    domain_id = None
    if domain:
        domain_id = manager.resolve_domain_id(domain)
        if not domain_id:
            error_out('Could not resolve domain_id for {} when checking if '
                      ' user {} exists'.format(domain, name))
    if manager.resolve_user_id(name, user_domain=domain):
        if manager.api_version == 2:
            users = manager.api.users.list()
        else:
            users = manager.api.users.list(domain=domain_id)
        for user in users:
            if user.name.lower() == name.lower():
                # In v3 Domains are seperate user namespaces so need to check
                # that the domain matched if provided
                if domain:
                    if domain_id == user.domain_id:
                        return True
                else:
                    return True

    return False


def create_user(name, password, tenant=None, domain=None):
    """Creates a user if it doesn't already exist, as a member of tenant"""
    manager = get_manager()
    if user_exists(name, domain=domain):
        log("A user named '%s' already exists in domain '%s'" % (name, domain),
            level=DEBUG)
        return

    tenant_id = None
    if tenant:
        tenant_id = manager.resolve_tenant_id(tenant, domain=domain)
        if not tenant_id:
            error_out("Could not resolve tenant_id for tenant '%s' in domain "
                      "'%s'" % (tenant, domain))

    domain_id = None
    if domain:
        domain_id = manager.resolve_domain_id(domain)
        if not domain_id:
            error_out('Could not resolve domain_id for domain %s when creating'
                      ' user %s' % (domain, name))

    manager.create_user(name=name,
                        password=password,
                        email='juju@localhost',
                        tenant_id=tenant_id,
                        domain_id=domain_id)
    log("Created new user '%s' tenant: '%s' domain: '%s'" % (name, tenant_id,
        domain_id), level=DEBUG)


def get_manager(api_version=None):
    """Return a keystonemanager for the correct API version"""
    set_python_path()
    from manager import get_keystone_manager
    return get_keystone_manager(get_local_endpoint(), get_admin_token(),
                                api_version)


def create_role(name, user=None, tenant=None, domain=None):
    """Creates a role if it doesn't already exist. grants role to user"""
    manager = get_manager()
    if not manager.resolve_role_id(name):
        manager.api.roles.create(name=name)
        log("Created new role '%s'" % name, level=DEBUG)
    else:
        log("A role named '%s' already exists" % name, level=DEBUG)

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
            error_out("Could not resolve tenant_id for tenant '%s' in domain "
                      "'%s'" % (tenant, domain))

    domain_id = None
    if domain:
        domain_id = manager.resolve_domain_id(domain)
        if not domain_id:
            error_out('Could not resolve domain_id for domain %s' % domain)

    cur_roles = manager.roles_for_user(user_id, tenant_id=tenant_id,
                                       domain_id=domain_id)
    if not cur_roles or role_id not in [r.id for r in cur_roles]:
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
        fd.writelines("%s\n" % data)


def get_admin_passwd(user=None):
    passwd = config("admin-password")
    if passwd and passwd.lower() != "none":
        return passwd

    _migrate_admin_password()
    passwd = leader_get('{}_passwd'.format(user))

    if not passwd and is_leader():
        log("Generating new passwd for user: %s" %
            config("admin-user"))
        cmd = ['pwgen', '-c', '16', '1']
        passwd = str(subprocess.check_output(cmd)).strip()

    return passwd


def set_admin_passwd(passwd, user=None):
    if user is None:
        user = 'admin'

    leader_set({'{}_passwd'.format(user): passwd})


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


def set_python_path():
    """ Set the Python path to include snap installed python libraries

    The charm itself requires access to the python client. When installed as a
    snap the client libraries are in /snap/$SNAP/common/lib/python2.7. This
    function sets the python path to allow clients to be imported from snap
    installs.
    """
    if snap_install_requested():
        sys.path.append(determine_python_path())


def ensure_initial_admin(config):
    # Allow retry on fail since leader may not be ready yet.
    # NOTE(hopem): ks client may not be installed at module import time so we
    # use this wrapped approach instead.
    set_python_path()
    try:
        from keystoneclient.apiclient.exceptions import InternalServerError
    except:
        # Backwards-compatibility for earlier versions of keystoneclient (< I)
        from keystoneclient.exceptions import (ClientException as
                                               InternalServerError)

    @retry_on_exception(3, base_delay=3, exc_type=InternalServerError)
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

        create_service_entry("keystone", "identity",
                             "Keystone Identity Service")

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
        ep = "%s://%s:%s/%s" % (proto, ip, port, suffix)
    else:
        ep = "%s://%s:%s" % (proto, ip, port)
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
    log("Updating password for user '%s'" % username)

    user_id = manager.resolve_user_id(username, user_domain=domain)
    if user_id is None:
        error_out("Could not resolve user id for '%s'" % username)

    manager.update_password(user=user_id, password=password)
    log("Successfully updated password for user '%s'" %
        username)


def load_stored_passwords(path=SERVICE_PASSWD_PATH):
    creds = {}
    if not os.path.isfile(path):
        return creds

    stored_passwd = open(path, 'r')
    for l in stored_passwd.readlines():
        user, passwd = l.strip().split(':')
        creds[user] = passwd
    return creds


def _migrate_admin_password():
    """Migrate on-disk admin passwords to leader storage"""
    if is_leader() and os.path.exists(STORED_PASSWD):
        log('Migrating on-disk stored passwords to leader storage')
        with open(STORED_PASSWD) as fd:
            leader_set({"admin_passwd": fd.readline().strip('\n')})

        os.unlink(STORED_PASSWD)


def _migrate_service_passwords():
    """Migrate on-disk service passwords to leader storage"""
    if is_leader() and os.path.exists(SERVICE_PASSWD_PATH):
        log('Migrating on-disk stored passwords to leader storage')
        creds = load_stored_passwords()
        for k, v in creds.iteritems():
            leader_set({"{}_passwd".format(k): v})
        os.unlink(SERVICE_PASSWD_PATH)


def get_service_password(service_username):
    _migrate_service_passwords()
    passwd = leader_get("{}_passwd".format(service_username))
    if passwd is None:
        passwd = pwgen(length=64)

    return passwd


def set_service_password(passwd, user):
    leader_set({"{}_passwd".format(user): passwd})


def is_password_changed(username, passwd):
    _passwd = leader_get("{}_passwd".format(username))
    return (_passwd is None or passwd != _passwd)


def relation_list(rid):
    cmd = [
        'relation-list',
        '-r', rid,
    ]
    result = str(subprocess.check_output(cmd)).split()
    if result == "":
        return None
    else:
        return result


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

    log("Creating service credentials for '%s'" % user, level=DEBUG)
    if user_exists(user, domain=domain):
        log("User '%s' already exists" % (user), level=DEBUG)
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
        log("No role grants requested for user '%s'" % (user), level=DEBUG)

    if new_roles:
        # Allow the remote service to request creation of any additional roles.
        # Currently used by Swift and Ceilometer.
        for role in new_roles:
            log("Creating requested role '%s'" % role, level=DEBUG)
            create_role(role, user=user, tenant=tenant, domain=domain)

    return passwd


def create_service_credentials(user, new_roles=None):
    """Create credentials for service with given username.

    For Keystone v2.0 API compability services are given a user under
    config('service-tenant') in DEFAULT_DOMAIN and are given the
    config('admin-role') role. Tenant is assumed to already exist.

    For Keysteone v3 API compability services are given a user in project
    config('service-tenant') in SERVICE_DOMAIN and are given the
    config('admin-role') role.

    Project is assumed to already exist.
    """
    tenant = config('service-tenant')
    if not tenant:
        raise Exception("No service tenant provided in config")

    domain = None
    if get_api_version() > 2:
        domain = DEFAULT_DOMAIN
    passwd = create_user_credentials(user, get_service_password,
                                     set_service_password,
                                     tenant=tenant, new_roles=new_roles,
                                     grants=[config('admin-role')],
                                     domain=domain)
    if get_api_version() > 2:
        # Create account in SERVICE_DOMAIN as well using same password
        domain = SERVICE_DOMAIN
        passwd = create_user_credentials(user, get_service_password,
                                         set_service_password,
                                         tenant=tenant, new_roles=new_roles,
                                         grants=[config('admin-role')],
                                         domain=domain)
    return passwd


def add_service_to_keystone(relation_id=None, remote_unit=None):
    manager = get_manager()
    settings = relation_get(rid=relation_id, unit=remote_unit)
    # the minimum settings needed per endpoint
    single = set(['service', 'region', 'public_url', 'admin_url',
                  'internal_url'])
    https_cns = []

    protocol = get_protocol()

    if single.issubset(settings):
        # other end of relation advertised only one endpoint
        if 'None' in settings.itervalues():
            # Some backend services advertise no endpoint but require a
            # hook execution to update auth strategy.
            relation_data = {}
            # Check if clustered and use vip + haproxy ports if so
            relation_data["auth_host"] = resolve_address(ADMIN)
            relation_data["service_host"] = resolve_address(PUBLIC)

            relation_data["auth_protocol"] = protocol
            relation_data["service_protocol"] = protocol
            relation_data["auth_port"] = config('admin-port')
            relation_data["service_port"] = config('service-port')
            relation_data["region"] = config('region')
            relation_data["api_version"] = get_api_version()
            relation_data["admin_domain_id"] = leader_get(
                attribute='admin_domain_id')

            # Allow the remote service to request creation of any additional
            # roles. Currently used by Horizon
            for role in get_requested_roles(settings):
                log("Creating requested role: %s" % role)
                create_role(role)

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
                service_username = "%s%s" % (prefix, service_username)

            # NOTE(jamespage) internal IP for backwards compat for SSL certs
            internal_cn = urlparse.urlparse(settings['internal_url']).hostname
            https_cns.append(internal_cn)
            public_cn = urlparse.urlparse(settings['public_url']).hostname
            https_cns.append(public_cn)
            https_cns.append(urlparse.urlparse(settings['admin_url']).hostname)
    else:
        # assemble multiple endpoints from relation data. service name
        # should be prepended to setting name, ie:
        #  realtion-set ec2_service=$foo ec2_region=$foo ec2_public_url=$foo
        #  relation-set nova_service=$foo nova_region=$foo nova_public_url=$foo
        # Results in a dict that looks like:
        # { 'ec2': {
        #       'service': $foo
        #       'region': $foo
        #       'public_url': $foo
        #   }
        #   'nova': {
        #       'service': $foo
        #       'region': $foo
        #       'public_url': $foo
        #   }
        # }
        endpoints = {}
        for k, v in settings.iteritems():
            ep = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if ep not in endpoints:
                endpoints[ep] = {}
            endpoints[ep][x] = v

        services = []
        for ep in endpoints:
            # weed out any unrelated relation stuff Juju might have added
            # by ensuring each possible endpiont has appropriate fields
            #  ['service', 'region', 'public_url', 'admin_url', 'internal_url']
            if single.issubset(endpoints[ep]):
                ep = endpoints[ep]
                ensure_valid_service(ep['service'])
                add_endpoint(region=ep['region'], service=ep['service'],
                             publicurl=ep['public_url'],
                             adminurl=ep['admin_url'],
                             internalurl=ep['internal_url'])
                services.append(ep['service'])
                # NOTE(jamespage) internal IP for backwards compat for
                # SSL certs
                internal_cn = urlparse.urlparse(ep['internal_url']).hostname
                https_cns.append(internal_cn)
                https_cns.append(urlparse.urlparse(ep['public_url']).hostname)
                https_cns.append(urlparse.urlparse(ep['admin_url']).hostname)

        service_username = '_'.join(sorted(services))

        # If an admin username prefix is provided, ensure all services use it.
        prefix = config('service-admin-prefix')
        if service_username and prefix:
            service_username = "%s%s" % (prefix, service_username)

    if 'None' in settings.itervalues():
        return

    if not service_username:
        return

    token = get_admin_token()
    roles = get_requested_roles(settings)
    service_password = create_service_credentials(service_username,
                                                  new_roles=roles)
    service_domain = None
    service_domain_id = None
    if get_api_version() > 2:
        service_domain = SERVICE_DOMAIN
        service_domain_id = manager.resolve_domain_id(SERVICE_DOMAIN)
    service_tenant = config('service-tenant')
    service_tenant_id = manager.resolve_tenant_id(service_tenant,
                                                  domain=service_domain)

    # NOTE(dosaboy): we use __null__ to represent settings that are to be
    # routed to relations via the cluster relation and set to None.
    relation_data = {
        "auth_host": resolve_address(ADMIN),
        "service_host": resolve_address(PUBLIC),
        "admin_token": token,
        "service_port": config("service-port"),
        "auth_port": config("admin-port"),
        "service_username": service_username,
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
        "api_version": get_api_version(),
        "admin_domain_id": leader_get(attribute='admin_domain_id'),
    }

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

    peer_store_and_set(relation_id=relation_id, **relation_data)


def get_protocol():
    """Determine the http protocol

    :returns: http or https
    """
    if https():
        protocol = 'https'
    else:
        protocol = 'http'
    return protocol


def ensure_valid_service(service):
    if service not in valid_services.keys():
        log("Invalid service requested: '%s'" % service)
        relation_set(admin_token=-1)
        return


def add_endpoint(region, service, publicurl, adminurl, internalurl):
    desc = valid_services[service]["desc"]
    service_type = valid_services[service]["type"]
    create_service_entry(service, service_type, desc)
    create_endpoint_template(region=region, service=service,
                             publicurl=publicurl,
                             adminurl=adminurl,
                             internalurl=internalurl)


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


def send_notifications(data, force=False):
    """Send notifications to all units listening on the identity-notifications
    interface.

    Units are expected to ignore notifications that they don't expect.

    NOTE: settings that are not required/inuse must always be set to None
          so that they are removed from the relation.

    :param data: Dict of key=value to use as trigger for notification. If the
                 last broadcast is unchanged by the addition of this data, the
                 notification will not be sent.
    :param force: Determines whether a trigger value is set to ensure the
                  remote hook is fired.
    """
    if not data or not is_elected_leader(CLUSTER_RES):
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
            keys += rs.keys()

        # Don't bother checking if we have already identified a diff
        if diff:
            continue

        # Work out if this notification changes anything
        for k, v in data.iteritems():
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
    for k, v in data.iteritems():
        _notifications[k] = v

    if force:
        _notifications['trigger'] = str(uuid.uuid4())

    # Broadcast
    log("Sending identity-service notifications (trigger=%s)" % (force),
        level=DEBUG)
    for rid in rel_ids:
        relation_set(relation_id=rid, relation_settings=_notifications)


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
            raise Exception("use_current_context=True but not in one of %s "
                            "rel hook contexts (currently in %s)." %
                            (', '.join(db_rels), relation_id()))

        allowed_units = relation_get(attribute=key)
        if allowed_units and local_unit() in allowed_units.split():
            return True

        # We are in shared-db rel but don't yet have permissions
        log("%s does not yet have db permissions" % (local_unit()),
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
    """Return the optional interfaces that should be checked if the relavent
    relations have appeared.
    :returns: {general_interface: [specific_int1, specific_int2, ...], ...}
    """
    optional_interfaces = {}
    if relation_ids('ha'):
        optional_interfaces = {'ha': ['cluster']}
    return optional_interfaces


def check_optional_relations(configs):
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
        except:
            return ('blocked',
                    'hacluster missing configuration: '
                    'vip, vip_iface, vip_cidr')
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


def assess_status_func(configs):
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
    return make_assess_status_func(
        configs, required_interfaces,
        charm_func=check_optional_relations,
        services=services(),
        ports=determine_ports())


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
    f(assess_status_func(configs),
      services=services(),
      ports=determine_ports())


def post_snap_install():
    """ Specific steps post snap install for this charm

    """
    log("Perfoming post snap install tasks", INFO)
    PASTE_SRC = ('{}/etc/keystone/keystone-paste.ini'
                 ''.format(SNAP_BASE_DIR))
    PASTE_DST = '{}/keystone-paste.ini'.format(SNAP_COMMON_KEYSTONE_DIR)
    if os.path.exists(PASTE_SRC):
        log("Perfoming post snap install tasks", INFO)
        shutil.copy(PASTE_SRC, PASTE_DST)


def restart_keystone():
    if not is_unit_paused_set():
        if snap_install_requested():
            service_restart('snap.keystone.*')
        else:
            service_restart(keystone_service())


def key_setup():
    """Initialize Fernet and Credential encryption key repositories

    To setup the key repositories, calls (as user "keystone"):

        keystone-manage fernet_setup
        keystone-manage credential_setup

    In addition we migrate any credentials currently stored in database using
    the null key to be encrypted by the new credential key:

        keystone-manage credential_migrate

    Note that we only want to do this once, so we store success in the leader
    settings (which we should be).

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

    :raises: :class:`subprocess.CalledProcessError` if the leader_set fails.
    """
    disk_keys = {}
    for key_repository in [FERNET_KEY_REPOSITORY, CREDENTIAL_KEY_REPOSITORY]:
        disk_keys[key_repository] = {}
        for key_number in os.listdir(key_repository):
            with open(os.path.join(key_repository, key_number),
                      'r') as f:
                disk_keys[key_repository][key_number] = f.read()
    leader_set({'key_repository': json.dumps(disk_keys)})


def key_write():
    """Get keys from leader storage and write out to disk

    The keys are written to the `FERNET_KEY_REPOSITORY` and
    `CREDENTIAL_KEY_REPOSITORY` directories.  Note that the keys are first
    written to a tmp file and then moved to the key to avoid any races.  Any
    'excess' keys are deleted, which may occur if the "number of keys" has been
    reduced on the leader.
    """
    leader_keys = leader_get('key_repository')
    if not leader_keys:
        log('"key_repository" not in leader settings yet...', level=DEBUG)
        return
    leader_keys = json.loads(leader_keys)
    for key_repository in [FERNET_KEY_REPOSITORY, CREDENTIAL_KEY_REPOSITORY]:
        mkdir(key_repository,
              owner=KEYSTONE_USER,
              group=KEYSTONE_USER,
              perms=0o700)
        for key_number, key in leader_keys[key_repository].items():
            tmp_filename = os.path.join(key_repository,
                                        ".{}".format(key_number))
            key_filename = os.path.join(key_repository, key_number)
            # write to tmp file first, move the key into place in an atomic
            # operation avoiding any races with consumers of the key files
            write_file(tmp_filename,
                       key,
                       owner=KEYSTONE_USER,
                       group=KEYSTONE_USER,
                       perms=0o600)
            os.rename(tmp_filename, key_filename)
        # now delete any keys that shouldn't be there
        for key_number in os.listdir(key_repository):
            if key_number not in leader_keys[key_repository].keys():
                os.remove(os.path.join(key_repository, key_number))
        # also say that keys have been setup for this system.
        open(KEY_SETUP_FILE, "w").close()


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

    where max-active-keys has a minumum of 3.

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
        # Nothing to do as not reached rotation time
        log_func("No rotation until at least {}"
                 .format(
                     time.asctime(time.gmtime(last_rotation + rotation_time))),
                 level=DEBUG)
        return
    # now rotate the keys and sync them
    fernet_rotate()
    key_leader_set()
    log_func("Rotated and started sync (via leader settings) of fernet keys",
             level=INFO)
