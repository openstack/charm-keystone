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

import os
import json
import yaml

from charmhelpers.contrib.openstack import context

from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port,
    determine_api_port,
    https,
)

from charmhelpers.core.hookenv import (
    cached,
    charm_dir,
    config,
    log,
    leader_get,
    is_leader,
    local_unit,
    related_units,
    relation_ids,
    relation_get,
)

from charmhelpers.contrib.openstack.utils import (
    CompareOpenStackReleases,
    os_release,
)


class MiddlewareContext(context.OSContextGenerator):
    interfaces = ['keystone-middleware']

    def __call__(self):

        middlewares = []

        for rid in relation_ids('keystone-middleware'):
            if related_units(rid):
                for unit in related_units(rid):
                    middleware_name = relation_get('middleware_name',
                                                   rid=rid,
                                                   unit=unit)
                    if middleware_name:
                        middlewares.append(middleware_name)
        return {
            'middlewares': ",".join(middlewares)
        }


class ApacheSSLContext(context.ApacheSSLContext):
    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'
    ssl_dir = os.path.join('/etc/apache2/ssl/', service_namespace)

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import (
            determine_ports,
        )

        self.external_ports = determine_ports()
        return super(ApacheSSLContext, self).__call__()


class NginxSSLContext(context.ApacheSSLContext):
    interfaces = ['https']
    external_ports = []
    service_namespace = 'keystone'
    ssl_dir = ('/var/snap/{}/common/lib/juju_ssl/{}/'
               ''.format(service_namespace, service_namespace))

    def __call__(self):
        # late import to work around circular dependency
        from keystone_utils import (
            determine_ports,
        )

        self.external_ports = determine_ports()
        ret = super(NginxSSLContext, self).__call__()
        if not ret:
            log("SSL not used", level='DEBUG')
            return {}

        # Transform for use by Nginx
        """
        {'endpoints': [(u'10.5.0.30', u'10.5.0.30', 4990, 4980),
                       (u'10.5.0.30', u'10.5.0.30', 35347, 35337)],
         'ext_ports': [4990, 35347],
         'namespace': 'keystone'}
        """

        nginx_ret = {}
        nginx_ret['ssl'] = https()
        nginx_ret['namespace'] = self.service_namespace
        endpoints = {}
        for ep in ret['endpoints']:
            int_address, address, ext, internal = ep
            if ext <= 5000:
                endpoints['public'] = {
                    'socket': 'public',
                    'address': address,
                    'ext': ext}
            elif ext >= 35337:
                endpoints['admin'] = {
                    'socket': 'admin',
                    'address': address,
                    'ext': ext}
            else:
                log("Unrecognized internal port", level='ERROR')
        nginx_ret['endpoints'] = endpoints

        return nginx_ret

    def enable_modules(self):
        return


class HAProxyContext(context.HAProxyContext):
    interfaces = []

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend nova.conf context with correct api_listening_ports
        '''
        from keystone_utils import api_port
        ctxt = super(HAProxyContext, self).__call__()

        # determine which port api processes should bind to, depending
        # on existence of haproxy + apache frontends
        listen_ports = {}
        listen_ports['admin_port'] = api_port('keystone-admin')
        listen_ports['public_port'] = api_port('keystone-public')

        # Apache ports
        a_admin_port = determine_apache_port(api_port('keystone-admin'),
                                             singlenode_mode=True)
        a_public_port = determine_apache_port(api_port('keystone-public'),
                                              singlenode_mode=True)

        port_mapping = {
            'admin-port': [
                api_port('keystone-admin'), a_admin_port],
            'public-port': [
                api_port('keystone-public'), a_public_port],
        }

        healthcheck = [{
            'option': 'httpchk GET /healthcheck',
            'http-check': 'expect status 200',
        }]

        backend_options = {
            'admin-port': healthcheck,
            'public-port': healthcheck,
        }

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        # for keystone.conf
        ctxt['listen_ports'] = listen_ports
        ctxt['backend_options'] = backend_options
        ctxt['https'] = https()
        return ctxt


class KeystoneContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        from keystone_utils import (
            api_port, endpoint_url, resolve_address,
            PUBLIC, ADMIN, ADMIN_DOMAIN,
            snap_install_requested, get_api_version,
        )
        ctxt = {}
        ctxt['api_version'] = get_api_version()
        ctxt['admin_role'] = config('admin-role')
        if ctxt['api_version'] > 2:
            ctxt['service_tenant_id'] = \
                leader_get(attribute='service_tenant_id')
            ctxt['admin_domain_name'] = ADMIN_DOMAIN
            ctxt['admin_domain_id'] = \
                leader_get(attribute='admin_domain_id')
            ctxt['default_domain_id'] = \
                leader_get(attribute='default_domain_id')
            # This is required prior to system-scope being implemented (Queens)
            ctxt['transitional_charm_user_id'] = leader_get(
                attribute='transitional_charm_user_id')
        ctxt['admin_port'] = determine_api_port(api_port('keystone-admin'),
                                                singlenode_mode=True)
        ctxt['public_port'] = determine_api_port(api_port('keystone-public'),
                                                 singlenode_mode=True)

        ctxt['debug'] = config('debug')
        ctxt['verbose'] = config('verbose')
        ctxt['token_expiration'] = config('token-expiration')
        ctxt['catalog_cache_expiration'] = config('catalog-cache-expiration')
        if config('role-cache-expiration') is not None:
            ctxt['role_cache_expiration'] = config('role-cache-expiration')

        ctxt['dogpile_cache_expiration'] = config('dogpile-cache-expiration')

        ctxt['identity_backend'] = config('identity-backend')
        ctxt['assignment_backend'] = config('assignment-backend')
        ctxt['token_provider'] = config('token-provider')
        ctxt['fernet_max_active_keys'] = config('fernet-max-active-keys')
        ctxt['ec2_auth_ttl'] = config('ec2-auth-ttl')
        if config('identity-backend') == 'ldap':
            ctxt['ldap_server'] = config('ldap-server')
            ctxt['ldap_user'] = config('ldap-user')
            ctxt['ldap_password'] = config('ldap-password')
            ctxt['ldap_suffix'] = config('ldap-suffix')
            ctxt['ldap_readonly'] = config('ldap-readonly')
            ldap_flags = config('ldap-config-flags')
            if ldap_flags:
                flags = context.config_flags_parser(ldap_flags)
                ctxt['ldap_config_flags'] = flags

        # Only try to decode it if there is something actually set - this
        # silences a NoneType warning in the logs if it isn't set
        password_security_compliance = config('password-security-compliance')
        if password_security_compliance:
            ctxt['password_security_compliance'] = (
                self._decode_password_security_compliance_string(
                    password_security_compliance))

        # Base endpoint URL's which are used in keystone responses
        # to unauthenticated requests to redirect clients to the
        # correct auth URL.
        ctxt['public_endpoint'] = endpoint_url(
            resolve_address(PUBLIC),
            api_port('keystone-public')).replace('v2.0', '')
        ctxt['admin_endpoint'] = endpoint_url(
            resolve_address(ADMIN),
            api_port('keystone-admin')).replace('v2.0', '')

        if snap_install_requested():
            ctxt['domain_config_dir'] = (
                '/var/snap/keystone/common/etc/keystone/domains')
            ctxt['log_config'] = (
                '/var/snap/keystone/common/etc/keystone/logging.conf')
            ctxt['paste_config_file'] = (
                '/var/snap/keystone/common/etc/keystone/keystone-paste.ini')
        else:
            ctxt['domain_config_dir'] = '/etc/keystone/domains'
            ctxt['log_config'] = ('/etc/keystone/logging.conf')
            ctxt['paste_config_file'] = '/etc/keystone/keystone-paste.ini'

        ctxt['default_authorization_ttl'] = config('default-authorization-ttl')

        return ctxt

    ALLOWED_SECURITY_COMPLIANCE_SCHEMA = {
        'lockout_failure_attempts': int,
        'lockout_duration': int,
        'disable_user_account_days_inactive': int,
        'change_password_upon_first_use': bool,
        'password_expires_days': int,
        'password_regex': str,
        'password_regex_description': str,
        'unique_last_password_count': int,
        'minimum_password_age': int,
    }

    @classmethod
    @cached
    def _decode_password_security_compliance_string(cls, maybe_yaml):
        """Decode string to dict for 'password-security-compliance'

        Perform some validation on the string and return either None,
        if the string is not valid, or a dictionary of the security
        compliance keys and values.

        :param maybe_yaml: the config item that is (hopefully) YAML format
        :type maybe_yaml: str
        :returns: a dictionary of keys: values or None if the value is not
                  valid.
        :rtype: Optional[Dict[str, Union[str, int, bool]]]
        """
        cmp_release = CompareOpenStackReleases(os_release('keystone'))
        if cmp_release < 'newton':
            log("'password-security-compliance' isn't valid for releases "
                "before Newton.",
                level='ERROR')
            return None
        try:
            config_items = yaml.safe_load(maybe_yaml)
        except Exception as e:
            log("Couldn't decode config value for "
                "'password-security-compliance': Invalid YAML?: {}"
                .format(str(e)),
                level='ERROR')
            return None
        # ensure that the top level is a dictionary.
        if type(config_items) != dict:
            log("Couldn't decode config value for "
                "'password-security-compliance'.  It doesn't appear to be a "
                "dictionary: {}".format(str(config_items)),
                level='ERROR')
            return None
        # check that the keys present are valid ones.
        config_keys = config_items.keys()
        allowed_keys = cls.ALLOWED_SECURITY_COMPLIANCE_SCHEMA.keys()
        invalid_keys = [k for k in config_keys if k not in allowed_keys]
        if invalid_keys:
            log("Invalid config key(s) found in config "
                "'password-security-compliance' setting: {}"
                .format(", ".join(invalid_keys)),
                level='ERROR')
            return None
        # check that the types are valid
        valid_types = cls.ALLOWED_SECURITY_COMPLIANCE_SCHEMA
        invalid_types = {k: (type(v) != valid_types[k])
                         for k, v in config_items.items()}
        if any(invalid_types.values()):
            log("Invalid config value type(s) found in config "
                "'password-security-compliance' setting: {}"
                .format(", ".join(["{}: {} -- should be an {}"
                                   .format(k, type(config_items[k]).__name__,
                                           valid_types[k].__name__)
                                   for k, v in invalid_types.items()])),
                level='ERROR')
            return None
        return config_items


class KeystoneLoggingContext(context.OSContextGenerator):

    def __call__(self):
        from keystone_utils import (
            snap_install_requested,
        )
        ctxt = {}
        debug = config('debug')
        if debug:
            ctxt['root_level'] = 'DEBUG'
        log_level = config('log-level')
        log_level_accepted_params = ['WARNING', 'INFO', 'DEBUG', 'ERROR']
        if log_level in log_level_accepted_params:
            ctxt['log_level'] = config('log-level')
        else:
            log("log-level must be one of the following states "
                "(WARNING, INFO, DEBUG, ERROR) keeping the current state.")
            ctxt['log_level'] = None
        if snap_install_requested():
            ctxt['log_file'] = (
                '/var/snap/keystone/common/log/keystone.log')
        else:
            ctxt['log_file'] = '/var/log/keystone/keystone.log'

        return ctxt


class TokenFlushContext(context.OSContextGenerator):

    def __call__(self):
        ctxt = {
            'token_flush': (not fernet_enabled() and is_leader())
        }
        return ctxt


class FernetCronContext(context.OSContextGenerator):

    def __call__(self):
        token_expiration = int(config('token-expiration'))
        ctxt = {
            'enabled': fernet_enabled(),
            'unit_name': local_unit(),
            'charm_dir': charm_dir(),
            'minute': ('*/5' if token_expiration > 300 else '*')
        }
        return ctxt


def fernet_enabled():
    """Helper function for determining whether Fernet tokens are enabled.

    :returns: True if the fernet keys should be configured.
    :rtype: bool
    """
    cmp_release = CompareOpenStackReleases(os_release('keystone'))
    if cmp_release < 'ocata':
        return False
    elif cmp_release >= 'ocata' and cmp_release < 'rocky':
        return config('token-provider') == 'fernet'
    else:
        return True


class KeystoneFIDServiceProviderContext(context.OSContextGenerator):
    interfaces = ['keystone-fid-service-provider']

    def __call__(self):
        fid_sp_keys = ['protocol-name', 'remote-id-attribute']
        fid_sps = []
        for rid in relation_ids("keystone-fid-service-provider"):
            for unit in related_units(rid):
                rdata = relation_get(unit=unit, rid=rid)
                if set(rdata).issuperset(set(fid_sp_keys)):
                    fid_sps.append({
                        k: json.loads(v) for k, v in rdata.items()
                        if k in fid_sp_keys
                    })
        # populate the context with data from one or more
        # service providers
        ctxt = ({'fid_sps': fid_sps}
                if fid_sps else {})
        return ctxt


class WebSSOTrustedDashboardContext(context.OSContextGenerator):
    interfaces = ['websso-trusted-dashboard']

    def __call__(self):
        trusted_dashboard_keys = ['scheme', 'hostname', 'path']
        trusted_dashboards = set()
        for rid in relation_ids("websso-trusted-dashboard"):
            for unit in related_units(rid):
                rdata = relation_get(unit=unit, rid=rid)
                if set(rdata).issuperset(set(trusted_dashboard_keys)):
                    scheme = rdata.get('scheme')
                    hostname = rdata.get('hostname')
                    path = rdata.get('path')
                    url = '{}{}{}'.format(scheme, hostname, path)
                    trusted_dashboards.add(url)
        # populate the context with data from one or more
        # service providers
        ctxt = ({'trusted_dashboards': trusted_dashboards}
                if trusted_dashboards else {})
        return ctxt


class AuthMethods(context.OSContextGenerator):

    auth_methods = ["external", "password", "token", "oauth1",
                    "openid", "totp", "application_credential"]

    def __call__(self):

        _external = "external"
        for rid in relation_ids("keystone-fid-service-provider"):
            for unit in related_units(rid):
                rdata = relation_get(unit=unit, rid=rid)
                _protocol_name = json.loads(rdata.get('protocol-name', '""'))
                if _protocol_name and _protocol_name not in self.auth_methods:
                    self.auth_methods.append(_protocol_name)
                    # We are federated so remove the external method
                    if _external in self.auth_methods:
                        self.auth_methods.remove(_external)

        ctxt = {"auth_methods": ",".join(self.auth_methods)}
        return ctxt
