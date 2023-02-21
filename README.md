# Overview

The keystone charm deploys [Keystone][upstream-keystone], the core OpenStack
service that provides API client authentication, service discovery, and
distributed multi-tenant authorization. The charm works alongside other
Juju-deployed OpenStack services.

# Usage

## Configuration

This section covers common and/or important configuration options. See file
`config.yaml` for the full list of options, along with their descriptions and
default values. See the [Juju documentation][juju-docs-config-apps] for details
on configuring applications.

#### `openstack-origin`

The `openstack-origin` option states the software sources. A common value is an
OpenStack UCA release (e.g. 'cloud:bionic-ussuri' or 'cloud:focal-victoria').
See [Ubuntu Cloud Archive][wiki-uca]. The underlying host's existing apt
sources will be used if this option is not specified (this behaviour can be
explicitly chosen by using the value of 'distro').

## Deployment

Keystone is often containerised. Here a single unit is deployed to a new
container on machine '1':

    juju deploy --to lxd:1 keystone

Now connect the keystone application to an existing cloud database. The
database application is determined by the series. Prior to focal
[percona-cluster][percona-cluster-charm] is used, otherwise it is
[mysql-innodb-cluster][mysql-innodb-cluster-charm]. In the example deployment
below mysql-innodb-cluster has been chosen.

    juju deploy mysql-router keystone-mysql-router
    juju add-relation keystone-mysql-router:db-router mysql-innodb-cluster:db-router
    juju add-relation keystone-mysql-router:shared-db keystone:shared-db

## Credentials

The `keystone:shared-db` relation added at deployment time stores the Keystone
admin password in the cloud database. By default this password is generated
randomly but, for testing purposes, can be set via the `admin-password`
configuration option. This option can also be used to view and change the
password post-deployment.

## Actions

This section covers Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions keystone`. If the charm is not
deployed then see file `actions.yaml`.

* `openstack-upgrade`
* `pause`
* `resume`
* `security-checklist`
* `get-admin-password`
* `rotate-admin-password`
* `rotate-service-user-password`
* `list-service-usernames`

## High availability

When more than one unit is deployed with the [hacluster][hacluster-charm]
application the charm will bring up an HA active/active cluster.

There are two mutually exclusive high availability options: using virtual IP(s)
or DNS. In both cases the hacluster subordinate charm is used to provide the
Corosync and Pacemaker backend HA functionality.

See [OpenStack high availability][cdg-ha-apps] in the [OpenStack Charms
Deployment Guide][cdg] for details.

## TLS

Communication between Keystone and cloud services (as well as the OpenStack
client) can be encrypted with TLS. Keystone also publishes API endpoints for
the cloud (e.g. cinder, glance, keystone, neutron, nova, and placement), which
may be TLS-based.

There are two methods for managing TLS keys and certificates:

1. with Vault
1. manually (via charm options)

Vault can set up private keys and server certificates for an application. It
can also store a central CA certificate for the cloud. See the
[vault][vault-charm] charm for more information.

Vault is the recommended method and is what will be covered here.

The private key and server certificate (and its signing) are enabled via a
relation made to the vault application:

    juju add-relation keystone:certificates vault:certificates

### Other applications

When Keystone is TLS-enabled every application that talks to Keystone (i.e.
there exists a relation between the two) must be in possession of the signing
CA cert. This is achieved by adding a relation between the application and
Vault. Doing so will also encrypt the application's own endpoint. For example,
the Placement API:

    juju add-relation placement:certificates vault:certificates

Vault will issue certificates to the application and Keystone will update the
corresponding API endpoint from HTTP to HTTPS.

> **Note**: API endpoints can be listed with `openstack catalog list`.

## Spaces

This charm supports the use of Juju Network Spaces, allowing the charm to be
bound to network space configurations managed directly by Juju. This is only
supported with Juju 2.0 and above.

API endpoints can be bound to distinct network spaces supporting the network
separation of public, internal and admin endpoints.

Access to the underlying MySQL instance can also be bound to a specific space
using the shared-db relation.

To use this feature, use the --bind option when deploying the charm:

    juju deploy keystone --bind \
       "public=public-space \
        internal=internal-space \
        admin=admin-space \
        shared-db=internal-space"

Alternatively, these can also be provided as part of a Juju native bundle
configuration:

```yaml
    keystone:
      charm: cs:xenial/keystone
      num_units: 1
      bindings:
        public: public-space
        admin: admin-space
        internal: internal-space
        shared-db: internal-space
```

> **Note**: Spaces must be configured in the underlying provider prior to
  attempting to use them (see [MAAS spaces][maas-docs-spaces]).

> **Note**: Existing deployments using `os\-\*-network` configuration options
  will continue to function; these options are preferred over any network space
  binding provided if set.

## Policy overrides

Policy overrides is an advanced feature that allows an operator to override the
default policy of an OpenStack service. The policies that the service supports,
the defaults it implements in its code, and the defaults that a charm may
include should all be clearly understood before proceeding.

> **Caution**: It is possible to break the system (for tenants and other
  services) if policies are incorrectly applied to the service.

Policy statements are placed in a YAML file. This file (or files) is then (ZIP)
compressed into a single file and used as an application resource. The override
is then enabled via a Boolean charm option.

Here are the essential commands (filenames are arbitrary):

    zip overrides.zip override-file.yaml
    juju attach-resource keystone policyd-override=overrides.zip
    juju config keystone use-policyd-override=true

See [Policy overrides][cdg-policy-overrides] in the [OpenStack Charms
Deployment Guide][cdg] for a thorough treatment of this feature.

## Relations

The charm supports the following relations. They are primarily of use to
developers:

* `identity-admin`: Used by charms to obtain the credentials for the admin
  user. This is intended for charms that automatically provision users,
  tenants, etc.

* `identity-credentials`: Used by charms to obtain Keystone credentials without
  creating a service catalogue entry. Set 'username' only on the relation and
  Keystone will set defaults and return authentication details. Possible
  relation settings:

  * `username`: Username to be created.
  * `project`: Project (tenant) name to be created. Defaults to service's
               project.
  * `requested_roles`: Comma-delimited list of roles to be created.
  * `requested_grants`: Comma-delimited list of roles to be granted. Defaults
                        to Admin role.
  * `domain`: Keystone v3 domain the user will be created in. Defaults to the
              Default domain.

* `identity-notifications`: Used to broadcast messages to services listening on
  the corresponding interface.

* `identity-service`: Used by API endpoints to request an entry in the Keystone
  service catalogue and the endpoint template catalogue.

  > **Note**: The `identity-service` relation is not used by Horizon (see
    `keystone-service` instead).

  When a relation is established Keystone receives the following data from the
  requesting API endpoint:

  * `service_name`
  * `region`
  * `public_url`
  * `admin_url`
  * `internal_url`

  Keystone verifies that the requested service is supported (the list of
  supported services should remain updated). The following will occur for a
  supported service:

  1. an entry in the service catalogue is created
  1. an endpoint template is created
  1. an admin token is generated.

  The API endpoint receives the token and is informed of the ports that
  Keystone is listening on.

* `keystone-service`: Used only by Horizon. Horizon requests its configured
  default role and Keystone responds with a token. Horizon also receives the
  authentication and admin ports on which Keystone is listening.

* `nrpe-external-master`: Used to generate Nagios checks.

## Further resources

The below topics are covered in the [OpenStack Charms Deployment Guide][cdg].

* [Security compliance][cdg-security-compliance]: Shows how to use the
  `password-security-compliance` charm option to set Keystone's security
  compliance configuration.

* [Token support][cdg-token-support]: Provides a background of Keystone keys
  and tokens. It explains key rotation, and how to use the
  `fernet-max-active-keys` and `token-expiration` charm options.

# Documentation

The OpenStack Charms project maintains two documentation guides:

* [OpenStack Charm Guide][cg]: for project information, including development
  and support notes
* [OpenStack Charms Deployment Guide][cdg]: for charm usage information

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-keystone].

<!-- LINKS -->

[hacluster-charm]: https://jaas.ai/hacluster
[vault-charm]: https://jaas.ai/vault
[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[cdg-policy-overrides]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-policy-overrides.html
[lp-bugs-charm-keystone]: https://bugs.launchpad.net/charm-keystone/+filebug
[cdg-ha-apps]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#ha-applications
[upstream-keystone]: https://docs.openstack.org/keystone/latest/
[juju-docs-config-apps]: https://juju.is/docs/configuring-applications
[wiki-uca]: https://wiki.ubuntu.com/OpenStack/CloudArchive
[juju-docs-actions]: https://jaas.ai/docs/actions
[percona-cluster-charm]: https://jaas.ai/percona-cluster
[mysql-innodb-cluster-charm]: https://jaas.ai/mysql-innodb-cluster
[maas-docs-spaces]: https://maas.io/docs/concepts-and-terms#heading--spaces
[cdg-token-support]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/keystone.html#token-support
[cdg-security-compliance]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/keystone.html#security-compliance
