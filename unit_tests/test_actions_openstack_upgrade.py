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

from unittest.mock import patch
import os

os.environ['JUJU_UNIT_NAME'] = 'keystone'

with patch('charmhelpers.contrib.openstack.utils'
           '.snap_install_requested') as snap_install_requested:
    snap_install_requested.return_value = False
    import openstack_upgrade as openstack_upgrade

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'do_openstack_upgrade',
    'os',
]


class TestKeystoneUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestKeystoneUpgradeActions, self).setUp(openstack_upgrade,
                                                      TO_PATCH)

    # NOTE(ajkavangh) patching charmhelpers here almost certainly means that
    # these tests are in the wrong place and should be moved.  In general
    # tests should only patch objects IN the file under test.  Anywhere else
    # creates dependencies that make the code harder to maintain (e.g. here,
    # changes to charmhelpers might break these tests).
    @patch.object(openstack_upgrade, 'register_configs')
    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_true(self, upgrade_avail,
                                    action_set, config, reg_configs):
        upgrade_avail.return_value = True
        config.return_value = True

        openstack_upgrade.openstack_upgrade()

        self.assertTrue(self.do_openstack_upgrade.called)
        self.os.execl.assert_called_with('./hooks/config-changed-postupgrade',
                                         'config-changed-postupgrade')

    @patch.object(openstack_upgrade, 'register_configs')
    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_false(self, upgrade_avail,
                                     action_set, config, reg_configs):
        upgrade_avail.return_value = True
        config.return_value = False

        openstack_upgrade.openstack_upgrade()

        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(self.os.execl.called)
