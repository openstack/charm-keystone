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

from unittest import mock
from unittest.mock import patch

from test_utils import CharmTestCase

with patch('charmhelpers.contrib.openstack.utils.'
           'snap_install_requested') as snap_install_requested, \
        patch('keystone_utils.register_configs') as configs, \
        patch('keystone_utils.restart_map'), \
        patch('keystone_utils.run_in_apache') as mock_run_in_apache:
    snap_install_requested.return_value = False
    configs.return_value = 'test-config'
    mock_run_in_apache.return_value = True
    import actions.actions


class ChangeAdminPasswordTestCase(CharmTestCase):

    def setUp(self):
        super(ChangeAdminPasswordTestCase, self).setUp(
            actions.actions, ["rotate_admin_passwd"])

    def test_rotate_admin_password(self):
        actions.actions.rotate_admin_password([])
        self.rotate_admin_passwd.assert_called_once()


class PauseTestCase(CharmTestCase):

    def setUp(self):
        super(PauseTestCase, self).setUp(
            actions.actions, ["pause_unit_helper"])

    def test_pauses_services(self):
        actions.actions.pause([])
        self.pause_unit_helper.assert_called_once_with('test-config')


class ResumeTestCase(CharmTestCase):

    def setUp(self):
        super(ResumeTestCase, self).setUp(
            actions.actions,
            ["resume_unit_helper", "update_all_domain_backends"])

    def test_pauses_services(self):
        actions.actions.resume([])
        self.resume_unit_helper.assert_called_once_with('test-config')

    def test_reconciles_domain_backends_after_resuming(self):
        # A domain-backend reconciliation deferred while paused (LP:
        # #2012647) must be completed once the unit is resumed.
        actions.actions.resume([])
        self.resume_unit_helper.assert_called_once_with('test-config')
        self.update_all_domain_backends.assert_called_once_with()

    def test_domain_backend_reconciliation_runs_after_services_resumed(self):
        # the reconciliation call must happen only after resume_unit_helper()
        # has returned (after the unit is no longer marked paused), not
        # concurrently with or before resume
        call_order = []
        self.resume_unit_helper.side_effect = (
            lambda *a, **k: call_order.append('resume_unit_helper'))
        self.update_all_domain_backends.side_effect = (
            lambda *a, **k: call_order.append('update_all_domain_backends'))

        actions.actions.resume([])

        self.assertEqual(
            call_order, ['resume_unit_helper', 'update_all_domain_backends'])


class MainTestCase(CharmTestCase):

    def setUp(self):
        super(MainTestCase, self).setUp(actions.actions, ["action_fail"])

    def test_invokes_action(self):
        dummy_calls = []

        def dummy_action(args):
            dummy_calls.append(True)

        with mock.patch.dict(actions.actions.ACTIONS, {"foo": dummy_action}):
            actions.actions.main(["foo"])
        self.assertEqual(dummy_calls, [True])

    def test_unknown_action(self):
        """Unknown actions aren't a traceback."""
        exit_string = actions.actions.main(["foo"])
        self.assertEqual("Action foo undefined", exit_string)

    def test_failing_action(self):
        """Actions which traceback trigger action_fail() calls."""
        dummy_calls = []

        self.action_fail.side_effect = dummy_calls.append

        def dummy_action(args):
            raise ValueError("uh oh")

        with mock.patch.dict(actions.actions.ACTIONS, {"foo": dummy_action}):
            actions.actions.main(["foo"])
        self.assertEqual(dummy_calls, ["uh oh"])
