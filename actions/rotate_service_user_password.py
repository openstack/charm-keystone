#!/usr/bin/env python3
#
# Copyright 2023 Canonical Ltd
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
import sys

sys.path.append('.')
sys.path.append('./hooks')

from charmhelpers.core.hookenv import (
    action_fail,
    action_get,
    action_set,
)

import keystone_utils


def rotate_service_user_password_action(args):
    """Rotate the service user's password.

    The parameter must be passed in the service-user parameter.

    :raises: Exception if keystone client cannot update the password
    """
    service_user = action_get("service-user")
    try:
        keystone_utils.rotate_service_user_passwd(service_user)
    except keystone_utils.NotLeaderError as e:
        action_fail(str(e))
    except keystone_utils.InvalidService as e:
        action_fail(str(e))


def list_service_usernames(args):
    """List the service usernames known in this model that can be rotated."""
    usernames = keystone_utils.get_service_usernames()
    action_set({'usernames': ','.join(usernames)})


ACTIONS = {
    "rotate-service-user-password": rotate_service_user_password_action,
    "list-service-usernames": list_service_usernames,
}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action {} undefined".format(action_name)
    else:
        try:
            action(args)
        except Exception as e:
            action_fail("Action {} failed: {}".format(action_name, str(e)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
