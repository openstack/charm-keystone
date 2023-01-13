# Copyright 2018 Canonical Ltd
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

import sys

from unittest.mock import patch

from test_utils import CharmTestCase

import fernet_rotate_and_sync as script


class FernetRotateAndSync(CharmTestCase):

    def setUp(self):
        super(FernetRotateAndSync, self).setUp(
            script, [])

    @patch('charmhelpers.core.hookenv.log')
    @patch('time.ctime')
    @patch('builtins.print')
    def test_cli_log(self, mock_print, mock_ctime, mock_ch_log):
        mock_ctime.return_value = 'FAKE_TIMESTAMP'
        script.cli_log('message', level='DEBUG')
        mock_ch_log.assert_called_with('message', level='DEBUG')
        script.cli_log('message', level='WARNING')
        mock_print.assert_called_with('FAKE_TIMESTAMP: message',
                                      file=sys.stderr)
        script.cli_log('message', level='INFO')
        mock_print.assert_called_with('FAKE_TIMESTAMP: message',
                                      file=sys.stdout)
