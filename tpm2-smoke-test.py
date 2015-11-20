#! /usr/bin/env python
# Copyright (c) 2015, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Intel Corporation nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from argparse import ArgumentParser
from argparse import FileType
import os
import sys
import tpm2
from tpm2 import ProtocolError
import unittest
from subprocess import check_output


class SmokeTest(unittest.TestCase):
    def setUp(self):
        self.root_key = tpm2.create_root_key()

    def tearDown(self):
        tpm2.flush_context(self.root_key)

    def test_seal_with_auth(self):
        data = 'X' * 64
        auth = 'A' * 15

        blob = tpm2.seal(self.root_key, data, auth, None)
        result = tpm2.unseal(self.root_key, blob, auth, None)
        self.assertEqual(data, result)

    def test_seal_with_policy(self):
        handle = tpm2.start_auth_session(tpm2.TPM2_SE_TRIAL)

        data = 'X' * 64
        auth = 'A' * 15
        pcrs = [16]

        try:
            tpm2.policy_pcr(handle, pcrs)
            tpm2.policy_password(handle)

            policy_dig = tpm2.get_policy_digest(handle)
        finally:
            tpm2.flush_context(handle)

        blob = tpm2.seal(self.root_key, data, auth, policy_dig)

        handle = tpm2.start_auth_session(tpm2.TPM2_SE_POLICY)

        try:
            tpm2.policy_pcr(handle, pcrs)
            tpm2.policy_password(handle)

            result = tpm2.unseal(self.root_key, blob, auth, handle)
        except:
            tpm2.flush_context(handle)
            raise

        self.assertEqual(data, result)

    def test_seal_with_policy_script(self):
        data = 'X' * 32
        auth = '\0' * 20
        pcrs = [16]

        policy_dig = check_output('./tpm2-pcr-policy --pcr=16 --name-alg=sha1 --bank=sha1 --trial'.split()).rstrip().decode('hex')
        blob = tpm2.seal(self.root_key, data, auth, policy_dig)

        handle = check_output('./tpm2-pcr-policy --pcr=16 --name-alg=sha1 --bank=sha1'.split()).rstrip()
        handle = int(handle, 0)

        try:
            result = tpm2.unseal(self.root_key, blob, auth, handle)
        except:
            tpm2.flush_context(handle)
            raise

        self.assertEqual(data, result)


    def test_unseal_with_wrong_auth(self):
        data = 'X' * 64
        auth = 'A' * 20
        rc = 0

        blob = tpm2.seal(self.root_key, data, auth, None)
        try:
            result = tpm2.unseal(self.root_key, blob, auth[:-1] + 'B', None)
        except ProtocolError, e:
            rc = e.rc

        self.assertEqual(e.rc, tpm2.TPM2_RC_AUTH_FAIL)

    def test_unseal_with_wrong_policy(self):
        handle = tpm2.start_auth_session(tpm2.TPM2_SE_TRIAL)

        data = 'X' * 64
        auth = 'A' * 17
        pcrs = [16]

        try:
            tpm2.policy_pcr(handle, pcrs)
            tpm2.policy_password(handle)

            policy_dig = tpm2.get_policy_digest(handle)
        finally:
            tpm2.flush_context(handle)

        blob = tpm2.seal(self.root_key, data, auth, policy_dig)

        # Extend first a PCR that is not part of the policy and try to unseal.
        # This should succeed.

        ds = tpm2.get_digest_size(tpm2.TPM2_ALG_SHA1)
        tpm2.extend_pcr(1, 'X' * ds)

        handle = tpm2.start_auth_session(tpm2.TPM2_SE_POLICY)

        try:
            tpm2.policy_pcr(handle, pcrs)
            tpm2.policy_password(handle)

            result = tpm2.unseal(self.root_key, blob, auth, handle)
        except:
            tpm2.flush_context(handle)
            raise

        self.assertEqual(data, result)

        # Then, extend a PCR that is part of the policy and try to unseal.
        # This should fail.
        tpm2.extend_pcr(16, 'X' * ds)

        handle = tpm2.start_auth_session(tpm2.TPM2_SE_POLICY)

        rc = 0

        try:
            tpm2.policy_pcr(handle, pcrs)
            tpm2.policy_password(handle)

            result = tpm2.unseal(self.root_key, blob, auth, handle)
        except ProtocolError, e:
            rc = e.rc
            tpm2.flush_context(handle)
        except:
            tpm2.flush_context(handle)
            raise

        self.assertEqual(e.rc, tpm2.TPM2_RC_POLICY_FAIL)

    def test_seal_with_too_long_auth(self):
        ds = tpm2.get_digest_size(tpm2.TPM2_ALG_SHA1)
        data = 'X' * 64
        auth = 'A' * (ds + 1)

        rc = 0
        try:
            blob = tpm2.seal(self.root_key, data, auth, None)
        except ProtocolError, e:
            rc = e.rc

        self.assertEqual(e.rc, tpm2.TPM2_RC_SIZE)


def main():
    parser = ArgumentParser(description='Create a storage root key')
    parser.add_argument('--debug',
                        action='store_true',
                        help='dump TPM commands and replies')
    args = parser.parse_args()

    tpm2.debug = args.debug

    try:
        unittest.main()
    except tpm2.ProtocolError, e:
        sys.stderr.write(str(e) + os.linesep)
        sys.exit(1)


if __name__ == '__main__':
    main()
