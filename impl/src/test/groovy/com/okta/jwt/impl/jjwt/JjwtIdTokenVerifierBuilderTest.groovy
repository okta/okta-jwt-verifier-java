/*
 * Copyright 2018-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.jwt.impl.jjwt

import com.okta.jwt.impl.TestUtil
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.instanceOf
import static org.hamcrest.Matchers.is

class JjwtIdTokenVerifierBuilderTest {

    @Test
    void happyPathTest() {
        def verifier = new JjwtIdTokenVerifierBuilder()
            .setIssuer("https://issuer.example.com")
            .setClientId("foo-clientId")
            .build()

        assertThat verifier.clientId, is("foo-clientId")
        assertThat verifier.issuer, is("https://issuer.example.com")
        assertThat verifier.leeway, is(120L)
        assertThat verifier.keyResolver, instanceOf(RemoteJwkSigningKeyResolver)
        assertThat verifier.keyResolver.jwkUri, is(new URL("https://issuer.example.com/v1/keys"))
    }

    @Test
    void issuer_nullTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtIdTokenVerifierBuilder()
                    .setIssuer(null)
                    .setClientId("foo-clientId")
                    .build()
        }
    }

    @Test
    void clientId_nullTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtIdTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setClientId(null)
                    .build()
        }

        TestUtil.expect IllegalArgumentException, {
            new JjwtIdTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .build()
        }
    }
}
