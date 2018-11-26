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

class JjwtAccessTokenVerifierBuilderTest {

    @Test
    void happyPathTest() {
        def verifier = new JjwtAccessTokenVerifierBuilder()
            .setIssuer("https://issuer.example.com")
            .setAudience("foo-aud")
            .build()

        assertThat verifier.audience, is("foo-aud")
        assertThat verifier.issuer, is("https://issuer.example.com")
        assertThat verifier.leeway, is(120L)
        assertThat verifier.keyResolver, instanceOf(RemoteJwkSigningKeyResolver)
        assertThat verifier.keyResolver.jwkUri, is(new URL("https://issuer.example.com/v1/keys")) // TODO this will be wrong when calculating non-default
    }

    @Test
    void issuer_nullTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer(null)
                    .setAudience("foo-aud")
                    .build()
        }
    }

    @Test
    void audience_nullTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .build()
        }
    }

    @Test
    void readTimeout_negativeTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setAudience("foo-aud")
                    .setReadTimeout(-1L)
                    .build()
        }
    }

    @Test
    void connectionTimeout_negativeTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setAudience("foo-aud")
                    .setConnectionTimeout(-1L)
                    .build()
        }
    }

    @Test
    void leeway_negativeTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setAudience("foo-aud")
                    .setLeeway(-1L)
                    .build()
        }
    }
}
