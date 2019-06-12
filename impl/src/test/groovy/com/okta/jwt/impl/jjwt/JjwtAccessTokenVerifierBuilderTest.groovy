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
import org.testng.annotations.DataProvider
import org.testng.annotations.Test

import java.time.Duration

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.instanceOf
import static org.hamcrest.Matchers.is

class JjwtAccessTokenVerifierBuilderTest {

    @Test
    void orgIssuerTest() {
        def verifier = new JjwtAccessTokenVerifierBuilder()
            .setIssuer("https://issuer.example.com")
            .setAudience("foo-aud")
            .build()

        assertThat verifier.audience, is("foo-aud")
        assertThat verifier.issuer, is("https://issuer.example.com")
        assertThat verifier.leeway, is(Duration.ofMinutes(2L))
        assertThat verifier.keyResolver, instanceOf(IssuerMatchingSigningKeyResolver)
        assertThat verifier.keyResolver.delegate, instanceOf(RemoteJwkSigningKeyResolver)
        assertThat verifier.keyResolver.delegate.jwkUri, is(new URL("https://issuer.example.com/oauth2/v1/keys"))
    }

    @Test
    void customIssuerTest() {
        def verifier = new JjwtAccessTokenVerifierBuilder()
            .setIssuer("https://issuer.example.com/oauth2/anAsId")
            .setAudience("foo-aud")
            .build()

        assertThat verifier.audience, is("foo-aud")
        assertThat verifier.issuer, is("https://issuer.example.com/oauth2/anAsId")
        assertThat verifier.leeway, is(Duration.ofMinutes(2L))
        assertThat verifier.keyResolver, instanceOf(IssuerMatchingSigningKeyResolver)
        assertThat verifier.keyResolver.delegate, instanceOf(RemoteJwkSigningKeyResolver)
        assertThat verifier.keyResolver.delegate.jwkUri, is(new URL("https://issuer.example.com/oauth2/anAsId/v1/keys"))
    }

    @Test(dataProvider = "validIssuers")
    void formatIssuerTest(String issuer) {
        def verifier = new JjwtAccessTokenVerifierBuilder()
            .setIssuer(issuer)
            .setAudience("foo-aud")
            .build()

        assertThat verifier.issuer, is("https://valid.example.com/oauth2/default")
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

    @Test(dataProvider = "invalidIssuers")
    void invalidIssuersTest(String issuer) {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer(issuer.toString())
                    .build()
        }
    }

    @DataProvider(name = "invalidIssuers")
    Object[][] invalidIssuers() {
        return [
                [""],
                [" "],
                ["not a url"],
                ["http://invalid.example.com/oauth2/default"], //not https
        ]
    }

    @DataProvider(name = "validIssuers")
    Object[][] validIssuers() {
        return [
                ["https://valid.example.com/oauth2/default"],
                [" https://valid.example.com/oauth2/default "],
                ["https://valid.example.com/oauth2/default/"],
                ["https://valid.example.com/oauth2/default/ "],
                [" https://valid.example.com/oauth2/default/ "],
        ]
    }

    @Test
    void audience_nullTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setAudience(null)
                    .build()
        }
    }

    @Test
    void readTimeout_negativeTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setAudience("foo-aud")
                    .setReadTimeout(Duration.ofSeconds(-1L))
                    .build()
        }
    }

    @Test
    void connectionTimeout_negativeTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setAudience("foo-aud")
                    .setConnectionTimeout(Duration.ofSeconds(-1L))
                    .build()
        }
    }

    @Test
    void leeway_negativeTest() {
        TestUtil.expect IllegalArgumentException, {
            new JjwtAccessTokenVerifierBuilder()
                    .setIssuer("https://issuer.example.com")
                    .setAudience("foo-aud")
                    .setLeeway(Duration.ofSeconds(-1L))
                    .build()
        }
    }
}
