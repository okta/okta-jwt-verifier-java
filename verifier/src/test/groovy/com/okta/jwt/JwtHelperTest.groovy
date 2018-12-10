/*
 * Copyright 2017 Okta, Inc.
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
package com.okta.jwt

import com.okta.jwt.impl.NimbusJwtVerifier
import com.okta.jwt.impl.OktaJWTClaimsVerifier
import org.hamcrest.Matcher
import org.testng.annotations.Test

import static com.okta.jwt.TestSupport.*

import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.*

class JwtHelperTest {

    @Test
    void basicBuildTest() {
        def helper = new JwtHelper()

        helper.setClientId("clientId")
        expect(IllegalArgumentException) {
            helper.build()
        }

        helper.setAudience("my_audience")
        expect(IllegalArgumentException) {
            helper.build()
        }

        helper.setAudience(null)
        helper.setIssuerUrl("https://example.com/oauth2/issuer")
        expect(IllegalArgumentException) {
            helper.build()
        }

        helper.setAudience("my_audience")
        helper.setIssuerUrl("https://example.com/oauth2/issuer")
        JwtVerifier verifier = helper.build()

        assertThat(verifier, allOf(
                notNullValue(),
                instanceOf(NimbusJwtVerifier)
        ))

        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier(), allOf(
                notNullValue(),
                instanceOf(OktaJWTClaimsVerifier)
        ))

        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier().audience, equalTo("my_audience"))
        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier().clientId, equalTo("clientId"))
        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier().issuer, equalTo("https://example.com/oauth2/issuer"))
        assertThat(verifier.jwtProcessor.getJWSKeySelector().getJWKSource().getJWKSetURL().toString(), equalTo("https://example.com/oauth2/issuer/v1/keys"))
        assertConnectionTimeout(verifier, equalTo(1000))
        assertReadTimeout(verifier, equalTo(1000))
    }

    @Test
    void issuerTrailingSlashTest() {
        // the call to setIssuer() strips trailing slashes
        def helper = new JwtHelper()
        helper.setIssuerUrl("https://example.com/oauth2/issuer/")
        JwtVerifier verifier = helper.build()
        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier().issuer, equalTo("https://example.com/oauth2/issuer"))
        assertThat(verifier.jwtProcessor.getJWSKeySelector().getJWKSource().getJWKSetURL().toString(), equalTo("https://example.com/oauth2/issuer/v1/keys"))
    }

    @Test
    void testOrgIssuer() {
        // the call to setIssuer() strips trailing slashes
        def helper = new JwtHelper()
        helper.setIssuerUrl("https://example.com")
        JwtVerifier verifier = helper.build()
        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier().issuer, equalTo("https://example.com"))
        assertThat(verifier.jwtProcessor.getJWSKeySelector().getJWKSource().getJWKSetURL().toString(), equalTo("https://example.com/oauth2/v1/keys"))
    }

    @Test
    void setTimeoutsTest() {
        def helper = new JwtHelper()
        helper.setAudience("my_audience")
        helper.setIssuerUrl("https://example.com/oauth2/issuer")
        helper.setConnectionTimeout(3000)
        helper.setReadTimeout(2500)
        JwtVerifier verifier = helper.build()
        assertConnectionTimeout(verifier, equalTo(3000))
        assertReadTimeout(verifier, equalTo(2500))
    }

    void assertConnectionTimeout(def verifier, Matcher<Integer> matcher) {
        assertThat(verifier.jwtProcessor.jwsKeySelector.getJWKSource().jwkSetRetriever.connectTimeout, matcher)
    }

    void assertReadTimeout(def verifier, Matcher<Integer> matcher) {
        assertThat(verifier.jwtProcessor.jwsKeySelector.getJWKSource().jwkSetRetriever.readTimeout, matcher)
    }
}