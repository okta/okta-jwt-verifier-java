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

import com.okta.commons.lang.Classes
import com.okta.jwt.JwtVerificationException
import com.okta.jwt.impl.TestUtil
import io.jsonwebtoken.*
import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.io.Serializer
import org.testng.annotations.DataProvider
import org.testng.annotations.Test

import java.time.Duration
import java.time.Instant
import java.time.temporal.ChronoUnit

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.is

class JjwtIdTokenVerifierTest extends TokenVerifierTestSupport {

    final static String TEST_CLIENT_ID = "test-clientId"
    final static String TEST_NONCE = "test-nonce"

    @Test(dataProvider = "validClientIds")
    void validClientIdsTest(Object aud) {
        assertValidJwt(baseJwtBuilder()
                .claim("aud", aud))
    }

    @Test(dataProvider = "invalidClientIds")
    void invalidClientIdsTest(Object aud) {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("aud", aud))
        }
    }

    @Test(dataProvider = "invalidNonce")
    void invalidNonceTest(Object nonce) {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("nonce", nonce))
        }
    }

    @Test
    void nullNonceTest() {
        invalidNonceTest(null)
    }

    @Test
    void noNonceExpected() {
        assertValidJwt(baseJwtBuilder()
                    .claim("nonce", null), this.signingKeyResolver, null)
    }

    @Override
    com.okta.jwt.Jwt decodeToken(String token, SigningKeyResolver signingKeyResolver) {
        return decodeToken(token, signingKeyResolver ?: this.signingKeyResolver, TEST_NONCE)
    }

    com.okta.jwt.Jwt decodeToken(String token, SigningKeyResolver signingKeyResolver, String nonce) {

        def verifier = new JjwtIdTokenVerifier(TEST_ISSUER, TEST_CLIENT_ID, Duration.ofSeconds(10L), signingKeyResolver)
        return verifier.decode(token, nonce)
    }

    @Override
    byte[] defaultFudgedBody() {
        Serializer serializer = Classes.loadFromService(Serializer)
        Instant now = Instant.now()
        def bodyMap = new DefaultClaims()
            .setIssuer(TEST_ISSUER)
            .setAudience(TEST_CLIENT_ID)
            .setIssuedAt(Date.from(now))
            .setNotBefore(Date.from(now))
            .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
        bodyMap.put("nonce", TEST_NONCE)

        return serializer.serialize(bodyMap)
    }

    void assertValidJwt(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver = this.signingKeyResolver, String nonce = TEST_NONCE) {
        def result = buildThenDecodeToken(jwtBuilder, signingKeyResolver, nonce)
        assertThat result.getClaims().get("nonce"), is(nonce)
        assertThat result.getClaims().get("iss"), is(TEST_ISSUER)

        def aud = result.getClaims().get("aud")
        if (aud instanceof String) {
            assertThat(aud, is(TEST_CLIENT_ID))
        } else {
            assertThat((Collection) aud, hasItem(TEST_CLIENT_ID))
        }
    }

    com.okta.jwt.Jwt buildThenDecodeToken(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver, String nonce) {

        def token = jwtBuilder
                .signWith(TEST_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)
                .compact()

        return decodeToken(token, signingKeyResolver, nonce)
    }

    @Override
    com.okta.jwt.Jwt buildThenDecodeToken(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver) {
        return buildThenDecodeToken(jwtBuilder, signingKeyResolver ?: this.signingKeyResolver, TEST_NONCE)
    }

    @Override
    JwtBuilder baseJwtBuilder() {
        return super.baseJwtBuilder()
                .setAudience(TEST_CLIENT_ID)
                .claim("nonce", TEST_NONCE)
    }

    @DataProvider(name = "invalidClientIds")
    Object[][] invalidClientIds() {
        return [
                [""],
                [" "],
                ["invalid-clientId"],
                [Collections.emptySet()],
                ["Test-Clientid"],
                [true],
        ]
    }

    @DataProvider(name = "validClientIds")
    Object[][] validClientIds() {
        return [
                [TEST_CLIENT_ID],
                [Collections.singleton(TEST_CLIENT_ID)],
                [["invalid-clientId", TEST_CLIENT_ID]],
        ]
    }

    @DataProvider(name = "invalidNonce")
    Object[][] invalidNonce() {
        return [
                [""],
                [" "],
                [".*"],
                ["some-invalid-nonce"],
                ["Test-Nonce"],
                [true]
        ]
    }

}
