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
import com.okta.jwt.Jwt
import com.okta.jwt.JwtVerificationException
import com.okta.jwt.impl.TestUtil
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SigningKeyResolver
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

class JjwtAccessTokenVerifierTest extends TokenVerifierTestSupport {

    final static String TEST_AUDIENCE_ID = "test-aud"

    @Test(dataProvider = "validAudienceIds")
    void validAudienceIds(Object aud) {
        if (aud instanceof Collection) {
            assertValidJwt(baseJwtBuilder()
                    .audience().add(aud).and())
        } else {
            assertValidJwt(baseJwtBuilder()
                    .claim("aud", aud))
        }
    }

    @Test(dataProvider = "invalidAudienceIds")
    void invalidAudienceIds(Object aud) {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("aud", aud))
        }
    }

    @Override
    JwtBuilder baseJwtBuilder() {
        return super.baseJwtBuilder()
                .setAudience(TEST_AUDIENCE_ID)
    }

    @Override
    Jwt buildThenDecodeToken(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver) {
        def token = jwtBuilder
                .signWith(TEST_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)
                .compact()

        return decodeToken(token, signingKeyResolver)
    }

    void assertValidJwt(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver = this.signingKeyResolver) {
        def result = buildThenDecodeToken(jwtBuilder, signingKeyResolver)
        assertThat result.getClaims().get("iss"), is(TEST_ISSUER)

        def aud = result.getClaims().get("aud")
        if (aud instanceof String) {
            assertThat(aud, is(TEST_AUDIENCE_ID))
        } else {
            assertThat((Collection) aud, hasItem(TEST_AUDIENCE_ID))
        }
    }

    @Override
    Jwt decodeToken(String token, SigningKeyResolver signingKeyResolver) {
        return new JjwtAccessTokenVerifier(TEST_ISSUER, TEST_AUDIENCE_ID,  Duration.ofSeconds(10L), signingKeyResolver)
            .decode(token)
    }

    @Override
    byte[] defaultFudgedBody() {
        Serializer serializer = Classes.loadFromService(Serializer)
        Instant now = Instant.now()
        def bodyMap = new HashMap()
        bodyMap.put(DefaultClaims.ISSUER, TEST_ISSUER)
        bodyMap.put(DefaultClaims.AUDIENCE, TEST_AUDIENCE_ID)
        bodyMap.put(DefaultClaims.ISSUED_AT, Date.from(now))
        bodyMap.put(DefaultClaims.NOT_BEFORE, Date.from(now))
        bodyMap.put(DefaultClaims.EXPIRATION, Date.from(now.plus(1L, ChronoUnit.HOURS)))

        return serializer.serialize(bodyMap)
    }

    @DataProvider(name = "invalidAudienceIds")
    Object[][] invalidAudienceIds() {
        return [
                [""],
                [" "],
                ["invalid-aud"],
                [Collections.emptySet()],
                ["Test-Aud"],
        ]
    }

    @DataProvider(name = "validAudienceIds")
    Object[][] validAudienceIds() {
        return [
                [TEST_AUDIENCE_ID],
                [Collections.singleton(TEST_AUDIENCE_ID)],
                [["invalid-clientId", TEST_AUDIENCE_ID]],
        ]
    }
}
