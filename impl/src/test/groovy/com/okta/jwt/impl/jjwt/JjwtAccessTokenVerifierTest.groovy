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

import com.okta.jwt.Jwt
import com.okta.jwt.JwtVerificationException
import com.okta.jwt.impl.TestUtil
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SigningKeyResolver
import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.io.JacksonSerializer
import org.testng.annotations.DataProvider
import org.testng.annotations.Test

import java.time.Instant
import java.time.temporal.ChronoUnit

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.is

class JjwtAccessTokenVerifierTest extends TokenVerifierTestSupport{

    final static String TEST_AUDIENCE_ID = "test-aud"

    @Test(dataProvider = "validAudienceIds")
    void validAudienceIds(Object aud) {
        assertValidJwt(baseJwtBuilder()
                .claim("aud", aud))
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
        return new JjwtAccessTokenVerifier(TEST_ISSUER, TEST_AUDIENCE_ID, 10L, signingKeyResolver)
            .decode(token)
    }

    @Override
    byte[] defaultFudgedBody() {
        JacksonSerializer serializer = new JacksonSerializer()
        Instant now = Instant.now()
        def bodyMap = new DefaultClaims()
            .setIssuer(TEST_ISSUER)
            .setAudience(TEST_AUDIENCE_ID)
            .setIssuedAt(Date.from(now))
            .setNotBefore(Date.from(now))
            .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))

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
                [true],
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
