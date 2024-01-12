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
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SigningKeyResolver
import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.io.Serializer
import org.testng.annotations.Test

import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.temporal.ChronoUnit

import static com.okta.jwt.impl.TestUtil.expect

class JjwtAccessTokenVerifierFixedClockTest extends JjwtAccessTokenVerifierTest {
    public final static Clock clock =
            Clock.fixed(Instant.ofEpochSecond(361385454L), ZoneId.systemDefault())

    @Override
    byte[] defaultFudgedBody() {
        Serializer serializer = Classes.loadFromService(Serializer)
        Instant now = clock.instant()
        def bodyMap = new HashMap()
        bodyMap.put(DefaultClaims.ISSUER, TEST_ISSUER)
        bodyMap.put(DefaultClaims.AUDIENCE, TEST_AUDIENCE_ID)
        bodyMap.put(DefaultClaims.ISSUED_AT, Date.from(now))
        bodyMap.put(DefaultClaims.NOT_BEFORE, Date.from(now))
        bodyMap.put(DefaultClaims.EXPIRATION, Date.from(now.plus(1L, ChronoUnit.HOURS)))

        return serializer.serialize(bodyMap)
    }

    @Override
    Jwt decodeToken(String token, SigningKeyResolver signingKeyResolver) {
        JjwtAccessTokenVerifier verifier = new JjwtAccessTokenVerifier(TEST_ISSUER, TEST_AUDIENCE_ID,  Duration.ofSeconds(10L), signingKeyResolver, clock)
        return verifier.decode(token)
    }

    @Override
    JwtBuilder baseJwtBuilder() {
        Instant now = clock.instant()
        return Jwts.builder()
                .subject("joe.coder@example.com")
                .issuer(TEST_ISSUER)
                .setAudience(TEST_AUDIENCE_ID)
                .issuedAt(Date.from(now))
                .notBefore(Date.from(now))
                .expiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
                .setHeaderParam("kid", TEST_PUB_KEY_ID)
    }

    @Test
    void expiredOverLeeway() {
        Instant now = clock.instant()
        expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .setExpiration(Date.from(now.minus(11L, ChronoUnit.SECONDS))))
        }
    }

    @Test
    void expiredUnderLeeway() {
        Instant now = clock.instant()
        buildThenDecodeToken(baseJwtBuilder()
                .setExpiration(Date.from(now.minus(8L, ChronoUnit.SECONDS))))
    }

    @Test
    void notBeforeUnderLeeway() {
        Instant now = clock.instant()
        buildThenDecodeToken(baseJwtBuilder()
                .setNotBefore(Date.from(now.minus(9L, ChronoUnit.SECONDS))))
    }
}
