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
package com.okta.jwt.it

import com.okta.jwt.AccessTokenVerifier
import com.okta.jwt.JwtVerifiers
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.testng.annotations.Test

import java.time.Instant
import java.time.temporal.ChronoUnit

import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.notNullValue
import static org.junit.Assert.assertThat


class AccessTokenVerifierIT extends KeyServerITSupport {

    @Test
    void keyRotateTest() {

        def server = createMockServer()
        def url = server.url("/oauth2/default").url()

        stubKeyResponse(server, TEST_PUB_KEY_ID_1, TEST_KEY_PAIR_1.getPublic())
        stubKeyResponse(server, TEST_PUB_KEY_ID_2, TEST_KEY_PAIR_2.getPublic())

        Instant now = Instant.now()
        String token1 = Jwts.builder()
                .setAudience("api://default")
                .setSubject("joe.coder@example.com")
                .setIssuer(url.toExternalForm())
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
                .setHeaderParam("kid", TEST_PUB_KEY_ID_1)
                .signWith(TEST_KEY_PAIR_1.getPrivate(), SignatureAlgorithm.RS256)
                .compact()

            String token2 = Jwts.builder()
                .setAudience("api://default")
                .setSubject("joe.coder@example.com")
                .setIssuer(url.toExternalForm())
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
                .setHeaderParam("kid", TEST_PUB_KEY_ID_2)
                .signWith(TEST_KEY_PAIR_2.getPrivate(), SignatureAlgorithm.RS256)
                .compact()

        try {

            AccessTokenVerifier verifier = JwtVerifiers.accessTokenVerifierBuilder()
                    .setIssuer(url.toExternalForm())
                    .build()

            assertThat verifier.decode(token1), notNullValue()
            assertThat server.takeRequest().getPath(), is("/oauth2/default/v1/keys")

            assertThat verifier.decode(token2), notNullValue()
            assertThat server.takeRequest().getPath(), is("/oauth2/default/v1/keys")

        } finally {
            server.shutdown()
        }
    }
}
