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
package com.okta.jwt.impl

import com.okta.jwt.Jwt
import org.testng.annotations.Test

import java.time.Instant

import static com.okta.jwt.TestSupport.*
import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.*

class DefaultJwtTest {

    @Test
    void testConstructorValidation() {

        String tokenValue = "token_string.no.validation"
        Instant issuedAt = Instant.now()
        Instant expiresAt = Instant.MAX
        Map<String, Object> claims = new HashMap<>()
        claims.put("foo", "bar")

        // valid
        Jwt jwt = new DefaultJwt(tokenValue, issuedAt, expiresAt, claims)
        assertThat(jwt.claims, equalTo(claims))
        assertThat(jwt.issuedAt, equalTo(issuedAt))
        assertThat(jwt.expiresAt, equalTo(expiresAt))
        assertThat(jwt.tokenValue, equalTo(tokenValue))

        expect(IllegalArgumentException) {
            new DefaultJwt(tokenValue, issuedAt, expiresAt, null)
        }

        expect(IllegalArgumentException) {
            new DefaultJwt(tokenValue, issuedAt, expiresAt, Collections.emptyMap())
        }

        expect(IllegalArgumentException) {
            new DefaultJwt(tokenValue, issuedAt, null, claims)
        }

        expect(IllegalArgumentException) {
            new DefaultJwt(tokenValue, null, expiresAt, claims)
        }

        expect(IllegalArgumentException) {
            new DefaultJwt(null, issuedAt, expiresAt, claims)
        }
    }
}