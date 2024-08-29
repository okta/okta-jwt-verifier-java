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
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Header
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.SigningKeyResolver
import io.jsonwebtoken.impl.DefaultJwtBuilder
import io.jsonwebtoken.io.Encoders
import org.testng.annotations.DataProvider
import org.testng.annotations.Test

import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyPair
import java.time.Instant
import java.time.temporal.ChronoUnit

import static com.okta.jwt.impl.TestUtil.expect
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.notNullValue
import static org.mockito.ArgumentMatchers.any
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.verify
import static org.mockito.Mockito.verifyNoMoreInteractions
import static org.mockito.Mockito.when

abstract class TokenVerifierTestSupport {

    public final static String TEST_PUB_KEY_ID = "TEST_PUB_KEY_ID"
    public final static String TEST_ISSUER = "https://test.example.com/issuer"
    public final static KeyPair TEST_KEY_PAIR = TestUtil.generateRsaKeyPair(2048)
    public final static KeyPair ORG_KEY_PAIR = TestUtil.generateRsaKeyPair(2048)
    protected SigningKeyResolver signingKeyResolver

    TokenVerifierTestSupport() {
        // Mockito string arg matching wasn't working so just stub the object directly
        // caused by some groovy issue arg matching issue i think
        signingKeyResolver = new SigningKeyResolver() {
            @Override
            Key resolveSigningKey(JwsHeader header, Claims claims) {
                return TEST_KEY_PAIR.getPublic()
            }

            @Override
            Key resolveSigningKey(JwsHeader header, byte[] bytes) {
                return TEST_KEY_PAIR.getPublic()
            }
        }
    }

    abstract Jwt decodeToken(String token, SigningKeyResolver signingKeyResolver)
    abstract Jwt buildThenDecodeToken(JwtBuilder jwtBuilder, SigningKeyResolver signingKeyResolver)
    abstract byte[] defaultFudgedBody()

    // default method args do not work when compiling from the command line, not sure why
    Jwt decodeToken(String token) {
        return decodeToken(token, this.signingKeyResolver)
    }

    Jwt buildThenDecodeToken(JwtBuilder jwtBuilder) {
        return buildThenDecodeToken(jwtBuilder, this.signingKeyResolver)
    }

    JwtBuilder baseJwtBuilder() {
        Instant now = Instant.now()
        return Jwts.builder()
                .subject("joe.coder@example.com")
                .issuer(TEST_ISSUER)
                .issuedAt(Date.from(now))
                .notBefore(Date.from(now))
                .header().add("kid", TEST_PUB_KEY_ID).and()
                .expiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
    }

    @Test
    void missingIssuerClaim() {
        expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .issuer(null))
        }
    }

    @Test(dataProvider = "invalidIssuers")
    void invalidIssuersTest(Object issuer) {
        expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("iss", issuer))
        }
    }

    @Test
    void invalidAlg() {
        def token = baseJwtBuilder()
                .signWith(TEST_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS384)
                .compact()

        expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void noneAlgoTest() {
        def token = buildJwtWithFudgedHeader('{"alg": "none"}')

        expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void nullAudienceTest() {
        expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("aud", null))
        }
    }

    @Test
    void nullAlg() {
        def token = buildJwtWithFudgedHeader('{"kid": "' + TEST_PUB_KEY_ID + '"}')

        expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void duplicateAlgRsaAndNone() {
        def token = buildJwtWithFudgedHeader('{"kid": "' + TEST_PUB_KEY_ID + '", "alg": "RS256", "alg": "none"}')

        expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void jkuNotUsedTest() {

        def signingKeyResolver = mock(SigningKeyResolver)
        when(signingKeyResolver.resolveSigningKey(any(Header) as JwsHeader, any(Claims))).thenReturn(TEST_KEY_PAIR.getPublic())

        def jwtBuilder = baseJwtBuilder()
            .setHeaderParam("jku", "http://example.com")

        assertThat buildThenDecodeToken(jwtBuilder, signingKeyResolver), notNullValue()
        verify(signingKeyResolver).resolveSigningKey(any(Header) as JwsHeader, any(Claims))
        verifyNoMoreInteractions(signingKeyResolver)
    }

    @Test
    void noSignature() {
        def jwtBuilder = baseJwtBuilder()
        def token = jwtBuilder.compact()

        expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void bodyIsNotJson() {
        def token = buildJwtWithFudgedHeader('{"kid": "' + TEST_PUB_KEY_ID + '", "alg": "RS256"}', "Some non-JSON string")
        expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void nullToken() {
        expect JwtVerificationException, {
            decodeToken(null)
        }
    }

    @Test(dataProvider = "invalidStringTokens")
    void invalidStringTokensTest(String tokenString) {
        expect JwtVerificationException, {
            decodeToken(tokenString)
        }
    }

    @Test
    void expiredOverLeeway() {
        Instant now = Instant.now()
        expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .expiration(Date.from(now.minus(10L, ChronoUnit.SECONDS))))
        }
    }

    @Test
    void expiredUnderLeeway() {
        Instant now = Instant.now()
        buildThenDecodeToken(baseJwtBuilder()
                .expiration(Date.from(now.minus(8L, ChronoUnit.SECONDS))))
    }


    @Test
    void notBeforeOverLeeway() {
        Instant now = Instant.now()
        expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .notBefore(Date.from(now.plus(11L, ChronoUnit.SECONDS))))
        }
    }

    @Test
    void notBeforeUnderLeeway() {
        Instant now = Instant.now()
        buildThenDecodeToken(baseJwtBuilder()
                .notBefore(Date.from(now.minus(9L, ChronoUnit.SECONDS))))
    }

    @Test
    void oktaOrgIssuerMismatch() {
        def orgIssuer = "https://test.example.com"
        String token = baseJwtBuilder()
            .issuer(orgIssuer)
            .header().add("kid", "OKTA_ORG_KEY").and()
            .signWith(ORG_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)
            .compact()

        def e = expect JwtVerificationException, {decodeToken(token, signingKeyResolver)}
        assertThat e.getMessage(), equalTo("Failed to parse token")
        assertThat e.cause.getMessage(), equalTo("JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.".toString())
    }

    String buildJwtWithFudgedHeader(String headerJson, String body) {
        return buildJwtWithFudgedHeader(headerJson, body.getBytes(StandardCharsets.UTF_8))
    }

    String buildJwtWithFudgedHeader(String headerJson, byte[] bodyBytes = defaultFudgedBody()) {

        JwtBuilder builder = new DefaultJwtBuilder()

        def headerBytes = headerJson.getBytes(StandardCharsets.UTF_8)
        def header = Encoders.BASE64URL.encode(headerBytes)
        def body = Encoders.BASE64URL.encode(bodyBytes)

        def jwt = header + "." + body
        jwt += "." + builder.signWith(TEST_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS256)

        return jwt
    }

    @DataProvider(name = "invalidIssuers")
    Object[][] invalidIssuers() {
        return [
                [TEST_ISSUER + "/"],
                [TEST_ISSUER + "/other-path"],
                ["https://Test.Example.com/Issuer"],
        ]
    }

    @DataProvider(name = "invalidStringTokens")
    Object[][] invalidStringTokens() {
        return [
                [""],
                [" "],
                ["foo"],
                ["foo.bar.fail"],
                [".."],
                ["."],
        ]
    }
}
