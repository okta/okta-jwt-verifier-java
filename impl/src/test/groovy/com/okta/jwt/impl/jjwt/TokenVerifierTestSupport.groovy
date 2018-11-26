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
import io.jsonwebtoken.impl.crypto.DefaultJwtSigner
import io.jsonwebtoken.impl.crypto.JwtSigner
import io.jsonwebtoken.io.Encoders
import org.testng.annotations.DataProvider
import org.testng.annotations.Test

import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyPair
import java.time.Instant
import java.time.temporal.ChronoUnit

import static org.hamcrest.MatcherAssert.assertThat
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
            Key resolveSigningKey(JwsHeader header, String plaintext) {
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
                .setSubject("joe.coder@example.com")
                .setIssuer(TEST_ISSUER)
                .setIssuedAt(Date.from(now))
                .setNotBefore(Date.from(now))
                .setExpiration(Date.from(now.plus(1L, ChronoUnit.HOURS)))
                .setHeader(Jwts.jwsHeader()
                .setKeyId(TEST_PUB_KEY_ID))
    }

    @Test
    void missingIssuerClaim() {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .setIssuer(null))
        }
    }

    @Test(dataProvider = "invalidIssuers")
    void invalidIssuersTest(Object issuer) {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("iss", issuer))
        }
    }

    @Test
    void invalidAlg() {
        def token = baseJwtBuilder()
                .signWith(TEST_KEY_PAIR.getPrivate(), SignatureAlgorithm.RS384)
                .compact()

        TestUtil.expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void nullAudienceTest() {
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .claim("aud", null))
        }
    }

    @Test
    void nullAlg() {
        def token = buildJwtWithFudgedHeader('{"kid": "' + TEST_PUB_KEY_ID + '"}')

        TestUtil.expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void duplicateAlgRsaAndNone() {
        def token = buildJwtWithFudgedHeader('{"kid": "' + TEST_PUB_KEY_ID + '", "alg": "RS256", "alg": "none"}')

        TestUtil.expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void jkuNotUsedTest() {

        def signingKeyResolver = mock(SigningKeyResolver)
        when(signingKeyResolver.resolveSigningKey(any(Header), any(Claims))).thenReturn(TEST_KEY_PAIR.getPublic())

        def jwtBuilder = baseJwtBuilder()
            .setHeaderParam("jku", "http://example.com")

        assertThat buildThenDecodeToken(jwtBuilder, signingKeyResolver), notNullValue()
        verify(signingKeyResolver).resolveSigningKey(any(Header), any(Claims))
        verifyNoMoreInteractions(signingKeyResolver)
    }

    @Test
    void noSignature() {
        def jwtBuilder = baseJwtBuilder()
        def token = jwtBuilder.compact()

        TestUtil.expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void bodyIsNotJson() {
        def token = buildJwtWithFudgedHeader('{"kid": "' + TEST_PUB_KEY_ID + '", "alg": "RS256"}', "Some non-JSON string")
        TestUtil.expect JwtVerificationException, {
            decodeToken(token)
        }
    }

    @Test
    void nullToken() {
        TestUtil.expect JwtVerificationException, {
            decodeToken(null)
        }
    }

    @Test(dataProvider = "invalidStringTokens")
    void invalidStringTokensTest(String tokenString) {
        TestUtil.expect JwtVerificationException, {
            decodeToken(tokenString)
        }
    }

    @Test
    void expiredOverLeeway() {
        Instant now = Instant.now()
        TestUtil.expect JwtVerificationException, {
            buildThenDecodeToken(baseJwtBuilder()
                    .setExpiration(Date.from(now.minus(10L, ChronoUnit.SECONDS))))
        }
    }

    @Test
    void expiredUnderLeeway() {
        Instant now = Instant.now()
        buildThenDecodeToken(baseJwtBuilder()
                .setExpiration(Date.from(now.minus(8L, ChronoUnit.SECONDS))))
    }

    String buildJwtWithFudgedHeader(String headerJson, String body) {
        return buildJwtWithFudgedHeader(headerJson, body.getBytes(StandardCharsets.UTF_8))
    }

    String buildJwtWithFudgedHeader(String headerJson, byte[] bodyBytes = defaultFudgedBody()) {

        JwtSigner signer = new DefaultJwtSigner(SignatureAlgorithm.RS256, TEST_KEY_PAIR.getPrivate(), Encoders.BASE64URL)

        def headerBytes = headerJson.getBytes(StandardCharsets.UTF_8)
        def header = Encoders.BASE64URL.encode(headerBytes)
        def body = Encoders.BASE64URL.encode(bodyBytes)

        def jwt = header + "." + body
        jwt += "." + signer.sign(jwt)

        return jwt
    }

    @DataProvider(name = "invalidIssuers")
    Object[][] invalidIssuers() {
        return [
                [TEST_ISSUER + "/"],
                [TEST_ISSUER + "/other-path"],
                ["https://Test.Example.com/Issuer"],
                [true]
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
