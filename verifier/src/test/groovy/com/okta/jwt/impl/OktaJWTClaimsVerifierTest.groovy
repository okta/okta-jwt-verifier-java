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

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.proc.SimpleSecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.BadJWTException
import com.okta.jwt.JoseException
import org.testng.annotations.Test

import java.security.NoSuchAlgorithmException
import java.time.Instant
import static com.okta.jwt.TestSupport.*
import static org.hamcrest.Matchers.*

class OktaJWTClaimsVerifierTest {

    private int clockSkewOffset = 65 * 1000 // default skew is 60 seconds

    private final def basicValidClaims = [
            exp: Instant.now().epochSecond + 10000,
            nbf: Instant.now().epochSecond,
            iat: Instant.now().epochSecond
    ]

    private final def basicExpiredClaims = [
            exp: Instant.now().epochSecond - clockSkewOffset,
            iat: Instant.now().epochSecond
    ]

    private final def basicFutureClaims = [
            exp: Instant.now().epochSecond + clockSkewOffset + 10000,
            iat: Instant.now().epochSecond + clockSkewOffset,
            nbf: Instant.now().epochSecond + clockSkewOffset,
    ]

    private final SimpleSecurityContext idTokenContext = new SimpleSecurityContext() + [token_type: 'id_token']
    private final SimpleSecurityContext accessTokenContext = new SimpleSecurityContext() + [token_type: 'access_token']

    @Test
    void basicAccessTokenDecodeTest() {

        JWTClaimsSet claimsSet = new JWTClaimsSet(basicValidClaims + [
                aud: ["my_audience"],
                iss: "https//example.com/issuer"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")
        verifier.verify(claimsSet, null)
    }

    @Test
    void missingTokenTypeInContextDecodeTest() {

        JWTClaimsSet claimsSet = new JWTClaimsSet(basicValidClaims + [
                aud: ["my_audience"],
                iss: "https//example.com/issuer"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")
        verifier.verify(claimsSet, new SimpleSecurityContext())
    }

    @Test
    void basicIdTokenDecodeTest() {

        JWTClaimsSet claimsSet = new JWTClaimsSet(basicValidClaims + [
                aud: ["my_clientId"],
                iss: "https//example.com/issuer",
                sub: "joe.coder@exapmle.com"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")
        verifier.verify(claimsSet, idTokenContext)
    }


    @Test
    void testNullToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")

        expect(IllegalArgumentException) {
            verifier.verify(null, null)
        }

        expect(IllegalArgumentException) {
            verifier.verify(null, null)
        }
    }

    @Test
    void testExpiredToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicExpiredClaims + [
                cid: "testClient",
                iss: "testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicExpiredClaims + [
                aud: ["testClient"],
                iss: "testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }
    }

    @Test
    void testCreatedFuture() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicFutureClaims + [
                cid: "testClient",
                iss: "testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicFutureClaims + [
                aud: ["testClient"],
                iss: "testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }
    }

    @Test
    void testInvalidClient() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicValidClaims + [
                cid: "invalid_testClient",
                iss: "testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicValidClaims + [
                aud: ["invalid_testClient"],
                iss: "testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }

        claimsSetId = new JWTClaimsSet(basicValidClaims + [
                aud: [],
                iss: "testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }

    }

    @Test
    void testInvalidIssuer() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicValidClaims + [
                cid: "testClient",
                iss: "invalid_testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicValidClaims + [
                aud: ["testClient"],
                iss: "invalid_testIssuer"
        ])

        expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }
    }

    @Test
    void IdTokenDecodeNoSubjectTest() {

        JWTClaimsSet claimsSet = new JWTClaimsSet(basicValidClaims + [
                aud: ["my_clientId"],
                iss: "https//example.com/issuer"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")
        expect(BadJWTException) {
            verifier.verify(claimsSet, idTokenContext)
        }
    }

    @Test
    void IdTokenDecodeNonceTest() {
        JWTClaimsSet claimsSet = new JWTClaimsSet(basicValidClaims + [
                aud: ["my_clientId"],
                iss: "https//example.com/issuer",
                sub: "joe.coder@example.com",
                nonce: "invalid_nonce"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")
        expect(BadJWTException, startsWith("Invalid nonce found in ID Token")) {
            verifier.verify(claimsSet, idTokenContext + [nonce: "a_nonce"])
        }
    }

    @Test
    void invalidTokenTypeTest() {
        JWTClaimsSet claimsSet = new JWTClaimsSet(basicValidClaims + [
                aud: ["my_clientId"],
                iss: "https//example.com/issuer",
                sub: "joe.coder@example.com"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience", "my_clientId")
        expect(BadJWTException) {
            verifier.verify(claimsSet, new SimpleSecurityContext() + [token_type: 'unknown'])
        }
    }
}