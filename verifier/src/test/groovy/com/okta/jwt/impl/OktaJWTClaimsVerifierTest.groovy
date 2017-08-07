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
import com.okta.jwt.JwtVerifier
import com.okta.jwt.TestSupport
import org.testng.annotations.Test

import java.security.NoSuchAlgorithmException
import java.time.Instant

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
                cid: "my_audience",
                iss: "https//example.com/issuer"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience")
        verifier.verify(claimsSet, null)
    }
    @Test
    void basicIdTokenDecodeTest() {

        JWTClaimsSet claimsSet = new JWTClaimsSet(basicValidClaims + [
                aud: ["my_audience"],
                iss: "https//example.com/issuer"
        ])

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience")
        verifier.verify(claimsSet, idTokenContext)
    }


    @Test
    void testNullToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience")

        TestSupport.expect(IllegalArgumentException) {
            verifier.verify(null, null)
        }

        TestSupport.expect(IllegalArgumentException) {
            verifier.verify(null, null)
        }
    }

    @Test
    void testExpiredToken() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicExpiredClaims + [
                cid: "testClient",
                iss: "testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicExpiredClaims + [
                aud: ["testClient"],
                iss: "testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }
    }

    @Test
    void testCreatedFuture() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicFutureClaims + [
                cid: "testClient",
                iss: "testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicFutureClaims + [
                aud: ["testClient"],
                iss: "testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }
    }

    @Test
    void testInvalidClient() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicValidClaims + [
                cid: "invalid_testClient",
                iss: "testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicValidClaims + [
                aud: ["invalid_testClient"],
                iss: "testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }
    }

    @Test
    void testInvalidIssuer() throws NoSuchAlgorithmException, JOSEException, JoseException {

        def verifier = new OktaJWTClaimsVerifier("https//example.com/issuer", "my_audience")

        JWTClaimsSet claimsSetAccess = new JWTClaimsSet(basicValidClaims + [
                cid: "testClient",
                iss: "invalid_testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetAccess, accessTokenContext)
        }

        JWTClaimsSet claimsSetId = new JWTClaimsSet(basicValidClaims + [
                aud: ["testClient"],
                iss: "invalid_testIssuer"
        ])

        TestSupport.expect(BadJWTException) {
            verifier.verify(claimsSetId, idTokenContext)
        }
    }

}
