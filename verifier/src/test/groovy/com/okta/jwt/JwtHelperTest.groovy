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
package com.okta.jwt

import com.okta.jwt.impl.NimbusJwtVerifier
import com.okta.jwt.impl.OktaJWTClaimsVerifier
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.testng.annotations.Test

import static com.okta.jwt.TestSupport.*

import static org.mockito.Mockito.*
import static org.hamcrest.Matchers.*
import static org.hamcrest.MatcherAssert.*

class JwtHelperTest {

    @Test
    void basicBuildTest() {
        def helper = spy(new JwtHelper())

        // when getResource is called, replace it with a call to get a static file
        doAnswer(new Answer<Object>() {
            @Override
            Object answer(InvocationOnMock invocation) throws Throwable {
                invocation.arguments[0] = JwtHelperTest.getResource("/mock-well-known.json")
                return invocation.callRealMethod()
            }
        }).when(helper).readMetadataFromUrl(any(URL))

        expect(IllegalArgumentException) {
            helper.build()
        }

        helper.setClientOrAudience("my_audience")
        expect(IllegalArgumentException) {
            helper.build()
        }

        helper.setClientOrAudience(null)
        helper.setIssuerUrl("http://example.com/issuer")
        expect(IllegalArgumentException) {
            helper.build()
        }

        helper.setClientOrAudience("my_audience")
        helper.setIssuerUrl("http://example.com/issuer")
        JwtVerifier verifier = helper.build()

        assertThat(verifier, allOf(
                notNullValue(),
                instanceOf(NimbusJwtVerifier)
        ))

        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier(), allOf(
                notNullValue(),
                instanceOf(OktaJWTClaimsVerifier)
        ))

        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier().clientOrAudience, equalTo("my_audience"))
        assertThat(verifier.jwtProcessor.getJWTClaimsSetVerifier().issuer, equalTo("http://example.com/issuer"))
    }
}