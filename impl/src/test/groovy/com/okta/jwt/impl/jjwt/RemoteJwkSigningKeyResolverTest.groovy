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

import com.okta.jwt.impl.TestUtil
import com.okta.jwt.impl.http.HttpClient
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.JwtException
import org.testng.annotations.Test

import java.nio.charset.Charset

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.mockito.ArgumentMatchers.any
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.times
import static org.mockito.Mockito.verify
import static org.mockito.Mockito.verifyNoMoreInteractions
import static org.mockito.Mockito.when

class RemoteJwkSigningKeyResolverTest {

    @Test
    void httpFailureTest() {

        def url = new URL("https://keys.example.com")
        def jwsHeader = mock(JwsHeader)
        def httpClient = mock(HttpClient)

        when(httpClient.get(url)).thenThrow(new IOException("expected in test"))

        def underTest = new RemoteJwkSigningKeyResolver(url, httpClient)
        TestUtil.expect JwtException, { underTest.resolveSigningKey(jwsHeader, "not.used".getBytes("UTF-8"))}
    }

    @Test
    void basicSuccessTest() {

        def url = new URL("https://keys.example.com")
        def jwsHeader1 = mock(JwsHeader)
        def jwsHeader2 = mock(JwsHeader)
        def httpClient = mock(HttpClient)

        when(httpClient.get(url)).thenReturn(getClass().getResourceAsStream("/http/basicSuccessTest.json"))
        when(jwsHeader1.getKeyId()).thenReturn("key-one")
        when(jwsHeader2.getKeyId()).thenReturn("key-two")

        def underTest = new RemoteJwkSigningKeyResolver(url, httpClient)
        def result = underTest.resolveSigningKey(jwsHeader1, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("RSA")

        result = underTest.resolveSigningKey(jwsHeader2, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("RSA")

        verify(httpClient, times(1)).get(any(URL))
        verifyNoMoreInteractions(httpClient)
    }

    @Test
    void refreshKeysTest() {

        def url = new URL("https://keys.example.com")
        def jwsHeader1 = mock(JwsHeader)
        def jwsHeader2 = mock(JwsHeader)
        def httpClient = mock(HttpClient)

        when(httpClient.get(url))
                .thenReturn(getClass().getResourceAsStream("/http/refreshKeysTest-1.json"))
                .thenReturn(getClass().getResourceAsStream("/http/refreshKeysTest-2.json"))
        when(jwsHeader1.getKeyId()).thenReturn("key-one")
        when(jwsHeader2.getKeyId()).thenReturn("key-two")

        def underTest = new RemoteJwkSigningKeyResolver(url, httpClient)
        def result = underTest.resolveSigningKey(jwsHeader1, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("RSA")

        result = underTest.resolveSigningKey(jwsHeader2, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("RSA")

        verify(httpClient, times(2)).get(any(URL))
        verifyNoMoreInteractions(httpClient)
    }
}