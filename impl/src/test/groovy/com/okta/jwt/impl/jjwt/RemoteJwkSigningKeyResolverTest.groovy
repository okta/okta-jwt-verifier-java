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

    @Test
    void symmetricKeyHS512Test() {

        def url = new URL("https://keys.example.com")
        def jwsHeader1 = mock(JwsHeader)
        def jwsHeader2 = mock(JwsHeader)
        def httpClient = mock(HttpClient)

        // Create a JSON with HS512 and RSA keys inline
        def jsonContent = '''
        {
          "keys": [
            {
              "kty": "oct",
              "alg": "HS512",
              "kid": "symmetric-key-one",
              "use": "sig",
              "k": "AyM32w-QxZP2W1TYZlOJSlnNcKVgaXxD5xFv-VSb0MZ-dHm9qyG_lh-AZyYl6cAVwSxnRSRnGI2WsFdI4PA8bwIeGQ4OIJt8RrBzXLI8M8fYjzrGbS9LAf8Vb0RQ8eeJPJnDrJLPV-mjMPCPfQJpKJuVA9Qeg"
            },
            {
              "kty": "RSA",
              "alg": "RS256",
              "kid": "rsa-key-one",
              "use": "sig",
              "e": "AQAB",
              "n": "7KjRGKEcR4Uizgc90GxgblqjLegbWCJyc7WF3vKGOcwazfZxMDryGU0BtYAKAe-HBZhu471r1jj8UXB_8GE7wVXMcDWLno89HkkW3feGss31qwVw6YiqFvV1LHm9Y57lyIBaKsnItIusBrI6NWoaDe6AuKm3WCX2sLrDixKzKsg4uPgtvMI4YFl7-ov2UKSAI2YqVmdOg2V9LxhKJU8GwyO0CjQWc4JoGV4U7HHhQHOihOsQ1ErrdEBuHxPq7rcQG229S8Qe-aSIDf5L4PPMnBYdCRPSWPWN8YiPXx85aXpVoEJRdlYOsgTxalFFh-ANSjwk0PbgqBWrLwBCZVLprQ"
            }
          ]
        }
        '''
        when(httpClient.get(url)).thenReturn(new ByteArrayInputStream(jsonContent.getBytes("UTF-8")))
        when(jwsHeader1.getKeyId()).thenReturn("symmetric-key-one")
        when(jwsHeader2.getKeyId()).thenReturn("rsa-key-one")

        def underTest = new RemoteJwkSigningKeyResolver(url, httpClient)
        
        // Verify symmetric key (HS512)
        def result = underTest.resolveSigningKey(jwsHeader1, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("HmacSHA512")

        // Verify RSA key still works
        result = underTest.resolveSigningKey(jwsHeader2, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("RSA")

        verify(httpClient, times(1)).get(any(URL))
        verifyNoMoreInteractions(httpClient)
    }

    @Test
    void symmetricKeyHS256Test() {

        def url = new URL("https://keys.example.com")
        def jwsHeader = mock(JwsHeader)
        def httpClient = mock(HttpClient)

        // Create a JSON with HS256 key inline
        def jsonContent = '''
        {
          "keys": [
            {
              "kty": "oct",
              "alg": "HS256",
              "kid": "hs256-key",
              "use": "sig",
              "k": "AyM32w-QxZP2W1TYZlOJSlnNcKVgaXxD5xFv-VSb0MZ"
            }
          ]
        }
        '''
        when(httpClient.get(url)).thenReturn(new ByteArrayInputStream(jsonContent.getBytes("UTF-8")))
        when(jwsHeader.getKeyId()).thenReturn("hs256-key")

        def underTest = new RemoteJwkSigningKeyResolver(url, httpClient)
        def result = underTest.resolveSigningKey(jwsHeader, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("HmacSHA256")
    }

    @Test
    void symmetricKeyHS384Test() {

        def url = new URL("https://keys.example.com")
        def jwsHeader = mock(JwsHeader)
        def httpClient = mock(HttpClient)

        // Create a JSON with HS384 key inline
        def jsonContent = '''
        {
          "keys": [
            {
              "kty": "oct",
              "alg": "HS384",
              "kid": "hs384-key",
              "use": "sig",
              "k": "AyM32w-QxZP2W1TYZlOJSlnNcKVgaXxD5xFv-VSb0MZ-dHm9qyG_lh-AZyYl6cAV"
            }
          ]
        }
        '''
        when(httpClient.get(url)).thenReturn(new ByteArrayInputStream(jsonContent.getBytes("UTF-8")))
        when(jwsHeader.getKeyId()).thenReturn("hs384-key")

        def underTest = new RemoteJwkSigningKeyResolver(url, httpClient)
        def result = underTest.resolveSigningKey(jwsHeader, "not.used".getBytes("UTF-8"))
        assertThat result.getAlgorithm(), is("HmacSHA384")
    }
}