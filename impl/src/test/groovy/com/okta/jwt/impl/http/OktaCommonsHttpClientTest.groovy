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
package com.okta.jwt.impl.http

import com.okta.commons.http.HttpException
import com.okta.commons.http.Request
import com.okta.commons.http.RequestExecutor
import com.okta.commons.http.Response
import com.okta.commons.lang.ApplicationInfo
import com.okta.jwt.RestoreSystemProperties
import org.mockito.Mockito
import org.testng.annotations.Listeners
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.not
import static org.mockito.Mockito.any
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when
import static org.mockito.Mockito.verify
import static org.mockito.Mockito.times

@Listeners(RestoreSystemProperties.class)
class OktaCommonsHttpClientTest {

    def expectedVersion

    OktaCommonsHttpClientTest() {
        Properties props = new Properties()
        props.load(OktaCommonsHttpClientTest.getResourceAsStream("/" + ApplicationInfo.VERSION_FILE_LOCATION))
        expectedVersion = props.getProperty("okta-jwt-verifier-java")
    }

    @Test
    void validateVersionTest() {
        // make sure the version has been filtered
        assertThat expectedVersion, not(containsString('${project.version}'))
    }

    @Test
    void testExecuteRequestSuccess() {
        def url = new URL("https://keys.example.com")
        def requestExecutor = mock(RequestExecutor)
        def oktaCommonsHttpClient = new OktaCommonsHttpClient(requestExecutor)
        def response = mock(Response)

        when(response.getHttpStatus()).thenReturn(200)
        when(response.getBody()).thenReturn(new InputStream() {
            @Override
            int read() throws IOException {
                return -1
            }
        })

        when(requestExecutor.executeRequest(Mockito.any(Request.class)))
                .thenReturn(response)

        oktaCommonsHttpClient.get(url)

        verify(requestExecutor, times(1)).executeRequest(any(Request.class))
        verify(response, times(1)).getHttpStatus()
        verify(response, times(1)).getBody()
    }

    @Test(expectedExceptions = HttpException)
    void testExecuteRequestHttpException() {
        def url = new URL("https://keys.example.com")
        def requestExecutor = mock(RequestExecutor)
        def oktaCommonsHttpClient = new OktaCommonsHttpClient(requestExecutor)

        when(requestExecutor.executeRequest(any(Request.class)))
                .thenThrow(new HttpException("Unable to execute HTTP request"))

        oktaCommonsHttpClient.get(url)
    }

    @Test(expectedExceptions = IOException)
    void testExecuteRequestResponseErrorStatusCode() {
        def url = new URL("https://keys.example.com")
        def requestExecutor = mock(RequestExecutor)
        def oktaCommonsHttpClient = new OktaCommonsHttpClient(requestExecutor)
        def response = mock(Response)

        when(response.getHttpStatus()).thenReturn(429)
        when(requestExecutor.executeRequest(any(Request.class)))
                .thenReturn(response)

        oktaCommonsHttpClient.get(url)
    }
}
