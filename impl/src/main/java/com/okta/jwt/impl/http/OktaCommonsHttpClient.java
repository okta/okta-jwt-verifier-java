/*
 * Copyright 2019-Present Okta, Inc.
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
package com.okta.jwt.impl.http;

import com.okta.commons.http.DefaultRequest;
import com.okta.commons.http.HttpHeaders;
import com.okta.commons.http.HttpMethod;
import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.RequestExecutorFactory;
import com.okta.commons.http.Response;
import com.okta.commons.http.config.HttpClientConfiguration;
import com.okta.commons.lang.ApplicationInfo;
import com.okta.commons.lang.Classes;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.stream.Collectors;

import static com.okta.commons.http.HttpHeaders.USER_AGENT;

public class OktaCommonsHttpClient implements HttpClient {
    private static final String USER_AGENT_VALUE = ApplicationInfo.get().entrySet().stream()
            .map(entry -> entry.getKey() + "/" + entry.getValue())
            .collect(Collectors.joining(" "));

    private final RequestExecutor requestExecutor;

    protected OktaCommonsHttpClient(RequestExecutor requestExecutor) {
        this.requestExecutor = requestExecutor;
    }

    public OktaCommonsHttpClient(HttpClientConfiguration httpClientConfiguration) {
        this.requestExecutor = createRequestExecutor(httpClientConfiguration);
    }

    @Override
    public InputStream get(URL url) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.add(USER_AGENT, USER_AGENT_VALUE);
        Response response = requestExecutor.executeRequest(new DefaultRequest(HttpMethod.GET, url.toExternalForm(), null, headers));

        if (response.getHttpStatus() != 200) {
            throw new IOException("GET request to '" + url + "' failed with status of: " + response.getHttpStatus());
        }
        return response.getBody();
    }

    private static RequestExecutor createRequestExecutor(HttpClientConfiguration httpClientConfiguration) {

        String msg = "Unable to find a '" + RequestExecutorFactory.class.getName() + "' " +
                "implementation on the classpath.  Please ensure you have added the " +
                "okta-http-okhttp.jar file to your runtime classpath.";
        return Classes.loadFromService(RequestExecutorFactory.class, msg).create(httpClientConfiguration);
    }
}
