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
package com.okta.jwt.impl.http;

import com.okta.commons.lang.ApplicationInfo;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public class OkHttpClient implements HttpClient {

    private static final String USER_AGENT = ApplicationInfo.get().entrySet().stream()
            .map(entry -> entry.getKey() + "/" + entry.getValue())
            .collect(Collectors.joining(" "));

    private final okhttp3.OkHttpClient client;

    public OkHttpClient(Duration connectionTimeout, Duration readTimeout) {
        this(connectionTimeout, readTimeout, null, null, null);
    }

    public OkHttpClient(Duration connectionTimeout, Duration readTimeout,
                        SSLSocketFactory sslSocketFactory, X509TrustManager trustManager,
                        HostnameVerifier hostnameVerifier) {

        okhttp3.OkHttpClient.Builder clientBuilder = new okhttp3.OkHttpClient.Builder()
                .connectTimeout(connectionTimeout.toMillis(), TimeUnit.MILLISECONDS)
                .readTimeout(readTimeout.toMillis(), TimeUnit.MILLISECONDS)
                .writeTimeout(readTimeout.toMillis(), TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(true);

        if (sslSocketFactory != null && trustManager != null) {
            clientBuilder.sslSocketFactory(sslSocketFactory, trustManager);
        }
        if (hostnameVerifier != null) {
            clientBuilder.hostnameVerifier(hostnameVerifier);
        }

        client = clientBuilder.build();

    }

    public InputStream get(URL url) throws IOException {

        Response response = client.newCall(new Request.Builder()
                .url(url)
                .header("User-Agent", USER_AGENT)
                .build()).execute();

        if (response.isSuccessful()) {
            ResponseBody body = response.body();
            if (body != null) {
                return body.byteStream();
            }
        }

        throw new IOException("GET request to '" + url + "' return invalid status of '" + response.code() + "' or had an empty response body.");
    }
}
