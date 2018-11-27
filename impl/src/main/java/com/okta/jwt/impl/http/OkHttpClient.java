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

import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.concurrent.TimeUnit;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public class OkHttpClient implements HttpClient {

    private final okhttp3.OkHttpClient client;

    public OkHttpClient(long connectionTimeout, long readTimeout) {

        client = new okhttp3.OkHttpClient.Builder()
                .connectTimeout(connectionTimeout, TimeUnit.MILLISECONDS)
                .readTimeout(readTimeout, TimeUnit.MILLISECONDS)
                .writeTimeout(readTimeout, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(true)
                .build();
    }

    public InputStream get(URL url) throws IOException {

        Response response = client.newCall(new Request.Builder().url(url).build()).execute();

        if (response.isSuccessful()) {
            ResponseBody body = response.body();
            if (body != null) {
                return body.byteStream();
            }
        }

        throw new IOException("GET request to '" + url + "' return invalid status of '" + response.code() + "' or had an empty response body.");
    }
}
