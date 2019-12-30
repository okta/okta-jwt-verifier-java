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
package com.okta.jwt.example;

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.JwtVerifiers;

import java.time.Duration;

/**
 * Example snippets used for this projects README.md.
 * <p>
 * Manually run {@code mvn okta-code-snippet:snip} after changing this file to update the README.md.
 */
@SuppressWarnings({"unused"})
public class ReadmeSnippets {

    private void basicUsage() {
        AccessTokenVerifier jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
            .setIssuer("https://{yourOktaDomain}/oauth2/default")
            .setAudience("api://default")                   // defaults to 'api://default'
            .setConnectionTimeout(Duration.ofSeconds(1))    // defaults to 1s
            .setMaxHttpRetryAttempts(3)                     // defaults to 3
            .setMaxHttpRetryElapsed(Duration.ofSeconds(10)) // defaults to 10s
            .build();
    }
}