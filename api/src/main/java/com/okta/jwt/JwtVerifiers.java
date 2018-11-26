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
package com.okta.jwt;

import java.util.ServiceLoader;
import java.util.stream.StreamSupport;

/**
 * Utility class to help load implementations of {@link IdTokenVerifier.Builder} and {@link AccessTokenVerifier.Builder}.
 * <p>Example usage:
 *
 * <pre>
 * AccessTokenVerifier jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
 *                                               .setIssuer(issuerUrl)
 *                                               .setAudience(audience)
 *                                               .build();
 * </pre>
 *
 * @since 0.4
 */
public final class JwtVerifiers {

    private JwtVerifiers() {}

    /**
     * Creates an instance of IdTokenVerifier.Builder.
     * @return an instance of IdTokenVerifier.Builder
     */
    public static IdTokenVerifier.Builder idTokenVerifierBuilder() {
        return loadService(IdTokenVerifier.Builder.class);
    }

    /**
     * Creates an instance of AccessTokenVerifier.Builder.
     * @return an instance of AccessTokenVerifier.Builder
     */
    public static AccessTokenVerifier.Builder accessTokenVerifierBuilder() {
        return loadService(AccessTokenVerifier.Builder.class);
    }

    private static <T> T loadService(Class<T> service) {
        ServiceLoader<T> serviceLoader = ServiceLoader.load(service);

        return StreamSupport.stream(serviceLoader.spliterator(), false)
                .reduce((a, b) -> { throw new IllegalStateException("Multiple implementations of `" + service + "` " +
                            "class found on the classpath. There can be only one."); })
                .orElseThrow(() -> new IllegalStateException("No `" + service + "` implementation found on the classpath. " +
                            "Have you remembered to include the okta-jwt-verifier-impl.jar in your runtime classpath?"));
    }
}
