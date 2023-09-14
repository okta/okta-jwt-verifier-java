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

/**
 * An AccessTokenVerifier can be used to validate Okta's OAuth 2.0 access tokens client side.  This implementation is
 * Okta specific as the OAuth 2.0 rfc states that access tokens are opaque.  This class is intended to help developer to
 * create OAuth 2.0 Resource Servers.
 *
 * @since 0.4
 * @see <a href="https://www.oauth.com/oauth2-servers/the-resource-server/">OAuth 2.0 Resource Server</a>
 */
public interface AccessTokenVerifier {

    /**
     * Validates the given {@code accessToken}.  Validates this token is valid Okta access token that has not expired.
     *
     * @param accessToken string JWT access token to validate
     * @return a decoded JWT
     * @throws JwtVerificationException when parsing or validation errors occur
     */
    Jwt decode(String accessToken) throws JwtVerificationException;

    /**
     * Builder interface used to simplify construction of a AccessTokenVerifier.
     */
    interface Builder extends VerifierBuilderSupport<Builder, AccessTokenVerifier> {

        /**
         * Sets the audience the verifier will expect.
         * Default implementation, uses "api://default" as the default value.
         * @param audience Audience
         * @return a reference to the current builder for use in method chaining
         */
        Builder setAudience(String audience);
    }
}