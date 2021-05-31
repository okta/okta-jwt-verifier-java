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


public interface IdTokenVerifier {

    /**
     * Validates the given {@code idToken}.  Validates this token is valid Okta id token that has not expired.
     *
     * @param idToken string JWT id token to validate
     * @param nonce ID Token nonce - nullable - it may be available as a cookie when Okta SigIn Widget is used.
     * Always check the request if it contains nonce.
     * @return a decoded JWT
     * @throws JwtVerificationException when parsing or validation errors occur
     */
    Jwt decode(String idToken, String nonce) throws JwtVerificationException;

    /**
     * Builder interface used to simplify construction of a IdTokenVerifier.
     */
    interface Builder extends VerifierBuilderSupport<Builder, IdTokenVerifier> {

        /**
         * Sets the {@code clienId} the verifier will expect.
         *
         * @param clientId Client Id
         * @return a reference to the current builder for use in method chaining
         */
        Builder setClientId(String clientId);
    }
}