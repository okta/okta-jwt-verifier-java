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
package com.okta.jwt.impl.jjwt;

import com.okta.commons.configcheck.ConfigurationValidator;
import com.okta.jwt.IdTokenVerifier;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public final class JjwtIdTokenVerifierBuilder extends BaseVerifierBuilderSupport<IdTokenVerifier.Builder, IdTokenVerifier>
                                              implements IdTokenVerifier.Builder {

    private String clientId;

    public String getClientId() {
        return clientId;
    }

    public IdTokenVerifier.Builder setClientId(String clientId) {
        this.clientId = clientId;
        return self();
    }

    @Override
    protected void validate() {
        super.validate();
        ConfigurationValidator.assertClientId(clientId);
    }

    @Override
    public IdTokenVerifier build() {
        validate();
        return new JjwtIdTokenVerifier(getIssuer(), getClientId(), getLeeway(), signingKeyResolver());
    }
}
