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
package com.okta.jwt.impl.jjwt.models;

import java.util.List;
import java.util.Objects;

/**
 * Classes in this `impl` implementation package may change in NON backward compatible way, and should ONLY be used as
 * a "runtime" dependency.
 */
public class JwkKeys {

    private List<JwkKey> keys;

    public List<JwkKey> getKeys() {
        return keys;
    }

    public JwkKeys setKeys(List<JwkKey> keys) {
        this.keys = keys;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JwkKeys jwkKeys = (JwkKeys) o;
        return Objects.equals(keys, jwkKeys.keys);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keys);
    }
}
