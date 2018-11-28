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
package com.okta.jwt.impl.jjwt.models

import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not

class JwkKeysTest {

    @Test
    void quickEqualsAndHashTest() {

        def a = new JwkKeys().setKeys([new JwkKey()
                .setAlgorithm("alg")
                .setKeyId("keyid")
                .setKeyType("type")
                .setPublicKeyExponent("pke")
                .setPublicKeyModulus("pkm")
                .setPublicKeyUse("use")])

        def b = new JwkKeys().setKeys([new JwkKey()
            .setAlgorithm("alg")
            .setKeyId("keyid")
            .setKeyType("type")
            .setPublicKeyExponent("pke")
            .setPublicKeyModulus("pkm")
            .setPublicKeyUse("different")])

        assertThat a, not(b)
        assertThat a.hashCode(), not(b.hashCode())

        b.getKeys().get(0).setPublicKeyUse("use") // set to same value as 'a'
        assertThat a, is(b)
        assertThat a.hashCode(), is(b.hashCode())
    }
}