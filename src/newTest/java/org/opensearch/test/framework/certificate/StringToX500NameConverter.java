/*
 * Copyright 2021 floragunn GmbH
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
 *
 */

package org.opensearch.test.framework.certificate;

import com.google.common.base.Strings;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;

class StringToX500NameConverter {

    private StringToX500NameConverter(){

    }

    static X500Name convert(String distinguishedName) {
        if (Strings.isNullOrEmpty(distinguishedName)) {
            throw new CertificateException("No DN (distinguished name) must not be null or empty");
        }
        try {
            return new X500Name(RFC4519Style.INSTANCE, distinguishedName);
        } catch (IllegalArgumentException e) {
            String message = String.format("Invalid DN (distinguished name) specified for %s certificate.", distinguishedName);
            throw new CertificateException(message, e);
        }
    }
}
