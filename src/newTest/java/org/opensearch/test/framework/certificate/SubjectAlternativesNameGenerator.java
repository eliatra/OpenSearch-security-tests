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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.google.common.base.Strings;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

class SubjectAlternativesNameGenerator {

    private SubjectAlternativesNameGenerator(){

    }

    public static DERSequence createSubjectAlternativeNameList(String nodeOid, List<String> dnsList, List<String> ipList) {
        List<ASN1Encodable> subjectAlternativeNameList = new ArrayList<>();

        if (!Strings.isNullOrEmpty(nodeOid)) {
            subjectAlternativeNameList.add(new GeneralName(GeneralName.registeredID, nodeOid));
        }

        if (isNotEmpty(dnsList)) {
            for (String dnsName : dnsList) {
                subjectAlternativeNameList.add(new GeneralName(GeneralName.dNSName, dnsName));
            }
        }

        if (isNotEmpty(ipList)) {
            for (String ip : ipList) {
                subjectAlternativeNameList.add(new GeneralName(GeneralName.iPAddress, ip));
            }
        }

        return new DERSequence(subjectAlternativeNameList.toArray(ASN1Encodable[]::new));
    }

    private static <T> boolean isNotEmpty(Collection<T> collection) {
        return (collection != null) && (!collection.isEmpty());
    }
}
