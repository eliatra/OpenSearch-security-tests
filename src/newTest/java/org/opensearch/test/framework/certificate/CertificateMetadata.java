package org.opensearch.test.framework.certificate;

import java.util.*;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.Objects.requireNonNull;

class CertificateMetadata {
    /**
     * Certification subject (describes "certificate owner")
     */
    private final String subject;

    private final int validityDays;

    private final String nodeOid;

    private final List<String> dnsNames;

    private final List<String> ipAddresses;

    private final boolean basicConstrainIsCa;

    private final Set<PrivateKeyUsage> keyUsages;

    private final Set<ExtendedPrivateKeyUsage> extendedKeyUsages;


    private CertificateMetadata(String subject,
                               int validityDays,
                               String nodeOid,
                               List<String> dnsNames,
                               List<String> ipAddresses,
                               boolean basicConstrainIsCa,
                               Set<PrivateKeyUsage> keyUsages,
                               Set<ExtendedPrivateKeyUsage> extendedKeyUsages) {
        this.subject = subject;
        this.validityDays = validityDays;
        this.nodeOid = nodeOid;
        this.dnsNames = requireNonNull(dnsNames, "List of dns names must not be null.");
        this.ipAddresses = requireNonNull(ipAddresses, "List of IP addresses must not be null");
        this.basicConstrainIsCa = basicConstrainIsCa;
        this.keyUsages = requireNonNull(keyUsages, "Key usage set must not be null.");
        this.extendedKeyUsages = requireNonNull(extendedKeyUsages, "Extended key usage must not be null.");
    }

    public static CertificateMetadata basicMetadata(String subjectName, int validityDays) {
        return new CertificateMetadata(subjectName, validityDays, null, emptyList(), emptyList(), false, emptySet(), emptySet());
    }

    public CertificateMetadata withKeyUsage(boolean basicConstrainIsCa,
                                                   Set<PrivateKeyUsage> keyUsages,
                                                   ExtendedPrivateKeyUsage...extendedKeyUsages){
        Set<ExtendedPrivateKeyUsage> extendedUsage = arrayToEnumSet(extendedKeyUsages);
        return new CertificateMetadata(subject, validityDays, nodeOid, dnsNames, ipAddresses, basicConstrainIsCa,
                keyUsages, extendedUsage);
    }

    private <T extends Enum<T>> Set<T> arrayToEnumSet(T[] enumArray) {
        if((enumArray == null) || (enumArray.length == 0)){
            return Collections.emptySet();
        }
        return EnumSet.copyOf(Arrays.asList(enumArray));
    }

    public CertificateMetadata withSubjectAlternativeName(String nodeOid, List<String> dnsNames, String...ipAddresses) {
        return new CertificateMetadata(subject, validityDays, nodeOid, dnsNames, Arrays.asList(ipAddresses),
                basicConstrainIsCa, keyUsages, extendedKeyUsages);
    }

    public String getSubject() {
        return subject;
    }

    public int getValidityDays() {
        return validityDays;
    }

    public boolean isBasicConstrainIsCa() {
        return basicConstrainIsCa;
    }

    KeyUsage asKeyUsage() {
        Integer keyUsageBitMask = keyUsages
                .stream()
                .map(PrivateKeyUsage::asInt)
                .reduce(0, (accumulator, currentValue) -> accumulator | currentValue);
        return new KeyUsage(keyUsageBitMask);
    }

    boolean hasSubjectAlternativeNameExtension() {
        return (ipAddresses.size() + dnsNames.size()) > 0;
    }

    DERSequence createSubjectAlternativeNames() {
        return SubjectAlternativesNameGenerator.createSubjectAlternativeNameList(nodeOid, dnsNames, ipAddresses);
    }

    boolean hasExtendedKeyUsage() {
        return ! extendedKeyUsages.isEmpty();
    }

    ExtendedKeyUsage getExtendedKeyUsage() {
        KeyPurposeId[] usages = extendedKeyUsages
                .stream()
                .map(ExtendedPrivateKeyUsage::getKeyPurposeId)
                .toArray(KeyPurposeId[]::new);
        return new ExtendedKeyUsage(usages);
    }
}
