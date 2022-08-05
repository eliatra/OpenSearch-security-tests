package org.opensearch.test.framework.certificate;


import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static java.util.Arrays.asList;
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


    private CertificateMetadata(String subject,
                               int validityDays,
                               String nodeOid,
                               List<String> dnsNames,
                               List<String> ipAddresses,
                               boolean basicConstrainIsCa,
                               Set<PrivateKeyUsage> keyUsages) {
        this.subject = subject;
        this.validityDays = validityDays;
        this.nodeOid = nodeOid;
        this.dnsNames = requireNonNull(dnsNames, "List of dns names must not be null.");
        this.ipAddresses = requireNonNull(ipAddresses, "List of IP addresses must not be null");
        this.basicConstrainIsCa = basicConstrainIsCa;
        this.keyUsages = requireNonNull(keyUsages, "Key usage set must not be null.");
    }

    public static CertificateMetadata basicMetadata(String subjectName, int validityDays) {
        return new CertificateMetadata(subjectName, validityDays, null, emptyList(), emptyList(), false, emptySet());
    }

    public CertificateMetadata withKeyUsage(boolean basicConstrainIsCa, PrivateKeyUsage...keyUsages){
        Set<PrivateKeyUsage> usages = arrayToEnumSet(keyUsages);
        return new CertificateMetadata(subject, validityDays, nodeOid, dnsNames, ipAddresses, basicConstrainIsCa, usages);
    }

    private <T extends Enum<T>> Set<T> arrayToEnumSet(T[] enumArray) {
        if((enumArray == null) || (enumArray.length == 0)){
            return Collections.emptySet();
        }
        return EnumSet.copyOf(asList(enumArray));
    }

    public CertificateMetadata withSubjectAlternativeName(String nodeOid, List<String> dnsNames, String...ipAddresses) {
        return new CertificateMetadata(subject, validityDays, nodeOid, dnsNames, asList(ipAddresses), basicConstrainIsCa, keyUsages);
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
            .filter(PrivateKeyUsage::isNotExtendedUsage)
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
        return keyUsages.stream().filter(PrivateKeyUsage::isNotExtendedUsage).count() > 0;
    }

    ExtendedKeyUsage getExtendedKeyUsage() {
        KeyPurposeId[] usages = keyUsages
            .stream()
            .filter(PrivateKeyUsage::isExtendedUsage)
            .map(PrivateKeyUsage::getKeyPurposeId)
            .toArray(KeyPurposeId[]::new);
        return new ExtendedKeyUsage(usages);
    }
}
