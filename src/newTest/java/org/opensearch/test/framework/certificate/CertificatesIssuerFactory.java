package org.opensearch.test.framework.certificate;

import java.security.Provider;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

class CertificatesIssuerFactory {

    public static final int KEY_SIZE = 2048;

    private CertificatesIssuerFactory() {

    }

    private static final Provider DEFAULT_SECURITY_PROVIDER = new BouncyCastleProvider();

    public static CertificatesIssuer rsaBaseCertificateIssuer() {
        return rsaBaseCertificateIssuer(null);
    }

    public static CertificatesIssuer rsaBaseCertificateIssuer(Provider securityProvider) {
        Provider provider = Optional.ofNullable(securityProvider).orElse(DEFAULT_SECURITY_PROVIDER);
        return new CertificatesIssuer(provider, new RSAAsymmetricCryptographyAlgorithm(provider, KEY_SIZE));
    }

    public static CertificatesIssuer ecdsaBaseCertificatesIssuer() {
        return ecdsaBaseCertificatesIssuer(null);
    }

    public static CertificatesIssuer ecdsaBaseCertificatesIssuer(Provider securityProvider) {
        Provider provider = Optional.ofNullable(securityProvider).orElse(DEFAULT_SECURITY_PROVIDER);
        return new CertificatesIssuer(provider, new ECDSAAsymmetricCryptographyAlgorithm(provider, "P-384"));
    }
}
