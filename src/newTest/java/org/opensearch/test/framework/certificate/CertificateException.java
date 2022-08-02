package org.opensearch.test.framework.certificate;

public class CertificateException extends RuntimeException {

    CertificateException(String message) {
        super(message);
    }

    CertificateException(String message, Throwable cause) {
        super(message, cause);
    }

}
