package com.nickmafra.util;

import java.security.cert.X509Certificate;
import java.util.Base64;

public class X509Utils {
    private X509Utils() {
    }

    public static String getBase64PublicKey(X509Certificate cert) {
        return cert == null ? null : FormatoUtils.bytesToBase64(cert.getPublicKey().getEncoded());
    }

    public static String getHexPublicKey(X509Certificate cert) {
        return cert == null ? null : FormatoUtils.bytesToHex(cert.getPublicKey().getEncoded());
    }
}
