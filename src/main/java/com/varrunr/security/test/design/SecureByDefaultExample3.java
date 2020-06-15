package com.varrunr.security.test.design;

public class SecureByDefaultExample3 {
    public static void main(String[] args) throws Exception {
        /**
         * 1. Separate security oriented code to a different repo
         * 2. Allow different micro-services to use common crypto
         */
        com.company.crypto.EncryptionWrapper encryptionWrapper  = new com.company.crypto.EncryptionWrapperImpl();
        System.out.println("Encrypted Data: " + encryptionWrapper.encrypt("0xdeadbeef", "myTenant"));
    }
}
