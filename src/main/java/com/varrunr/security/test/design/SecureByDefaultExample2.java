package com.varrunr.security.test.design;

public class SecureByDefaultExample2 {

    public static void main(String[] args) throws Exception {
        /**
         * 1. Avoid bloat of repeated crypto and risk of mistakes
         * 2. Q: What if someone modifies EncryptionWrapper to take insecure defaults?
         */
        EncryptionWrapper encryptionWrapper = new EncryptionWrapperImpl();
        System.out.println("Encrypted Data: " + encryptionWrapper.encrypt("0xdeadbeef", "myTenant"));
    }
}
