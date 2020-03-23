package com.varrunr.security.test.design;

public interface EncryptionWrapper {
    /**
     * Encrypts plain-text for a given tenant using the configured SecretKey
     *
     * @param plaintext
     * @param tenantId
     * @return
     * @throws EncryptionException
     */
    String encrypt(String plaintext, String tenantId) throws EncryptionException;
}
