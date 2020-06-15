package com.varrunr.security.test.design;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class SecureByDefaultExample1 {

    private static Random PRNG;
    private static Map<String, javax.crypto.SecretKey> KEY_STORE = new HashMap<>();

    private static Random getPrng() {
        if (PRNG == null) {
            PRNG = new SecureRandom();
        }
        return PRNG;
    }

    private static SecretKey getSecretKey(String tenantId) throws NoSuchAlgorithmException {
        if (KEY_STORE.containsKey(tenantId)) {
            return KEY_STORE.get(tenantId);
        } else {
            // Generate new secret key if not present already

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            // Q: How long should my key be? Is 128-bits enough?
            keyGenerator.init(128);
            SecretKey tenantKey = keyGenerator.generateKey();

            // Persist newly generated key
            // Q: How to secure key?
            // Q: How to rotate key?
            // Q: How to store key in memory?
            KEY_STORE.put(tenantId, tenantKey);
            return KEY_STORE.get(tenantId);
        }
    }

    private static String encrypt(String plaintext, String tenantId) throws NoSuchAlgorithmException,
                                                                    NoSuchPaddingException,
                                                                    InvalidKeyException,
                                                                    InvalidAlgorithmParameterException,
                                                                    IllegalBlockSizeException,
                                                                    BadPaddingException {
        // Fetch Secret Key for tenant
        SecretKey secretKey = getSecretKey(tenantId);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // Problem 1: How to securely use a PRNG
        Random secureRandom = getPrng();

        // Q: What's an IV? What IV length do I choose?
        byte[] iv = new byte[12];
        // Q: Can I generate IV just once for an application? I want to avoid blocking for entropy.
        secureRandom.nextBytes(iv);

        // Q: What is tag length? Why is tag length 128?
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        // Q: What provider do I use? Does it matter which one I use?
        // Q: Why no padding?
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        byte[] plainText = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = cipher.doFinal(plainText);

        return new String(cipherText, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Encrypted Data: " + encrypt("0xdeadbeef", "myTenant"));
    }
}
