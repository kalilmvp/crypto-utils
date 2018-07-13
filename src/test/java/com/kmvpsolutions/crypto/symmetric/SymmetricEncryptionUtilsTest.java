package com.kmvpsolutions.crypto.symmetric;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SymmetricEncryptionUtilsTest {

    @Test
    public void createAESKey() throws Exception {
        SecretKey key = SymmetricEncryptionUtils.createAESKey();

        assertNotNull(key);

        System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));
    }

    @Test
    public void testAESCryptoRoutine() throws Exception {
        SecretKey key = SymmetricEncryptionUtils.createAESKey();
        byte[] initializationVector = SymmetricEncryptionUtils.createInitializationVector();

        String plainText = "Text to be cyphered";

        byte[] cipherText = SymmetricEncryptionUtils.performAESEncryption(plainText, key, initializationVector);
        assertNotNull(cipherText);

        System.out.println(DatatypeConverter.printHexBinary(cipherText));

        String decryptedText = SymmetricEncryptionUtils.performAESDecryption(cipherText, key, initializationVector);
        assertEquals(plainText, decryptedText);
    }
}