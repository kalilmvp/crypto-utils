package com.kmvpsolutions.crypto.asymmetric;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AsymmetricEncryptionUtilsTest {

    @Test
    public void createRSAKeyPair() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtils.createRSAKeyPair();
        assertNotNull(keyPair);

        System.out.println("Private key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void testRSAEncryptionRoutine() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtils.createRSAKeyPair();
        assertNotNull(keyPair);

        String plainText = "Text to hide from everyone";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncyption(plainText, keyPair.getPrivate());

        System.out.println("Cipher text: " + DatatypeConverter.printHexBinary(cipherText));

        String decrypted = AsymmetricEncryptionUtils.performRSADecyption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decrypted);
    }
}