package com.kmvpsolutions.crypto.asymmetric;

import javax.crypto.Cipher;
import java.security.*;

public class AsymmetricEncryptionUtils {

    private static final String RSA = "RSA";

    public static KeyPair createRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(4096, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] performRSAEncyption(String plainText, PrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String performRSADecyption(byte[] cipherText, PublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(cipherText));
    }
}
