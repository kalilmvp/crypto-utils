package com.kmvpsolutions.crypto.hash;

import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashUtils {

    private static final String SHA2 = "SHA-256";

    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] createSHA2Hash(String input, byte[] salt) throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(salt);
        stream.write(input.getBytes());

        return MessageDigest.getInstance(SHA2).digest(stream.toByteArray());
    }

    public static String hashPassword(String passwd) {
        return BCrypt.hashpw(passwd, BCrypt.gensalt());
    }

    public static boolean verify(String plainPassword, String hashPasswd) {
        return BCrypt.checkpw(plainPassword, hashPasswd);
    }
}
