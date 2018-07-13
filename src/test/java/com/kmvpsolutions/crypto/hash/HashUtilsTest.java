package com.kmvpsolutions.crypto.hash;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;

import java.util.UUID;

import static org.junit.Assert.*;

public class HashUtilsTest {

    @Test
    public void generateRandomSalt() {
        byte[] salt = HashUtils.generateRandomSalt();
        assertNotNull(salt);

        System.out.println(DatatypeConverter.printHexBinary(salt));
    }

    @Test
    public void createSHA2Hash() throws Exception {
        byte[] salt = HashUtils.generateRandomSalt();
        assertNotNull(salt);

        String uuid = UUID.randomUUID().toString();

        System.out.println(uuid);

        byte[] hash = HashUtils.createSHA2Hash(uuid, salt);
        assertNotNull(hash);

        byte[] hash2 = HashUtils.createSHA2Hash(uuid, salt);
        assertNotNull(hash2);

        assertEquals(DatatypeConverter.printHexBinary(hash), DatatypeConverter.printHexBinary(hash2));
    }

    @Test
    public void createHashPasswordRoutine() throws Exception {
        final String plainPassword = "This is my password and i do like it";

        final String hashedPassword = HashUtils.hashPassword(plainPassword);

        assertNotNull(hashedPassword);

        System.out.println(hashedPassword);

        assertTrue(HashUtils.verify(plainPassword, hashedPassword));
    }
}