package com.kmvpsolutions.crypto.digitalsignature;

import com.kmvpsolutions.crypto.asymmetric.AsymmetricEncryptionUtils;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DigitalSignatureUtilsTest {

    @Test
    public void testDigitalSignatureRoutine() throws Exception {
        URL url = this.getClass().getClassLoader().getResource("file.txt");
        Path path = Paths.get(url.toURI());
        byte[] input = Files.readAllBytes(path);

        KeyPair keyPair = AsymmetricEncryptionUtils.createRSAKeyPair();
        byte[] digitallySigned = DigitalSignatureUtils.createDigitalSignature(input, keyPair.getPrivate());

        assertNotNull(digitallySigned);

        System.out.println(DatatypeConverter.printHexBinary(digitallySigned));

        assertTrue(DigitalSignatureUtils.verifyDigitalSignature(input, digitallySigned, keyPair.getPublic()));
    }
}