package com.chencraft.crypto.simpleSubstituion;

import com.chencraft.crypto.utils.Encrypt;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SimpleSubstitutionAlgorithmTest {
    private final String privateKey = "";
    private final String plainText = "";
    private final String cipherText = "";

    @Test
    public void basicEncryptTest() throws Exception {
        String cipher = Encrypt.with(plainText, privateKey, SimpleSubstitutionAlgorithm.class);
        Assertions.assertEquals(cipherText, cipher);
    }

    @Test
    public void basicDecryptTest() throws Exception {
        String plain = Encrypt.with(cipherText, privateKey, SimpleSubstitutionAlgorithm.class);
        Assertions.assertEquals(plainText, plain);
    }
}
