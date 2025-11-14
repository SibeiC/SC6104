package com.chencraft.crypto.algo;

import com.chencraft.crypto.utils.Decrypt;
import com.chencraft.crypto.utils.Encrypt;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SimpleSubstitutionAlgorithmTest {
    private final String privateKey = "JICAXSEYVDKWBQTZRHFMPNULGO";
    private final String plainText = "I am Groot".toUpperCase();
    private final String cipherText = "V JB EHTTM";

    @Test
    public void basicEncryptTest() throws Exception {
        String cipher = Encrypt.with(plainText, privateKey, SimpleSubstitutionAlgorithm.class);
        Assertions.assertEquals(cipherText, cipher);
    }

    @Test
    public void basicDecryptTest() throws Exception {
        String plain = Decrypt.with(cipherText, privateKey, SimpleSubstitutionAlgorithm.class);
        Assertions.assertEquals(plainText, plain);
    }
}
