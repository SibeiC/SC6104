package com.chencraft.crypto.algo;

import com.chencraft.crypto.utils.Decrypt;
import com.chencraft.crypto.utils.Encrypt;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class VigenereAlgorithmTest {
    private final String privateKey = "DUH";
    private final String plainText = "THEY DRINK THE TEA";
    private final String cipherText = "WBLB XYLHR WBL WYH";

    @Test
    public void basicEncryptTest() throws Exception {
        String cipher = Encrypt.with(plainText, privateKey, VigenereAlgorithm.class);
        Assertions.assertEquals(cipherText, cipher);
    }

    @Test
    public void basicDecryptTest() throws Exception {
        String plain = Decrypt.with(cipherText, privateKey, VigenereAlgorithm.class);
        Assertions.assertEquals(plainText, plain);
    }
}
