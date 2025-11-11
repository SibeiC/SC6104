package com.chencraft.crypto.utils;

import com.chencraft.crypto.SymmetricKeyAlgorithm;

public class Decrypt {
    public static String with(String cipherText, String privateKey, Class<? extends SymmetricKeyAlgorithm> algorithmClass) throws Exception {
        SymmetricKeyAlgorithm algorithm = algorithmClass.getDeclaredConstructor().newInstance();
        algorithm.setPrivateKey(privateKey);
        return algorithm.decrypt(cipherText);
    }
}
