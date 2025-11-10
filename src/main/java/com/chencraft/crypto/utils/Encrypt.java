package com.chencraft.crypto.utils;

import com.chencraft.crypto.SymmetricKeyAlgorithm;

public class Encrypt {
    public static String with(String plainText, String privateKey, Class<? extends SymmetricKeyAlgorithm> algorithmClass) throws Exception {
        SymmetricKeyAlgorithm algorithm = algorithmClass.getDeclaredConstructor().newInstance();
        algorithm.setPrivateKey(privateKey);
        return algorithm.encrypt(plainText);
    }
}
