package com.chencraft.crypto;

public interface Algorithm {
    String encrypt(String plainText);

    String decrypt(String cipherText);
}
