package com.chencraft.crypto.simpleSubstituion;

import com.chencraft.crypto.SymmetricKeyAlgorithm;

/**
 * Only the English alphabet is supported. All inputs and outputs are upper case.
 */
public class SimpleSubstitutionAlgorithm implements SymmetricKeyAlgorithm {

    /**
     * Private key should be a 26-letter string. 'A' will be mapped to 0-index character and so on.
     */
    private String privateKey;

    @Override
    public void setPrivateKey(String privateKey) {
        if (privateKey == null || privateKey.length() != 26) {
            throw new IllegalArgumentException("Invalid private key");
        }
        this.privateKey = privateKey.toUpperCase();
    }

    @Override
    public String encrypt(String plainText) {
        if (plainText == null) {
            return "";
        }

        StringBuilder cipherText = new StringBuilder();

        for (char c : plainText.toUpperCase().toCharArray()) {
            int index = c - 'A';
            if (index >= 0 && index < 26) {
                cipherText.append(privateKey.charAt(index));
            } else {
                cipherText.append(c);
            }
        }

        return cipherText.toString();
    }

    @Override
    public String decrypt(String cipherText) {
        if (cipherText == null) {
            return "";
        }

        StringBuilder plainText = new StringBuilder();

        for (char c : cipherText.toUpperCase().toCharArray()) {
            int index = privateKey.indexOf(c);
            if (index >= 0 && index < 26) {
                plainText.append((char) ('A' + index));
            } else {
                plainText.append(c);
            }
        }

        return plainText.toString();
    }
}
