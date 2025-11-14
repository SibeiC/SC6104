package com.chencraft.crypto.algo;

import com.chencraft.crypto.SymmetricKeyAlgorithm;

import java.util.ArrayList;
import java.util.List;

/**
 * All inputs and outputs are upper case.
 */
public class VigenereAlgorithm implements SymmetricKeyAlgorithm {
    private List<Integer> privateKey;

    @Override
    public void setPrivateKey(String privateKey) {
        this.privateKey = new ArrayList<>();

        for (char c : privateKey.toUpperCase().toCharArray()) {
            this.privateKey.add(c - 'A');
        }
    }

    @Override
    public String encrypt(String plainText) {
        int index = 0;
        int pkSize = privateKey.size();

        StringBuilder cipherText = new StringBuilder();

        for (char c : plainText.toUpperCase().toCharArray()) {
            if (c < 'A' || c > 'Z') {
                cipherText.append(c);
                continue;
            }

            int i = index % pkSize;
            char newVal = (char) (c + privateKey.get(i));
            cipherText.append((char) (newVal > 'Z' ? newVal - 26 : newVal));
            index++;
        }

        return cipherText.toString();
    }

    @Override
    public String decrypt(String cipherText) {
        int index = 0;
        int pkSize = privateKey.size();

        StringBuilder plainText = new StringBuilder();

        for (char c : cipherText.toUpperCase().toCharArray()) {
            if (c < 'A' || c > 'Z') {
                plainText.append(c);
                continue;
            }

            int i = index % pkSize;
            char newVal = (char) (c - privateKey.get(i));
            plainText.append((char) (newVal < 'A' ? newVal + 26 : newVal));
            index++;
        }

        return plainText.toString();
    }
}
