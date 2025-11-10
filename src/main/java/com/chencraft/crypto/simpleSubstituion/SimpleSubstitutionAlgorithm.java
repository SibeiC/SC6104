package com.chencraft.crypto.simpleSubstituion;

import com.chencraft.crypto.SymmetricKeyAlgorithm;
import lombok.Setter;

public class SimpleSubstitutionAlgorithm implements SymmetricKeyAlgorithm {
    @Setter
    private String privateKey;

    @Override
    public String encrypt(String plainText) {
        // TODO: Finish this part
        return "";
    }

    @Override
    public String decrypt(String cipherText) {
        // TODO: Finish this part
        return "";
    }
}
