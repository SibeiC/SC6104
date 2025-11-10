package com.chencraft.crypto;

public interface AsymmetricKeyAlgorithm extends Algorithm {
    void setPublicKey(String publicKey);

    void setPrivateKey(String privateKey);
}
