package org.bitcoinj.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * This class provides PBKDF2 with SHA-512 HMAC key derivation using
 * {@link PBEKeySpec} and {@link SecretKeyFactory} of the Java Crypto package.
 */
public class PBKDF2SHA512 {
    /**
     * Derive a secret key from a password using PBKDF2 with SHA-512 HMAC
     * @param password material from which the cryptographic key is derived
     * @param salt the salt
     * @param iterationCount the iteration count
     * @param keyLength the to-be-derived key length in bytes
     * @return the secret key
     */
    public static byte[] derive(String password, String salt, int iterationCount, int keyLength) {
        /*
         * Encode salt bytes to UTF-8 as specified in BIP39
         */
        final byte[] saltBytes;
        try {
            saltBytes = salt.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        /*
         * A previous implementation of this method used bytes for the key length. Convert to bits
         * for PBEKeySpec.
         */
        final int keyLengthBits = keyLength * 8;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, iterationCount, keyLengthBits);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
