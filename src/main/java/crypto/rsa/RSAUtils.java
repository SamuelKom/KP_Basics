package crypto.rsa;

import java.math.BigInteger;
import java.util.*;


public class RSAUtils {

    public static class RSAEncryption {
        private BigInteger privateKey;
        private BigInteger publicKey;
        private BigInteger modulus;

        public RSAEncryption() {
            generateKeys();
        }

        private void generateKeys() {
            BigInteger p = BigInteger.probablePrime(1024, new Random());
            BigInteger q = BigInteger.probablePrime(1024, new Random());

            modulus = p.multiply(q);

            BigInteger phi = p.subtract(BigInteger.ONE)
                    .multiply(q.subtract(BigInteger.ONE));

            // Commonly used public exponent
            publicKey = BigInteger.valueOf(65537);
            privateKey = publicKey.modInverse(phi);
        }

        /**
         * Encrypts a message using RSA.
         *
         * @param message The message to encrypt (as bytes).
         * @param key The public RSA key.
         * @param mod The modulus used for encryption.
         * @return The encrypted message as a byte array.
         */
        public byte[] encrypt(byte[] message, BigInteger key, BigInteger mod) {
            BigInteger m = new BigInteger(1, message);
            return m.modPow(key, mod).toByteArray();
        }

        /**
         * Decrypts an RSA-encrypted message using own private key.
         *
         * @param encryptedMessage The encrypted message as a byte array.
         * @return The decrypted message as a byte array.
         */
        public byte[] decrypt(byte[] encryptedMessage) {
            BigInteger encrypted = new BigInteger(1, encryptedMessage);
            return encrypted.modPow(privateKey, modulus).toByteArray();
        }

        public BigInteger getPublicKey() {
            return publicKey;
        }

        public BigInteger getModulus() {
            return modulus;
        }
    }
}