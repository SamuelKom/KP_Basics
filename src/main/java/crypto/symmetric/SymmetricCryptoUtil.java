package crypto.symmetric;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricCryptoUtil {

    // Constants
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * Generates a secret key for AES encryption
     *
     * @return A SecretKey for AES
     * @throws NoSuchAlgorithmException If the algorithm is not available
     */
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    /**
     * Encrypts a string message using AES-GCM
     *
     * @param message The plaintext message to encrypt
     * @param key The secret key for encryption
     * @return Byte array containing IV and ciphertext
     * @throws Exception If encryption fails
     */
    public static byte[] encrypt(String message, SecretKey key) throws Exception {
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

        // Generate a random IV (Initialization Vector)
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Create GCM parameter specification
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        // Encrypt the plaintext
        byte[] ciphertext = cipher.doFinal(plaintext);

        System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));
        System.out.println("Ciphertext+Tag: " + Base64.getEncoder().encodeToString(ciphertext));

        // Combine IV and ciphertext into a single byte array
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);

        return byteBuffer.array();
    }

    /**
     * Decrypts an encrypted message using AES-GCM
     *
     * @param encryptedData Byte array containing IV and ciphertext
     * @param key The secret key for decryption
     * @return The decrypted plaintext message
     * @throws Exception If decryption fails
     */
    public static String decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        // Extract IV and ciphertext
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);

        byte[] ciphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertext);

        // Create GCM parameter specification
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));
        System.out.println("Ciphertext+Tag: " + Base64.getEncoder().encodeToString(ciphertext));


        // Decrypt the ciphertext
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Converts a SecretKey to Base64 string for storage or transmission
     */
    public static String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Recreates a SecretKey from a Base64 string
     */
    public static SecretKey stringToKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
}
