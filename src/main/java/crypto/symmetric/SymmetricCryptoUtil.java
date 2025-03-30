package crypto.symmetric;


import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricCryptoUtil {

    // Common cipher algorithms
    public static final String AES = "AES";
    public static final String DES = "DES";
    public static final String TRIPLE_DES = "DESede";
    public static final String BLOWFISH = "Blowfish";

    // Common cipher modes
    public static final String ECB = "ECB";
    public static final String CBC = "CBC";
    public static final String CTR = "CTR";
    public static final String GCM = "GCM";

    // Common padding schemes
    public static final String PKCS5_PADDING = "PKCS5Padding";
    public static final String NO_PADDING = "NoPadding";

    /**
     * Generates a secret key for the specified algorithm with the given key size
     *
     * @param algorithm The cipher algorithm (e.g., "AES")
     * @param keySize The key size in bits (e.g., 128, 192, 256 for AES)
     * @return The generated secret key
     * @throws NoSuchAlgorithmException If the specified algorithm is not available
     */
    public SecretKey generateKey(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    /**
     * Creates a secret key from the provided key bytes for the specified algorithm
     *
     * @param keyBytes The raw key bytes
     * @param algorithm The cipher algorithm (e.g., "AES")
     * @return The secret key
     */
    public SecretKey createKey(byte[] keyBytes, String algorithm) {
        return new SecretKeySpec(keyBytes, algorithm);
    }

    /**
     * Generates a random initialization vector (IV) of the specified size
     *
     * @param size The size of the IV in bytes
     * @return The generated IV
     */
    public byte[] generateIV(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Encrypts the provided plaintext using the specified parameters
     *
     * @param plaintext The text to encrypt
     * @param key The secret key
     * @param algorithm The cipher algorithm (e.g., "AES")
     * @param mode The cipher mode (e.g., "CBC")
     * @param padding The padding scheme (e.g., "PKCS5Padding")
     * @return An EncryptionResult containing the ciphertext and IV
     * @throws Exception If encryption fails
     */
    public EncryptionResult encrypt(String plaintext, SecretKey key, String algorithm,
                                    String mode, String padding) throws Exception {

        // Construct the transformation string
        String transformation = String.format("%s/%s/%s", algorithm, mode, padding);
        Cipher cipher = Cipher.getInstance(transformation);

        byte[] iv;

        // Initialize the cipher based on the mode
        if (mode.equals(ECB)) {
            // ECB mode doesn't use an IV
            cipher.init(Cipher.ENCRYPT_MODE, key);
            iv = null;
        } else if (mode.equals(GCM)) {
            // GCM mode uses a 12-byte IV
            iv = generateIV(12);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        } else {
            // Other modes (CBC, CTR) use an IV the size of the cipher block
            iv = generateIV(cipher.getBlockSize());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        }

        // Encrypt the plaintext
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);

        return new EncryptionResult(ciphertext, iv);
    }

    /**
     * Decrypts the provided ciphertext using the specified parameters
     *
     * @param encryptionResult The EncryptionResult containing the ciphertext and IV
     * @param key The secret key
     * @param algorithm The cipher algorithm (e.g., "AES")
     * @param mode The cipher mode (e.g., "CBC")
     * @param padding The padding scheme (e.g., "PKCS5Padding")
     * @return The decrypted plaintext
     * @throws Exception If decryption fails
     */
    public String decrypt(EncryptionResult encryptionResult, SecretKey key, String algorithm,
                          String mode, String padding) throws Exception {

        // Construct the transformation string
        String transformation = String.format("%s/%s/%s", algorithm, mode, padding);
        Cipher cipher = Cipher.getInstance(transformation);

        // Initialize the cipher based on the mode
        if (mode.equals(ECB)) {
            // ECB mode doesn't use an IV
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else if (mode.equals(GCM)) {
            // GCM mode uses a GCMParameterSpec
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, encryptionResult.getIv());
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        } else {
            // Other modes (CBC, CTR) use an IvParameterSpec
            IvParameterSpec ivSpec = new IvParameterSpec(encryptionResult.getIv());
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        }

        // Decrypt the ciphertext
        byte[] decryptedBytes = cipher.doFinal(encryptionResult.getCiphertext());

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts the provided plaintext and encodes the result as a Base64 string
     *
     * @param plaintext The text to encrypt
     * @param key The secret key
     * @param algorithm The cipher algorithm (e.g., "AES")
     * @param mode The cipher mode (e.g., "CBC")
     * @param padding The padding scheme (e.g., "PKCS5Padding")
     * @return The encrypted data encoded as a Base64 string
     * @throws Exception If encryption fails
     */
    public String encryptToBase64(String plaintext, SecretKey key, String algorithm,
                                  String mode, String padding) throws Exception {

        EncryptionResult result = encrypt(plaintext, key, algorithm, mode, padding);

        // Combine IV and ciphertext for storage/transmission
        byte[] combined;
        if (result.getIv() != null) {
            // Format: [IV length (4 bytes)][IV][ciphertext]
            ByteBuffer buffer = ByteBuffer.allocate(4 + result.getIv().length + result.getCiphertext().length);
            buffer.putInt(result.getIv().length);
            buffer.put(result.getIv());
            buffer.put(result.getCiphertext());
            combined = buffer.array();
        } else {
            // ECB mode doesn't use an IV
            combined = result.getCiphertext();
        }

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypts the provided Base64-encoded ciphertext
     *
     * @param encodedText The Base64-encoded encrypted data
     * @param key The secret key
     * @param algorithm The cipher algorithm (e.g., "AES")
     * @param mode The cipher mode (e.g., "CBC")
     * @param padding The padding scheme (e.g., "PKCS5Padding")
     * @return The decrypted plaintext
     * @throws Exception If decryption fails
     */
    public String decryptFromBase64(String encodedText, SecretKey key, String algorithm,
                                    String mode, String padding) throws Exception {

        byte[] combined = Base64.getDecoder().decode(encodedText);

        byte[] iv = null;
        byte[] ciphertext;

        if (!mode.equals(ECB)) {
            // Extract IV and ciphertext
            ByteBuffer buffer = ByteBuffer.wrap(combined);
            int ivLength = buffer.getInt();
            iv = new byte[ivLength];
            buffer.get(iv);

            ciphertext = new byte[combined.length - 4 - ivLength];
            buffer.get(ciphertext);
        } else {
            // ECB mode doesn't use an IV
            ciphertext = combined;
        }

        EncryptionResult result = new EncryptionResult(ciphertext, iv);
        return decrypt(result, key, algorithm, mode, padding);
    }

    /**
     * Lists all available cipher algorithms in the JVM
     *
     * @return An array of available cipher algorithm names
     */
    public String[] getAvailableCipherAlgorithms() {
        return Security.getProviders()[0].getServices().stream()
                .filter(s -> "Cipher".equals(s.getType()))
                .map(Provider.Service::getAlgorithm)
                .toArray(String[]::new);
    }

    /**
     * Class to hold encryption results (ciphertext and IV)
     */
    public static class EncryptionResult {
        private final byte[] ciphertext;
        private final byte[] iv;

        public EncryptionResult(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public byte[] getIv() {
            return iv;
        }
    }

    /**
     * Demonstrates how to use the SymmetricCryptoUtil class
     */
    public static void main(String[] args) {
        try {
            // Create an instance of the utility
            SymmetricCryptoUtil util = new SymmetricCryptoUtil();

            // Generate a new AES key (256 bits)
            SecretKey key = util.generateKey(AES, 256);

            // Text to encrypt
            String plaintext = "This is a test message for symmetric encryption.";

            // Encrypt the text using AES in GCM mode with PKCS5 padding
            String encrypted = util.encryptToBase64(plaintext, key, AES, GCM, PKCS5_PADDING);
            System.out.println("Encrypted: " + encrypted);

            // Decrypt the text
            String decrypted = util.decryptFromBase64(encrypted, key, AES, GCM, PKCS5_PADDING);
            System.out.println("Decrypted: " + decrypted);

        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}
