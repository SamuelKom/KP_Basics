package crypto.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {

    // Common hash algorithms
    public enum HashAlgorithm {
        MD5("MD5"),
        SHA1("SHA1"),
        SHA256("SHA256"),
        SHA512("SHA512");

        private final String algorithmName;

        HashAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        public String getAlgorithmName() {
            return algorithmName;
        }
    }

    /**
     * Hashes a string using the specified algorithm.
     *
     * @param input The string to hash
     * @param algorithm The hashing algorithm to use
     * @return The hex string representation of the hash
     * @throws NoSuchAlgorithmException If the specified algorithm is not available
     */
    public static String hash(String input, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getAlgorithmName());
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashBytes);
    }

    /**
     * Verifies if a hash matches the hash of the input string using the specified algorithm.
     *
     * @param input The input string
     * @param hash The hash to verify against
     * @param algorithm The hashing algorithm that was used
     * @return true if the hash matches, false otherwise
     * @throws NoSuchAlgorithmException If the specified algorithm is not available
     */
    public static boolean verify(String input, String hash, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        String computedHash = hash(input, algorithm);
        return computedHash.equalsIgnoreCase(hash);
    }

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes The byte array to convert
     * @return A hexadecimal string representation of the byte array
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Returns a formatted string listing all available hash algorithms.
     *
     * @return A string containing all available hash algorithms
     */
    public static String getAvailableAlgorithmsInfo() {
        StringBuilder sb = new StringBuilder("--- Available Hash Algorithms ---\n");
        int i = 1;
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            sb.append(i).append(". ").append(algorithm.name()).append("\n");
            i++;
        }
        return sb.toString();
    }
}
