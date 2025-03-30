package crypto.hmac;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacUtil {

    public static final String HMAC_SHA256 = "HmacSHA256";

    /**
     * Generates an HMAC for the given message using the specified key and algorithm
     *
     * @param message The message to generate HMAC for
     * @param key The secret key bytes
     * @param algorithm The HMAC algorithm to use (e.g., "HmacSHA256")
     * @return The raw HMAC bytes
     * @throws NoSuchAlgorithmException If the specified algorithm is not available
     * @throws InvalidKeyException If the provided key is invalid
     */
    public byte[] generateHmacBytes(byte[] message, byte[] key, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {

        // Create a key specification for the given key
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);

        // Get MAC instance with the specified algorithm
        Mac mac = Mac.getInstance(algorithm);

        // Initialize MAC with the secret key
        mac.init(secretKeySpec);

        // Compute the HMAC
        return mac.doFinal(message);
    }

    /**
     * Generates an HMAC for the given message using the specified key and algorithm
     *
     * @param message The message to generate HMAC for as a String
     * @param key The secret key as a String
     * @param algorithm The HMAC algorithm to use (e.g., "HmacSHA256")
     * @return The HMAC encoded as a Base64 string
     * @throws NoSuchAlgorithmException If the specified algorithm is not available
     * @throws InvalidKeyException If the provided key is invalid
     */
    public String generateHmac(String message, String key, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeyException {

        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        byte[] hmacBytes = generateHmacBytes(messageBytes, keyBytes, algorithm);

        // Encode the HMAC as a Base64 string
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    /**
     * Verifies if the provided HMAC matches the expected HMAC for the given message and key
     *
     * @param message The original message
     * @param key The secret key
     * @param expectedHmac The expected HMAC (Base64 encoded)
     * @param algorithm The HMAC algorithm used (e.g., "HmacSHA256")
     * @return true if the HMACs match, false otherwise
     */
    public boolean verifyHmac(String message, String key, String expectedHmac, String algorithm) {
        try {
            String calculatedHmac = generateHmac(message, key, algorithm);
            return calculatedHmac.equals(expectedHmac);
        } catch (Exception e) {
            return false;
        }
    }
}
