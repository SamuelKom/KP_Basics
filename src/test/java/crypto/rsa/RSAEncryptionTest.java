package crypto.rsa;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

public class RSAEncryptionTest {

    @Test
    public void testEncryptionDecryption() {
        RSAUtils.generateRSAKeys();
        String message = "hello world";

        BigInteger pubKey = new BigInteger(RSAUtils.getPublicKey());
        RSAUtils.setServerPublicKey(pubKey);

        BigInteger encrypted = RSAUtils.encryptWithServerPublicKey(message);
        String decrypted = RSAUtils.decryptRSA(encrypted);

        assertEquals(message, decrypted, "Decrypted message should match the original");
    }

    @Test
    public void testDifferentMessages() {
        RSAUtils.generateRSAKeys();
        String message1 = "123456789";
        String message2 = "987654321";

        BigInteger pubKey = new BigInteger(RSAUtils.getPublicKey());
        RSAUtils.setClientPublicKey(pubKey);

        BigInteger encrypted1 = RSAUtils.encryptWithClientPublicKey(message1);
        BigInteger encrypted2 = RSAUtils.encryptWithClientPublicKey(message2);

        assertNotEquals(encrypted1, encrypted2, "Different messages should have different ciphertexts");
    }

    @Test
    public void testSameCiphertext() {
        RSAUtils.generateRSAKeys();
        String message1 = "987654321";
        String message2 = "987654321";

        BigInteger pubKey = new BigInteger(RSAUtils.getPublicKey());
        RSAUtils.setClientPublicKey(pubKey);

        BigInteger encrypted1 = RSAUtils.encryptWithClientPublicKey(message1);
        BigInteger encrypted2 = RSAUtils.encryptWithClientPublicKey(message2);

        assertEquals(encrypted1, encrypted2, "Same messages should have same ciphertexts");
    }

}
