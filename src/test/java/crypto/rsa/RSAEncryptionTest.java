package crypto.rsa;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

public class RSAEncryptionTest {

    @Test
    public void testEncryptionDecryption() {
        RSAEncryption rsa = new RSAEncryption();
        String message = "hello world";
        BigInteger encrypted = rsa.encrypt(message);
        String decrypted = rsa.decrypt(encrypted);

        assertEquals(message, decrypted, "Decrypted message should match the original");
    }

    @Test
    public void testDifferentMessages() {
        RSAEncryption rsa = new RSAEncryption();
        String message1 = "123456789";
        String message2 = "987654321";

        BigInteger encrypted1 = rsa.encrypt(message1);
        BigInteger encrypted2 = rsa.encrypt(message2);

        assertNotEquals(encrypted1, encrypted2, "Different messages should have different ciphertexts");
    }

    @Test
    public void testSameCiphertext() {
        RSAEncryption rsa = new RSAEncryption();
        String message1 = "987654321";
        String message2 = "987654321";

        BigInteger encrypted1 = rsa.encrypt(message1);
        BigInteger encrypted2 = rsa.encrypt(message2);

        assertEquals(encrypted1, encrypted2, "Same messages should have same ciphertexts");
    }

}
