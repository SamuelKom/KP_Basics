package crypto.rsa;

import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import static org.junit.jupiter.api.Assertions.*;

public class RSAEncryptionTest {

    @Test
    public void testEncryptionDecryption() {
        RSAEncryption rsa = new RSAEncryption();
        BigInteger message = new BigInteger("123456789");
        BigInteger encrypted = rsa.encrypt(message);
        BigInteger decrypted = rsa.decrypt(encrypted);

        assertEquals(message, decrypted, "Decrypted message should match the original");
    }

    @Test
    public void testDifferentMessages() {
        RSAEncryption rsa = new RSAEncryption();
        BigInteger message1 = new BigInteger("123456789");
        BigInteger message2 = new BigInteger("987654321");

        BigInteger encrypted1 = rsa.encrypt(message1);
        BigInteger encrypted2 = rsa.encrypt(message2);

        assertNotEquals(encrypted1, encrypted2, "Different messages should have different ciphertexts");
    }

}
