package experimental.hashchainpfs;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(JUnit4.class)
public class HashChainForwardSecrecyTest {
    @Test
    public void testEncryptMessage() throws Exception {
        HashChainForwardSecrecy hashChainForwardSecrecy = new HashChainForwardSecrecy();
        String testString = "This is a pretty long message, isn't it?";
        byte[] encrypted =
                hashChainForwardSecrecy.encryptMessage(testString.getBytes("UTF8"));
        byte[] decrypted = hashChainForwardSecrecy.decryptMessage(encrypted);

        String decryptedString = new String(decrypted, "UTF8");
        assertEquals(decryptedString, testString);
    }

    @Test(expected = InvalidCipherTextException.class)
    public void testMacFailure() throws Exception {

        HashChainForwardSecrecy hashChainForwardSecrecy = new HashChainForwardSecrecy();
        String testString = "This is a pretty long message, isn't it?";
        byte[] encrypted = hashChainForwardSecrecy.encryptMessage(testString.getBytes("UTF8"));
        encrypted[0] = 0; // modify a byte so mac will fail

        hashChainForwardSecrecy.decryptMessage(encrypted);
    }

    @Test
    public void testAdvance() throws Exception {
        HashChainForwardSecrecy hashChainForwardSecrecy = new HashChainForwardSecrecy();
        byte[] oldKey = hashChainForwardSecrecy.getCurrentKey().clone();
        hashChainForwardSecrecy.advance();
        assertFalse(Arrays.equals(oldKey, hashChainForwardSecrecy.getCurrentKey()));
    }
}