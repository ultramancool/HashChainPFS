package experimental.hashchainpfs;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * High level cryptography helper class using AES-128 in GCM mode and a SHA-256 hash chain to achieve perfect forward
 * secrecy without the need for a connection initialization handshake.
 */
public class HashChainForwardSecrecy implements Serializable {
    public static final int NUM_HASH_BYTES = 32;
    public static final int GCM_MAC_SIZE = 128;
    public static final int NONCE_SIZE_BYTES = 16;
    public static final int KEY_SIZE_BYTES = 16;
    private final byte[] currentKey;

    /**
     * Constructs a new HashChainForwardSecrecy with a random starting key (generated using SecureRandom)
     */
    public HashChainForwardSecrecy() {
        SecureRandom random = new SecureRandom();
        currentKey = random.generateSeed(NUM_HASH_BYTES);
    }

    /**
     * Constructs a new HashChainForwardSecrecy with a given starting key
     *
     * @param currentKey the given key
     */
    public HashChainForwardSecrecy(byte[] currentKey) {
        this.currentKey = currentKey;
        assert this.currentKey.length == NUM_HASH_BYTES; // assure we have correct key length
    }

    /**
     * Returns the current key in the hash chain.
     * <p/>
     * Some notes on securing the key and keeping forward secrecy working:
     * <p/>
     * Keeping any but the latest version of this destroys the purpose of this perfect forward secrecy completely.
     * Only store the latest version securely when the user is done using the application (or don't store it at all).
     * <p/>
     * May be used for initial synchronization purposes. Could be done via QR code or communicated via an established
     * PFS medium such as SSH2. Performing this securely is up to the implementer.
     *
     * @return the current key in the hash chain
     */
    public byte[] getCurrentKey() {
        return currentKey;
    }

    private GCMBlockCipher createCipher(boolean encrypt) {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESFastEngine());

        byte[] nonce = Arrays.copyOfRange(currentKey, 0, NONCE_SIZE_BYTES);
        byte[] key = Arrays.copyOfRange(currentKey, NONCE_SIZE_BYTES, NONCE_SIZE_BYTES + KEY_SIZE_BYTES);

        AEADParameters aeadParameters = new AEADParameters(new KeyParameter(key), GCM_MAC_SIZE, nonce, null);
        gcm.init(encrypt, aeadParameters);
        return gcm;
    }

    /**
     * Decrypts a given ciphertext to its plaintext using the current key
     *
     * @param ciphertext the encrypted ciphertext
     * @return the decrypted message
     * @throws InvalidCipherTextException if MAC fails
     */
    public byte[] decryptMessage(byte[] ciphertext) throws InvalidCipherTextException {
        GCMBlockCipher gcm = createCipher(false);
        byte[] data = new byte[gcm.getOutputSize(ciphertext.length)];
        int offset = gcm.processBytes(ciphertext, 0, ciphertext.length, data, 0);
        gcm.doFinal(data, offset);
        return data;
    }

    /**
     * Moves to the next key in the hash chain by changing the key to the hash of the current key.
     */
    public void advance() {
        SHA256Digest digest = new SHA256Digest();
        digest.update(currentKey, 0, currentKey.length);
        digest.doFinal(currentKey, 0);
    }

    /**
     * Encrypts a plaintext to a ciphertext using the current key
     *
     * @param message plaintext message to encrypt
     * @return the encrypted ciphertext
     * @throws InvalidCipherTextException MAC creation failure
     */
    public byte[] encryptMessage(byte[] message) throws InvalidCipherTextException {
        GCMBlockCipher gcm = createCipher(true);
        byte[] data = new byte[gcm.getOutputSize(message.length)];
        int offset = gcm.processBytes(message, 0, message.length, data, 0);
        gcm.doFinal(data, offset);
        return data;
    }
}
