package org.codehaus.plexus.components.secdispatcher.internal.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Named;
import javax.inject.Singleton;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.bouncycastle.jcajce.spec.Argon2KeySpec;
import org.codehaus.plexus.components.secdispatcher.CipherException;

@Singleton
@Named("Argon2" + Argon2AESGCMNoPadding.CIPHER_ALG)
public class Argon2AESGCMNoPadding implements org.codehaus.plexus.components.secdispatcher.Cipher {

    private static final int SALT_LENGTH_BYTE = 16;
    private static final int ARGON_NUM_PASSES = 2;
    private static final int ARGON_MEMORY_COST_KIB = 1 << 16;
    private static final int ARGON_NUM_LANES = 1;
    private static final int KEY_SIZE_BIT = 256;

    public static final String CIPHER_ALG = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final String KEY_ALGORITHM = "AES";

    @Override
    public String encrypt(String clearText, String password) throws CipherException {
        try {
            byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
            SecretKey secretKey = createSecretKey(password.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALG);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] cipherText = cipher.doFinal(clearText.getBytes(StandardCharsets.UTF_8));
            byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                    .put(iv)
                    .put(salt)
                    .put(cipherText)
                    .array();
            return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
        } catch (Exception e) {
            throw new CipherException("Failed encrypting", e);
        }
    }

    @Override
    public String decrypt(String encryptedText, String password) throws CipherException {
        try {
            byte[] material = Base64.getDecoder().decode(encryptedText.getBytes(StandardCharsets.UTF_8));
            ByteBuffer buffer = ByteBuffer.wrap(material);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            buffer.get(iv);
            byte[] salt = new byte[SALT_LENGTH_BYTE];
            buffer.get(salt);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);
            SecretKey secretKey = createSecretKey(password.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALG);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CipherException("Failed decrypting", e);
        }
    }

    /**
     * Use Argon2 from Bouncycastle (https://github.com/bcgit/bc-java/commit/1c15beda06a5f716941ae07680c81a335b6e78e0)
     * to derive a key from the password and salt.
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    private SecretKey createSecretKey(char[] password, byte[] salt)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        Argon2KeySpec spec = new Argon2KeySpec(
                Argon2KeySpec.ARGON2_i,
                Argon2KeySpec.ARGON2_VERSION_13,
                password,
                salt,
                ARGON_NUM_PASSES,
                ARGON_MEMORY_COST_KIB,
                ARGON_NUM_LANES,
                KEY_SIZE_BIT);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("ARGON2", "BC");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), KEY_ALGORITHM);
    }

    private static byte[] getRandomNonce(int numBytes) throws NoSuchAlgorithmException {
        byte[] nonce = new byte[numBytes];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        return nonce;
    }
}
