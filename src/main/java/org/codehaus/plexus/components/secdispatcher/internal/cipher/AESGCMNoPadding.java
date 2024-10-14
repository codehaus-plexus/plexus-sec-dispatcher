/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.codehaus.plexus.components.secdispatcher.internal.cipher;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Named;
import javax.inject.Singleton;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import org.codehaus.plexus.components.secdispatcher.CipherException;

@Singleton
@Named(AESGCMNoPadding.CIPHER_ALG)
public class AESGCMNoPadding implements org.codehaus.plexus.components.secdispatcher.Cipher {
    public static final String CIPHER_ALG = "AES/GCM/NoPadding";

    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final int PBE_ITERATIONS = 310000;
    private static final int PBE_KEY_SIZE = SALT_LENGTH_BYTE * 16;
    private static final String KEY_FACTORY = "PBKDF2WithHmacSHA512";
    private static final String KEY_ALGORITHM = "AES";

    @Override
    public String encrypt(String clearText, String password) throws CipherException {
        try {
            byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
            SecretKey secretKey = getAESKeyFromPassword(password.toCharArray(), salt);
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
            SecretKey secretKey = getAESKeyFromPassword(password.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALG);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new CipherException("Failed decrypting", e);
        }
    }

    private static byte[] getRandomNonce(int numBytes) throws NoSuchAlgorithmException {
        byte[] nonce = new byte[numBytes];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        return nonce;
    }

    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY);
        KeySpec spec = new PBEKeySpec(password, salt, PBE_ITERATIONS, PBE_KEY_SIZE);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), KEY_ALGORITHM);
    }
}
