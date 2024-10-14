/*
 * Copyright (c) 2008 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */

package org.codehaus.plexus.components.secdispatcher.internal.dispatchers;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.CipherException;
import org.codehaus.plexus.components.secdispatcher.Dispatcher;
import org.codehaus.plexus.components.secdispatcher.DispatcherMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.xml.sax.InputSource;

/**
 * This dispatcher is legacy, serves the purpose of migration only. Should not be used.
 */
@Singleton
@Named(LegacyDispatcher.NAME)
public class LegacyDispatcher implements Dispatcher, DispatcherMeta {
    public static final String NAME = "legacy";

    private static final String MASTER_MASTER_PASSWORD = "settings.security";

    private final LegacyCipher legacyCipher;

    @Inject
    public LegacyDispatcher() {
        this.legacyCipher = new LegacyCipher();
    }

    @Override
    public boolean isHidden() {
        return true;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String displayName() {
        return "LEGACY (for migration purposes only; can only decrypt)";
    }

    @Override
    public Collection<Field> fields() {
        return List.of();
    }

    @Override
    public EncryptPayload encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        throw new SecDispatcherException(
                NAME + " dispatcher MUST not be used for encryption; is inherently insecure and broken");
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        String masterPassword = getMasterPassword();
        if (masterPassword == null) {
            throw new SecDispatcherException("Master password could not be obtained");
        }
        return legacyCipher.decrypt64(str, masterPassword);
    }

    @Override
    public SecDispatcher.ValidationResponse validateConfiguration(Map<String, String> config) {
        HashMap<SecDispatcher.ValidationResponse.Level, List<String>> report = new HashMap<>();
        boolean valid = false;
        try {
            String mpe = getMasterMasterPasswordFromSettingsSecurityXml();
            if (mpe == null) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("Legacy configuration not found or does not contains encrypted master password");
            } else {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.INFO, k -> new ArrayList<>())
                        .add("Legacy configuration found with encrypted master password");

                String mp = getMasterPassword();
                if (mp == null) {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                            .add("Legacy master password not found");
                } else {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.INFO, k -> new ArrayList<>())
                            .add("Legacy master password successfully decrypted");
                    valid = true;
                }
            }
        } catch (CipherException e) {
            report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                    .add("Legacy master password decryption failed");
        }
        return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), valid, report, List.of());
    }

    private String getMasterPassword() throws SecDispatcherException {
        String masterPassword = getMasterMasterPasswordFromSettingsSecurityXml();
        if (masterPassword == null) {
            return null;
        }
        if (masterPassword.startsWith("{") && masterPassword.endsWith("}")) {
            return legacyCipher.decrypt64(
                    masterPassword.substring(1, masterPassword.length() - 1), MASTER_MASTER_PASSWORD);
        } else {
            return masterPassword;
        }
    }

    private String getMasterMasterPasswordFromSettingsSecurityXml() {
        Path xml;
        String override = System.getProperty(MASTER_MASTER_PASSWORD);
        if (override != null) {
            xml = Paths.get(override);
        } else {
            xml = Paths.get(System.getProperty("user.home"), ".m2", "settings-security.xml");
        }
        if (Files.exists(xml)) {
            try (InputStream is = Files.newInputStream(xml)) {
                return (String) XPathFactory.newInstance()
                        .newXPath()
                        .evaluate("//master", new InputSource(is), XPathConstants.STRING);
            } catch (Exception e) {
                // just ignore whatever it is
            }
        }
        return null;
    }

    private static final class LegacyCipher {
        private static final String STRING_ENCODING = "UTF8";
        private static final int SPICE_SIZE = 16;
        private static final int SALT_SIZE = 8;
        private static final String DIGEST_ALG = "SHA-256";
        private static final String KEY_ALG = "AES";
        private static final String CIPHER_ALG = "AES/CBC/PKCS5Padding";

        private String decrypt64(final String encryptedText, final String password) throws CipherException {
            try {
                byte[] allEncryptedBytes = Base64.getDecoder().decode(encryptedText.getBytes());
                int totalLen = allEncryptedBytes.length;
                byte[] salt = new byte[SALT_SIZE];
                System.arraycopy(allEncryptedBytes, 0, salt, 0, SALT_SIZE);
                byte padLen = allEncryptedBytes[SALT_SIZE];
                byte[] encryptedBytes = new byte[totalLen - SALT_SIZE - 1 - padLen];
                System.arraycopy(allEncryptedBytes, SALT_SIZE + 1, encryptedBytes, 0, encryptedBytes.length);
                Cipher cipher = createCipher(password.getBytes(STRING_ENCODING), salt, Cipher.DECRYPT_MODE);
                byte[] clearBytes = cipher.doFinal(encryptedBytes);
                return new String(clearBytes, STRING_ENCODING);
            } catch (Exception e) {
                throw new CipherException("Error decrypting", e);
            }
        }

        private Cipher createCipher(final byte[] pwdAsBytes, byte[] salt, final int mode)
                throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                        InvalidAlgorithmParameterException {
            MessageDigest _digester = MessageDigest.getInstance(DIGEST_ALG);
            byte[] keyAndIv = new byte[SPICE_SIZE * 2];
            if (salt == null || salt.length == 0) {
                salt = null;
            }
            byte[] result;
            int currentPos = 0;
            while (currentPos < keyAndIv.length) {
                _digester.update(pwdAsBytes);
                if (salt != null) {
                    _digester.update(salt, 0, 8);
                }
                result = _digester.digest();
                int stillNeed = keyAndIv.length - currentPos;
                if (result.length > stillNeed) {
                    byte[] b = new byte[stillNeed];
                    System.arraycopy(result, 0, b, 0, b.length);
                    result = b;
                }
                System.arraycopy(result, 0, keyAndIv, currentPos, result.length);
                currentPos += result.length;
                if (currentPos < keyAndIv.length) {
                    _digester.reset();
                    _digester.update(result);
                }
            }
            byte[] key = new byte[SPICE_SIZE];
            byte[] iv = new byte[SPICE_SIZE];
            System.arraycopy(keyAndIv, 0, key, 0, key.length);
            System.arraycopy(keyAndIv, key.length, iv, 0, iv.length);
            Cipher cipher = Cipher.getInstance(CIPHER_ALG);
            cipher.init(mode, new SecretKeySpec(key, KEY_ALG), new IvParameterSpec(iv));
            return cipher;
        }
    }
}
