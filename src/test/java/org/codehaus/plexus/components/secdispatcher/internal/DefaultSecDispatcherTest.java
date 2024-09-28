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

package org.codehaus.plexus.components.secdispatcher.internal;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import org.codehaus.plexus.components.cipher.internal.AESGCMNoPadding;
import org.codehaus.plexus.components.cipher.internal.DefaultPlexusCipher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.dispatcher.StaticDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.sources.EnvMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.GpgAgentMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.StaticMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.SystemPropertyMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DefaultSecDispatcherTest {
    String masterPassword = "masterPw";
    String password = "somePassword";

    private void saveSec(String masterSource) throws Exception {
        SettingsSecurity sec = new SettingsSecurity();
        sec.setModelEncoding(StandardCharsets.UTF_8.name());
        sec.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        sec.setMasterSource(masterSource);
        sec.setMasterCipher(AESGCMNoPadding.CIPHER_ALG);

        try (OutputStream fos = Files.newOutputStream(Paths.get("./target/sec.xml"))) {
            new SecurityConfigurationStaxWriter().write(fos, sec);
        }
        System.setProperty(DefaultSecDispatcher.SYSTEM_PROPERTY_CONFIGURATION_LOCATION, "./target/sec.xml");
    }

    @BeforeEach
    public void prepare() throws Exception {
        saveSec("magic:might");
    }

    @Test
    void testEncrypt() throws Exception {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String enc = sd.encrypt(password, null);
        assertNotNull(enc);
        String password1 = sd.decrypt(enc);
        assertEquals(password, password1);
    }

    @Test
    void testDecrypt() throws Exception {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String encrypted = sd.encrypt(password, null);
        String pass = sd.decrypt(encrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Test
    void testDecryptSystemProperty() throws Exception {
        System.setProperty("foobar", masterPassword);
        saveSec("prop:foobar");
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of(
                        "prop",
                        new SystemPropertyMasterPasswordSource(),
                        "env",
                        new EnvMasterPasswordSource(),
                        "gpg",
                        new GpgAgentMasterPasswordSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String encrypted = sd.encrypt(password, null);
        String pass = sd.decrypt(encrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Test
    void testDecryptEnv() throws Exception {
        saveSec("env:MASTER_PASSWORD");
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of(
                        "prop",
                        new SystemPropertyMasterPasswordSource(),
                        "env",
                        new EnvMasterPasswordSource(),
                        "gpg",
                        new GpgAgentMasterPasswordSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String encrypted = sd.encrypt(password, null);
        String pass = sd.decrypt(encrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Disabled("triggers GPG agent: remove this and type in 'masterPw'")
    @Test
    void testDecryptGpg() throws Exception {
        saveSec("gpg-agent:/run/user/1000/gnupg/S.gpg-agent");
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of(
                        "prop",
                        new SystemPropertyMasterPasswordSource(),
                        "env",
                        new EnvMasterPasswordSource(),
                        "gpg",
                        new GpgAgentMasterPasswordSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String encrypted = sd.encrypt(password, null);
        String pass = sd.decrypt(encrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Test
    void testEncryptWithDispatcher() throws Exception {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of("magic", new StaticDispatcher("decrypted", "encrypted")),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);

        assertEquals(Set.of("magic"), sd.availableDispatchers());
        String enc = sd.encrypt("whatever", Map.of(SecDispatcher.DISPATCHER_NAME_ATTR, "magic", "a", "b"));
        assertNotNull(enc);
        assertTrue(enc.contains("encrypted"));
        assertTrue(enc.contains(SecDispatcher.DISPATCHER_NAME_ATTR + "=magic"));
        String password1 = sd.decrypt(enc);
        assertEquals("decrypted", password1);
    }

    @Test
    void testDecryptWithDispatcher() throws Exception {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of("magic", new StaticDispatcher("decrypted", "encrypted")),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);

        assertEquals(Set.of("magic"), sd.availableDispatchers());
        String pass = sd.decrypt("{" + "[a=b," + SecDispatcher.DISPATCHER_NAME_ATTR + "=magic]"
                + Base64.getEncoder().encodeToString("whatever".getBytes(StandardCharsets.UTF_8)) + "}");
        assertNotNull(pass);
        assertEquals("decrypted", pass);
    }

    @Test
    void testDecryptWithDispatcherConf() throws Exception {
        String bare = Base64.getEncoder().encodeToString("whatever".getBytes(StandardCharsets.UTF_8));
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of("magic", new Dispatcher() {
                    @Override
                    public String encrypt(String str, Map<String, String> attributes, Map<String, String> config)
                            throws SecDispatcherException {
                        throw new IllegalStateException("should not be called");
                    }

                    @Override
                    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
                            throws SecDispatcherException {
                        assertEquals(bare, str);
                        assertEquals(2, attributes.size());
                        assertEquals("magic", attributes.get(SecDispatcher.DISPATCHER_NAME_ATTR));
                        assertEquals("value", attributes.get("key"));

                        assertEquals(1, config.size());
                        assertEquals(masterPassword, config.get(Dispatcher.CONF_MASTER_PASSWORD));

                        return "magic";
                    }
                }),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);

        assertEquals(Set.of("magic"), sd.availableDispatchers());
        String pass = sd.decrypt("{" + "[key=value," + SecDispatcher.DISPATCHER_NAME_ATTR + "=magic]"
                + Base64.getEncoder().encodeToString("whatever".getBytes(StandardCharsets.UTF_8)) + "}");
        assertNotNull(pass);
        assertEquals("magic", pass);
    }
}
