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
import java.util.Map;

import org.codehaus.plexus.components.cipher.internal.AESGCMNoPadding;
import org.codehaus.plexus.components.cipher.internal.DefaultPlexusCipher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.dispatchers.TestDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.sources.EnvMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.GpgAgentMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.SystemPropertyMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.TestMasterSource;
import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
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
        saveSec(sec);
    }

    private void saveSec(String dispatcher, Map<String, String> config) throws Exception {
        SettingsSecurity sec = new SettingsSecurity();
        sec.setModelEncoding(StandardCharsets.UTF_8.name());
        sec.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        Config conf = new Config();
        conf.setName(dispatcher);
        for (Map.Entry<String, String> entry : config.entrySet()) {
            ConfigProperty prop = new ConfigProperty();
            prop.setName(entry.getKey());
            prop.setValue(entry.getValue());
            conf.addProperty(prop);
        }
        sec.getConfigurations().add(conf);
        saveSec(sec);
    }

    private void saveSec(SettingsSecurity sec) throws Exception {
        sec.setModelEncoding(StandardCharsets.UTF_8.name());
        sec.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
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
        saveSec("test:" + masterPassword);
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new TestMasterSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String enc = sd.encrypt(password, null);
        assertNotNull(enc);
        String password1 = sd.decrypt(enc);
        assertEquals(password, password1);
    }

    @Test
    void testDecrypt() throws Exception {
        saveSec("test:" + masterPassword);
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new TestMasterSource()),
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
                        new SystemPropertyMasterSource(),
                        "env",
                        new EnvMasterSource(),
                        "gpg",
                        new GpgAgentMasterSource()),
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
                        new SystemPropertyMasterSource(),
                        "env",
                        new EnvMasterSource(),
                        "gpg",
                        new GpgAgentMasterSource()),
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
                        new SystemPropertyMasterSource(),
                        "env",
                        new EnvMasterSource(),
                        "gpg",
                        new GpgAgentMasterSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String encrypted = sd.encrypt(password, null);
        String pass = sd.decrypt(encrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Test
    void testRoundTripWithDispatcher() throws Exception {
        saveSec("magic", Map.of("salt", "foobar"));
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding())),
                Map.of("static", new TestMasterSource()),
                Map.of("magic", new TestDispatcher()),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);

        assertEquals(1, sd.availableDispatchers().size());
        String encrypted = sd.encrypt("supersecret", Map.of(SecDispatcher.DISPATCHER_NAME_ATTR, "magic", "a", "b"));
        assertTrue(encrypted.startsWith("{") && encrypted.endsWith("}"));
        assertTrue(encrypted.contains("name=magic"));
        assertTrue(encrypted.contains("a=b"));
        assertTrue(encrypted.contains("tercesrepus@foobar"));
        // assertEquals("{[name=magic,a=b]tercesrepus@foobar}", encrypted);
        String pass = sd.decrypt(encrypted);
        assertEquals("supersecret", pass);
    }
}
