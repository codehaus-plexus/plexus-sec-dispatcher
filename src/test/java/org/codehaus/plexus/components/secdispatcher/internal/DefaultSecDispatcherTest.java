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

import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.codehaus.plexus.components.cipher.internal.DefaultPlexusCipher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
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
    String passwordEncrypted = "{TT2NQZ4iAdoHqsSfYUab3s6X2IHl5qaf4vx/F8DvtSI=}";

    private void saveSec(String masterSource) throws Exception {
        SettingsSecurity sec = new SettingsSecurity();
        sec.setMasterSource(masterSource);

        try (FileWriter fw = new FileWriter("./target/sec.xml")) {
            new SecurityConfigurationStaxWriter().write(fw, sec);
            fw.flush();
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
                new DefaultPlexusCipher(),
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
                new DefaultPlexusCipher(),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String pass = sd.decrypt(passwordEncrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Test
    void testDecryptSystemProperty() throws Exception {
        System.setProperty("foobar", masterPassword);
        saveSec("prop:foobar");
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(),
                Map.of(
                        "prop",
                        new SystemPropertyMasterPasswordSource(),
                        "env",
                        new EnvMasterPasswordSource(),
                        "gpg",
                        new GpgAgentMasterPasswordSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String pass = sd.decrypt(passwordEncrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Test
    void testDecryptEnv() throws Exception {
        saveSec("env:MASTER_PASSWORD");
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(),
                Map.of(
                        "prop",
                        new SystemPropertyMasterPasswordSource(),
                        "env",
                        new EnvMasterPasswordSource(),
                        "gpg",
                        new GpgAgentMasterPasswordSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String pass = sd.decrypt(passwordEncrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Disabled("triggers GPG agent: remove this and type in 'masterPw'")
    @Test
    void testDecryptGpg() throws Exception {
        saveSec("gpg-agent:/run/user/1000/gnupg/S.gpg-agent");
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(),
                Map.of(
                        "prop",
                        new SystemPropertyMasterPasswordSource(),
                        "env",
                        new EnvMasterPasswordSource(),
                        "gpg",
                        new GpgAgentMasterPasswordSource()),
                Map.of(),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
        String pass = sd.decrypt(passwordEncrypted);
        assertNotNull(pass);
        assertEquals(password, pass);
    }

    @Test
    void testEncryptWithDispatcher() throws Exception {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of("magic", new StaticDispatcher("decrypted", "encrypted")),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);

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
                new DefaultPlexusCipher(),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of("magic", new StaticDispatcher("decrypted", "encrypted")),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);

        String pass = sd.decrypt("{" + Base64.getEncoder().encodeToString("whatever".getBytes(StandardCharsets.UTF_8))
                + "[a=b," + SecDispatcher.DISPATCHER_NAME_ATTR + "=magic]}");
        assertNotNull(pass);
        assertEquals("decrypted", pass);
    }
}
