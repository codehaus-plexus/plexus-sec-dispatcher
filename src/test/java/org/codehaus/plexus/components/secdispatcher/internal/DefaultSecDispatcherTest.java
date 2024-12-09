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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.cipher.AESGCMNoPadding;
import org.codehaus.plexus.components.secdispatcher.internal.dispatchers.LegacyDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.dispatchers.MasterDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.sources.EnvMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.GpgAgentMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.SystemPropertyMasterSource;
import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DefaultSecDispatcherTest {
    private final Path CONFIG_PATH = Paths.get("./target/sec.xml");

    private void saveSec(String dispatcher, Map<String, String> config) throws Exception {
        SettingsSecurity sec = new SettingsSecurity();
        sec.setModelEncoding(StandardCharsets.UTF_8.name());
        sec.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        sec.setDefaultDispatcher(dispatcher);
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

        try (OutputStream fos = Files.newOutputStream(CONFIG_PATH)) {
            new SecurityConfigurationStaxWriter().write(fos, sec);
        }
    }

    @Test
    void masterWithEnvRoundTrip() throws Exception {
        saveSec("master", Map.of("source", "env:MASTER_PASSWORD", "cipher", AESGCMNoPadding.CIPHER_ALG));
        roundtrip();
    }

    @Test
    void masterWithSystemPropertyRoundTrip() throws Exception {
        saveSec("master", Map.of("source", "system-property:masterPassword", "cipher", AESGCMNoPadding.CIPHER_ALG));
        roundtrip();
    }

    @Test
    void validate() throws Exception {
        saveSec("master", Map.of("source", "system-property:masterPassword", "cipher", AESGCMNoPadding.CIPHER_ALG));
        System.setProperty("settings.security", "src/test/legacy/legacy-settings-security-1.xml");

        SecDispatcher secDispatcher = construct();
        SecDispatcher.ValidationResponse response = secDispatcher.validateConfiguration();
        assertTrue(response.isValid());
        // secDispatcher
        assertEquals(1, response.getReport().size());
        assertEquals(2, response.getSubsystems().size());
        // master dispatcher
        assertEquals(1, response.getSubsystems().get(0).getReport().size());
        assertEquals(1, response.getSubsystems().get(0).getSubsystems().size());
        // master source
        assertEquals(
                1,
                response.getSubsystems()
                        .get(0)
                        .getSubsystems()
                        .get(0)
                        .getReport()
                        .size());
        assertEquals(
                0,
                response.getSubsystems()
                        .get(0)
                        .getSubsystems()
                        .get(0)
                        .getSubsystems()
                        .size());
    }

    @Test
    void detection() {
        SecDispatcher secDispatcher = construct();
        assertFalse(secDispatcher.isAnyEncryptedString(null));
        assertFalse(secDispatcher.isAnyEncryptedString(""));
        assertFalse(secDispatcher.isAnyEncryptedString("foo"));

        assertFalse(secDispatcher.isEncryptedString("{foo}"));
        assertTrue(secDispatcher.isLegacyEncryptedString("{foo}"));
        assertFalse(secDispatcher.isEncryptedString("Oleg was here {foo}"));
        assertTrue(secDispatcher.isLegacyEncryptedString("Oleg was here {foo}"));
        assertTrue(secDispatcher.isLegacyEncryptedString("Oleg {foo} was here"));

        assertFalse(secDispatcher.isEncryptedString("{12345678901234567890123456789012345678901234567890}"));
        assertTrue(secDispatcher.isLegacyEncryptedString("{12345678901234567890123456789012345678901234567890}"));
        assertFalse(
                secDispatcher.isEncryptedString("Oleg was here {12345678901234567890123456789012345678901234567890}"));
        assertTrue(secDispatcher.isLegacyEncryptedString(
                "{12345678901234567890123456789012345678901234567890} Oleg was here"));
        assertTrue(secDispatcher.isLegacyEncryptedString(
                "Oleg {12345678901234567890123456789012345678901234567890} was here"));

        // contains {} in the middle
        assertFalse(secDispatcher.isEncryptedString("{KDvsYOFLlX{}gH4LU8tvpzAGg5otiosZXvfdQq0yO86LU=}"));
        assertFalse(secDispatcher.isLegacyEncryptedString("{KDvsYOFLlX{}gH4LU8tvpzAGg5otiosZXvfdQq0yO86LU=}"));
        assertFalse(secDispatcher.isLegacyEncryptedString(
                "Oleg was here {KDvsYOFLlX{}gH4LU8tvpzAGg5otiosZXvfdQq0yO86LU=}"));

        assertFalse(secDispatcher.isEncryptedString("{KDvsYOFLlXgH4LU8tvpzAGg5otiosZXvfdQq0yO86LU=}"));
        assertTrue(secDispatcher.isLegacyEncryptedString("{KDvsYOFLlXgH4LU8tvpzAGg5otiosZXvfdQq0yO86LU=}"));
        assertTrue(
                secDispatcher.isLegacyEncryptedString("Oleg was here {KDvsYOFLlXgH4LU8tvpzAGg5otiosZXvfdQq0yO86LU=}"));

        assertTrue(
                secDispatcher.isEncryptedString(
                        "{[name=master,cipher=AES/GCM/NoPadding,version=4.0,a=b]vvq66pZ7rkvzSPStGTI9q4QDnsmuDwo+LtjraRel2b0XpcGJFdXcYAHAS75HUA6GLpcVtEkmyQ==}"));
        assertFalse(
                secDispatcher.isLegacyEncryptedString(
                        "{[name=master,cipher=AES/GCM/NoPadding,version=4.0,a=b]vvq66pZ7rkvzSPStGTI9q4QDnsmuDwo+LtjraRel2b0XpcGJFdXcYAHAS75HUA6GLpcVtEkmyQ==}"));
    }

    protected void roundtrip() throws Exception {
        DefaultSecDispatcher sd = construct();

        assertEquals(2, sd.availableDispatchers().size());
        String encrypted = sd.encrypt("supersecret", Map.of(SecDispatcher.DISPATCHER_NAME_ATTR, "master", "a", "b"));
        // example:
        // {[name=master,cipher=AES/GCM/NoPadding,a=b]vvq66pZ7rkvzSPStGTI9q4QDnsmuDwo+LtjraRel2b0XpcGJFdXcYAHAS75HUA6GLpcVtEkmyQ==}
        assertTrue(encrypted.startsWith("{") && encrypted.endsWith("}"));
        assertTrue(encrypted.contains("name=master"));
        assertTrue(encrypted.contains("cipher=" + AESGCMNoPadding.CIPHER_ALG));
        assertTrue(encrypted.contains("version=test"));
        assertTrue(encrypted.contains("a=b"));
        String pass = sd.decrypt(encrypted);
        assertEquals("supersecret", pass);
    }

    protected DefaultSecDispatcher construct() {
        return new DefaultSecDispatcher(
                Map.of(
                        "master",
                        new MasterDispatcher(
                                Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding()),
                                Map.of(
                                        EnvMasterSource.NAME,
                                        new EnvMasterSource(),
                                        SystemPropertyMasterSource.NAME,
                                        new SystemPropertyMasterSource(),
                                        GpgAgentMasterSource.NAME,
                                        new GpgAgentMasterSource())),
                        "legacy",
                        new LegacyDispatcher()),
                CONFIG_PATH);
    }

    /**
     * Test values created with Maven 3.9.9.
     * <p>
     * master password: "masterpassword"
     * password: "password"
     */
    @ParameterizedTest
    @ValueSource(
            strings = {
                "src/test/legacy/legacy-settings-security-1.xml",
                "src/test/legacy/legacy-settings-security-2.xml"
            })
    void legacy(String xml) throws Exception {
        System.setProperty("settings.security", xml);
        SecDispatcher secDispatcher = construct();
        String cleartext = secDispatcher.decrypt("{L6L/HbmrY+cH+sNkphnq3fguYepTpM04WlIXb8nB1pk=}");
        assertEquals("password", cleartext);

        cleartext = secDispatcher.decrypt("Oleg was here {L6L/HbmrY+cH+sNkphnq3fguYepTpM04WlIXb8nB1pk=}");
        assertEquals("password", cleartext);

        cleartext = secDispatcher.decrypt("Oleg {L6L/HbmrY+cH+sNkphnq3fguYepTpM04WlIXb8nB1pk=} was here");
        assertEquals("password", cleartext);
    }
}
