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

import org.codehaus.plexus.components.cipher.internal.AESGCMNoPadding;
import org.codehaus.plexus.components.cipher.internal.DefaultPlexusCipher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.dispatchers.MasterDispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.sources.EnvMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.GpgAgentMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.SystemPropertyMasterSource;
import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxWriter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DefaultSecDispatcherTest {
    private final Path CONFIG_PATH = Paths.get("./target/sec.xml");

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

    protected void roundtrip() throws Exception {
        DefaultSecDispatcher sd = construct();

        assertEquals(1, sd.availableDispatchers().size());
        String encrypted = sd.encrypt("supersecret", Map.of(SecDispatcher.DISPATCHER_NAME_ATTR, "master", "a", "b"));
        // example:
        // {[name=master,cipher=AES/GCM/NoPadding,a=b]vvq66pZ7rkvzSPStGTI9q4QDnsmuDwo+LtjraRel2b0XpcGJFdXcYAHAS75HUA6GLpcVtEkmyQ==}
        assertTrue(encrypted.startsWith("{") && encrypted.endsWith("}"));
        assertTrue(encrypted.contains("name=master"));
        assertTrue(encrypted.contains("cipher=" + AESGCMNoPadding.CIPHER_ALG));
        assertTrue(encrypted.contains("a=b"));
        String pass = sd.decrypt(encrypted);
        assertEquals("supersecret", pass);
    }

    protected DefaultSecDispatcher construct() {
        DefaultPlexusCipher dpc = new DefaultPlexusCipher(Map.of(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding()));
        return new DefaultSecDispatcher(
                dpc,
                Map.of(
                        "master",
                        new MasterDispatcher(
                                dpc,
                                Map.of(
                                        EnvMasterSource.NAME,
                                        new EnvMasterSource(),
                                        SystemPropertyMasterSource.NAME,
                                        new SystemPropertyMasterSource(),
                                        GpgAgentMasterSource.NAME,
                                        new GpgAgentMasterSource()))),
                CONFIG_PATH);
    }
}
