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
    String masterPassword = "masterPw";
    String password = "somePassword";

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

        try (OutputStream fos = Files.newOutputStream(Paths.get("./target/sec.xml"))) {
            new SecurityConfigurationStaxWriter().write(fos, sec);
        }
        System.setProperty(DefaultSecDispatcher.SYSTEM_PROPERTY_CONFIGURATION_LOCATION, "./target/sec.xml");
    }

    @Test
    void testRoundTripWithDispatcher() throws Exception {
        saveSec(
                "master",
                Map.of("masterSource", "system-property:masterPassword", "masterCipher", AESGCMNoPadding.CIPHER_ALG));
        DefaultSecDispatcher sd = construct();

        assertEquals(1, sd.availableDispatchers().size());
        String encrypted = sd.encrypt("supersecret", Map.of(SecDispatcher.DISPATCHER_NAME_ATTR, "master", "a", "b"));
        assertTrue(encrypted.startsWith("{") && encrypted.endsWith("}"));
        assertTrue(encrypted.contains("name=master"));
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
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);
    }
}
