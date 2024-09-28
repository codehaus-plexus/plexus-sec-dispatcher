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
import org.codehaus.plexus.components.secdispatcher.internal.decryptor.StaticPasswordDecryptor;
import org.codehaus.plexus.components.secdispatcher.internal.sources.EnvMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.GpgAgentMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.StaticMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.SystemPropertyMasterPasswordSource;
import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.xpp3.SecurityConfigurationXpp3Writer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 *
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public class SecUtilTest {
    String masterPassword = "masterPw";
    String password = "somePassword";
    String passwordEncrypted = "{a/8OtPCGPvQLUVF+n6+UDTD3SeRCdqb0tPJLF71cs29M9Ms81MAb3Y1XG/TS4C4f}";

    String _confName = "cname";

    String _propName = "pname";

    String _propVal = "pval";

    private void saveSec(String masterSource) throws Exception {
        SettingsSecurity sec = new SettingsSecurity();

        sec.setRelocation(null);
        sec.setMasterSource(masterSource);

        ConfigProperty cp = new ConfigProperty();
        cp.setName(_propName);
        cp.setValue(_propVal);

        Config conf = new Config();
        conf.setName(_confName);
        conf.addProperty(cp);

        sec.addConfiguration(conf);

        new SecurityConfigurationXpp3Writer().write(new FileWriter("./target/sec1.xml"), sec);
    }

    @BeforeEach
    public void prepare() throws Exception {
        System.setProperty(DefaultSecDispatcher.SYSTEM_PROPERTY_SEC_LOCATION, "./target/sec.xml");

        SettingsSecurity sec = new SettingsSecurity();

        sec.setRelocation("./target/sec1.xml");
        new SecurityConfigurationXpp3Writer().write(new FileWriter("./target/sec.xml"), sec);

        saveSec("magic:mighty");
    }

    @Test
    void testRead() throws Exception {
        SettingsSecurity sec = SecUtil.read("./target/sec.xml", true);

        assertNotNull(sec);

        assertEquals("magic:mighty", sec.getMasterSource());

        Map<String, String> conf = SecUtil.getConfig(sec, _confName);

        assertNotNull(conf);

        assertNotNull(conf.get(_propName));

        assertEquals(_propVal, conf.get(_propName));
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
        saveSec("system-property:/foobar");
        // /run/user/1000/gnupg/S.gpg-agent
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
        saveSec("env:/MASTER_PASSWORD");
        // /run/user/1000/gnupg/S.gpg-agent
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

    @Disabled("triggers GPG agent: remove this and type in master pw")
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
    void testDecryptWithDecryptor() throws Exception {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(
                new DefaultPlexusCipher(),
                Map.of("static", new StaticMasterPasswordSource(masterPassword)),
                Map.of("magic", new StaticPasswordDecryptor("magic")),
                DefaultSecDispatcher.DEFAULT_CONFIGURATION);

        String pass = sd.decrypt("{" + Base64.getEncoder().encodeToString("whatever".getBytes(StandardCharsets.UTF_8))
                + "[a=b,type=magic]}");

        assertNotNull(pass);

        assertEquals("magic", pass);
    }
}
