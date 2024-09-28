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
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public class SecUtilTest {
    String _confName = "cname";
    String _propName = "pname";
    String _propVal = "pval";

    private void saveSec(String masterSource) throws Exception {
        saveSec("./target/sec1.xml", masterSource);
    }

    private void saveSec(String path, String masterSource) throws Exception {
        SettingsSecurity sec = new SettingsSecurity();

        sec.setModelEncoding(StandardCharsets.UTF_8.name());
        sec.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        sec.setRelocation(null);
        sec.setMasterSource(masterSource);

        ConfigProperty cp = new ConfigProperty();
        cp.setName(_propName);
        cp.setValue(_propVal);

        Config conf = new Config();
        conf.setName(_confName);
        conf.addProperty(cp);

        sec.addConfiguration(conf);

        try (OutputStream fos = Files.newOutputStream(Paths.get(path))) {
            new SecurityConfigurationStaxWriter().write(fos, sec);
        }
    }

    @BeforeEach
    public void prepare() throws Exception {
        System.setProperty(DefaultSecDispatcher.SYSTEM_PROPERTY_CONFIGURATION_LOCATION, "./target/sec.xml");
        SettingsSecurity sec = new SettingsSecurity();
        sec.setModelEncoding(StandardCharsets.UTF_8.name());
        sec.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        sec.setRelocation("sec1.xml");
        try (OutputStream fos = Files.newOutputStream(Paths.get("./target/sec.xml"))) {
            new SecurityConfigurationStaxWriter().write(fos, sec);
        }
        saveSec("magic:mighty");
    }

    @Test
    void testReadWithRelocation() throws Exception {
        SettingsSecurity sec = SecUtil.read(Paths.get("./target/sec.xml"), true);
        assertNotNull(sec);
        assertEquals("magic:mighty", sec.getMasterSource());
        Map<String, String> conf = SecUtil.getConfig(sec, _confName);
        assertNotNull(conf);
        assertNotNull(conf.get(_propName));
        assertEquals(_propVal, conf.get(_propName));
    }

    @Test
    void testReadWithRelocationCycleSelf() throws Exception {
        Path sec1 = Paths.get("./target/sec-cycle-1.xml");
        SettingsSecurity s1 = new SettingsSecurity();
        s1.setModelEncoding(StandardCharsets.UTF_8.name());
        s1.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        s1.setRelocation("sec-cycle-1.xml");
        try (OutputStream fos = Files.newOutputStream(sec1)) {
            new SecurityConfigurationStaxWriter().write(fos, s1);
        }
        SecDispatcherException ex = assertThrows(SecDispatcherException.class, () -> SecUtil.read(sec1, true));
        assertTrue(ex.getMessage().contains("cycle"));
    }

    @Test
    void testReadWithRelocationCycle() throws Exception {
        Path sec1 = Paths.get("./target/sec-cycle-1.xml");
        Path sec2 = Paths.get("./target/sec-cycle-2.xml");
        SettingsSecurity s1 = new SettingsSecurity();
        s1.setModelEncoding(StandardCharsets.UTF_8.name());
        s1.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        s1.setRelocation("sec-cycle-2.xml");
        try (OutputStream fos = Files.newOutputStream(sec1)) {
            new SecurityConfigurationStaxWriter().write(fos, s1);
        }
        SettingsSecurity s2 = new SettingsSecurity();
        s2.setModelEncoding(StandardCharsets.UTF_8.name());
        s2.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        s2.setRelocation("sec-cycle-1.xml");
        try (OutputStream fos = Files.newOutputStream(sec1)) {
            new SecurityConfigurationStaxWriter().write(fos, s2);
        }
        SecDispatcherException ex = assertThrows(SecDispatcherException.class, () -> SecUtil.read(sec1, true));
        assertTrue(ex.getMessage().contains("cycle"));
    }
}
