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
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxWriter;
import org.junit.jupiter.api.BeforeEach;
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

        try (FileWriter fw = new FileWriter("./target/sec1.xml")) {
            new SecurityConfigurationStaxWriter().write(fw, sec);
            fw.flush();
        }
    }

    @BeforeEach
    public void prepare() throws Exception {
        System.setProperty(DefaultSecDispatcher.SYSTEM_PROPERTY_CONFIGURATION_LOCATION, "./target/sec.xml");
        SettingsSecurity sec = new SettingsSecurity();
        sec.setRelocation("./target/sec1.xml");
        try (FileWriter fw = new FileWriter("./target/sec.xml")) {
            new SecurityConfigurationStaxWriter().write(fw, sec);
            fw.flush();
        }
        saveSec("magic:mighty");
    }

    @Test
    void testReadWithRelocation() throws Exception {
        SettingsSecurity sec = SecUtil.read("./target/sec.xml", true);
        assertNotNull(sec);
        assertEquals("magic:mighty", sec.getMasterSource());
        Map<String, String> conf = SecUtil.getConfig(sec, _confName);
        assertNotNull(conf);
        assertNotNull(conf.get(_propName));
        assertEquals(_propVal, conf.get(_propName));
    }
}
