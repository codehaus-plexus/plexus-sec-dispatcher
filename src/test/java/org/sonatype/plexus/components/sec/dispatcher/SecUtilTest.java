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

package org.sonatype.plexus.components.sec.dispatcher;

import java.io.FileWriter;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonatype.plexus.components.cipher.DefaultPlexusCipher;
import org.sonatype.plexus.components.sec.dispatcher.model.Config;
import org.sonatype.plexus.components.sec.dispatcher.model.ConfigProperty;
import org.sonatype.plexus.components.sec.dispatcher.model.SettingsSecurity;
import org.sonatype.plexus.components.sec.dispatcher.model.io.xpp3.SecurityConfigurationXpp3Writer;

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
    String masterPasswordEncrypted = "{zKIp99JSqcMP383jVX4zaomd8/gXhXxY0k1ZTKgIY81yzWesjdM0SZPnlI9fEJYp}";
    String password = "somePassword";
    String passwordEncrypted = "{Gfsw+RhB7REL9DE4+T73MdNRbF8zHW4Dt3YbhooZVVJVa70IjqGFz9hXOs7AH1Hi}";

    String _confName = "cname";

    String _propName = "pname";

    String _propVal = "pval";

    @BeforeEach
    public void prepare() throws Exception {
        System.setProperty(DefaultSecDispatcher.SYSTEM_PROPERTY_SEC_LOCATION, "./target/sec.xml");

        // DefaultPlexusCipher c = new DefaultPlexusCipher();
        // System.out.println(_clear+" -> "+c.encrypt( _clear, "testtest" ));

        SettingsSecurity sec = new SettingsSecurity();

        sec.setRelocation("./target/sec1.xml");
        new SecurityConfigurationXpp3Writer().write(new FileWriter("./target/sec.xml"), sec);

        sec.setRelocation(null);
        sec.setMaster(masterPasswordEncrypted);

        ConfigProperty cp = new ConfigProperty();
        cp.setName(_propName);
        cp.setValue(_propVal);

        Config conf = new Config();
        conf.setName(_confName);
        conf.addProperty(cp);

        sec.addConfiguration(conf);

        new SecurityConfigurationXpp3Writer().write(new FileWriter("./target/sec1.xml"), sec);
    }

    @Test
    void testRead() throws Exception {
        SettingsSecurity sec = SecUtil.read("./target/sec.xml", true);

        assertNotNull(sec);

        assertEquals(masterPasswordEncrypted, sec.getMaster());

        Map<String, String> conf = SecUtil.getConfig(sec, _confName);

        assertNotNull(conf);

        assertNotNull(conf.get(_propName));

        assertEquals(_propVal, conf.get(_propName));
    }

    @Test
    void testDecrypt() throws Exception {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(new DefaultPlexusCipher());

        String pass = sd.decrypt(masterPasswordEncrypted);

        assertNotNull(pass);

        assertEquals(masterPassword, pass);
    }
}
