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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    private void saveSec(String defaultDispatcher) throws IOException {
        saveSec("./target/sec.xml", defaultDispatcher);
    }

    private void saveSec(String path, String defaultDispatcher) throws IOException {
        SettingsSecurity sec = new SettingsSecurity();
        sec.setDefaultDispatcher(defaultDispatcher);
        ConfigProperty cp = new ConfigProperty();
        cp.setName(_propName);
        cp.setValue(_propVal);
        Config conf = new Config();
        conf.setName(_confName);
        conf.addProperty(cp);
        sec.addConfiguration(conf);
        SecUtil.write(Paths.get(path), sec, false);
    }

    @BeforeEach
    void prepare() throws IOException {
        saveSec("magic:mighty");
    }

    @Test
    void readWrite() throws IOException {
        Path path = Path.of("./target/sec.xml");
        SettingsSecurity config = SecUtil.read(path);
        assertNotNull(config);
        assertEquals(SecUtil.specVersion(), config.getModelVersion());
        assertEquals(StandardCharsets.UTF_8.name(), config.getModelEncoding());
        assertEquals("magic:mighty", config.getDefaultDispatcher());
        SecUtil.write(path, config, false);
    }

    @Test
    void readWriteWithBackup() throws IOException {
        Path path = Path.of("./target/sec.xml");
        SettingsSecurity config = SecUtil.read(path);
        assertNotNull(config);
        assertEquals(SecUtil.specVersion(), config.getModelVersion());
        assertEquals(StandardCharsets.UTF_8.name(), config.getModelEncoding());
        assertEquals("magic:mighty", config.getDefaultDispatcher());
        SecUtil.write(path, config, true);
        assertTrue(Files.exists(path));
        assertTrue(Files.exists(path.getParent().resolve(path.getFileName() + ".bak")));
    }
}
