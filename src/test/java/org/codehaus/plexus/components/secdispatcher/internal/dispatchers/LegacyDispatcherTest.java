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

package org.codehaus.plexus.components.secdispatcher.internal.dispatchers;

import java.util.Map;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LegacyDispatcherTest {
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
    void smoke(String xml) {
        System.setProperty("settings.security", xml);
        LegacyDispatcher legacyDispatcher = new LegacyDispatcher();
        // SecDispatcher "un decorates" the PW
        String cleartext = legacyDispatcher.decrypt("L6L/HbmrY+cH+sNkphnq3fguYepTpM04WlIXb8nB1pk=", Map.of(), Map.of());
        assertEquals("password", cleartext);
    }
}
