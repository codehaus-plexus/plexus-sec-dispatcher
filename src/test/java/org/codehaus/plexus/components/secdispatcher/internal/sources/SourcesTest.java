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

package org.codehaus.plexus.components.secdispatcher.internal.sources;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * surefire plugin set system property and env.
 */
public class SourcesTest {
    @Test
    void systemProperty() {
        SystemPropertyMasterSource source = new SystemPropertyMasterSource();
        assertEquals("masterPw", source.handle("system-property:masterPassword"));
    }

    @Test
    void env() {
        EnvMasterSource source = new EnvMasterSource();
        assertEquals("masterPw", source.handle("env:MASTER_PASSWORD"));
    }

    @Disabled("enable and type in 'masterPw'")
    @Test
    void gpgAgent() {
        GpgAgentMasterSource source = new GpgAgentMasterSource();
        // you may adjust path, this is Fedora40 WS. Ubuntu does `.gpg/S.gpg-agent`
        assertEquals("masterPw", source.handle("gpg-agent:/run/user/1000/gnupg/S.gpg-agent"));
    }

    @Disabled("enable and type in 'masterPw'")
    @Test
    void pinEntry() {
        PinEntryMasterSource source = new PinEntryMasterSource();
        // ypu may adjust path, this is Fedora40 WS + gnome
        assertEquals("masterPw", source.handle("pinentry-prompt:/usr/bin/pinentry-gnome3"));
    }
}
