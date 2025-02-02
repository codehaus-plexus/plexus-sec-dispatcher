/*
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

import java.util.Collections;
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.Dispatcher.EncryptPayload;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher.ValidationResponse;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.sources.EnvMasterSource;
import org.codehaus.plexus.components.secdispatcher.internal.sources.SystemPropertyMasterSource;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MasterSourceLookupDispatcherTest {

    @Test
    void testUnknownPrefix() {
        MasterSourceLookupDispatcher masterSourceLookupDispatcher =
                new MasterSourceLookupDispatcher(Collections.singleton(new EnvMasterSource()));
        assertThrows(
                SecDispatcherException.class,
                () -> masterSourceLookupDispatcher.decrypt("unknown-prefix:test", Map.of(), Map.of()));
        assertThrows(
                SecDispatcherException.class,
                () -> masterSourceLookupDispatcher.encrypt("unknown-prefix:test", Map.of(), Map.of()));
    }

    @Test
    void testSystemPropertyMasterSourceDecrypt() {
        System.setProperty("myprop", "plaintext");
        MasterSourceLookupDispatcher masterSourceLookupDispatcher =
                new MasterSourceLookupDispatcher(Collections.singleton(new SystemPropertyMasterSource()));
        // SecDispatcher "un decorates" the PW
        String cleartext = masterSourceLookupDispatcher.decrypt("system-property:myprop", Map.of(), Map.of());
        assertEquals("plaintext", cleartext);
    }

    @Test
    void testEncrypt() {
        System.setProperty("myprop", "plaintext");
        MasterSourceLookupDispatcher masterSourceLookupDispatcher =
                new MasterSourceLookupDispatcher(Collections.singleton(new SystemPropertyMasterSource()));
        // SecDispatcher "un decorates" the PW
        EncryptPayload payload = masterSourceLookupDispatcher.encrypt("system-property:myprop", Map.of(), Map.of());
        assertEquals("system-property:myprop", payload.getEncrypted());
    }

    @Test
    void testValidateConfiguration() {
        MasterSourceLookupDispatcher masterSourceLookupDispatcher =
                new MasterSourceLookupDispatcher(Collections.singleton(new SystemPropertyMasterSource()));
        ValidationResponse response = masterSourceLookupDispatcher.validateConfiguration(Collections.emptyMap());
        assertTrue(response.isValid());
    }
}
