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

package org.codehaus.plexus.components.secdispatcher;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;

/**
 * This component decrypts a string, passed to it using various dispatchers.
 *
 * @author Oleg Gusakov
 */
public interface SecDispatcher {
    /**
     * Attribute that selects a dispatcher. If not present in {@link #encrypt(String, Map)} attributes, the
     * configured "default dispatcher" is used.
     *
     * @see #availableDispatchers()
     */
    String DISPATCHER_NAME_ATTR = "name";

    /**
     * Attribute for version, added by SecDispatcher for possible upgrade path.
     */
    String DISPATCHER_VERSION_ATTR = "version";

    /**
     * Returns the set of available dispatcher metadata, never {@code null}.
     */
    Set<DispatcherMeta> availableDispatchers();

    /**
     * Encrypt given plaintext string.
     *
     * @param str the plaintext to encrypt
     * @param attr the attributes, may be {@code null}
     * @return encrypted string
     * @throws SecDispatcherException in case of problem
     */
    String encrypt(String str, Map<String, String> attr) throws SecDispatcherException, IOException;

    /**
     * Decrypt given encrypted string.
     *
     * @param str the encrypted string
     * @return decrypted string
     * @throws SecDispatcherException in case of problem
     */
    String decrypt(String str) throws SecDispatcherException, IOException;

    /**
     * Returns {@code true} if passed in string adheres to "encrypted string" format (current or legacy).
     *
     * @since 4.0.1
     */
    default boolean isAnyEncryptedString(String str) {
        return isEncryptedString(str) || isLegacyEncryptedString(str);
    }

    /**
     * Returns {@code true} if passed in string adheres "encrypted string" format.
     */
    boolean isEncryptedString(String str);

    /**
     * Returns {@code true} if passed in string adheres to "legacy encrypted string" format.
     */
    boolean isLegacyEncryptedString(String str);

    /**
     * Reads the effective configuration, eventually creating new instance if not present.
     *
     * @param createIfMissing If {@code true}, it will create a new empty instance
     * @return the configuration, of {@code null} if it does not exist in {@code createIfMissing} is {@code false}
     * @throws IOException In case of IO problem
     */
    SettingsSecurity readConfiguration(boolean createIfMissing) throws IOException;

    /**
     * Writes the effective configuration.
     *
     * @param configuration The configuration to write, may not be {@code null}
     * @throws IOException In case of IO problem
     */
    void writeConfiguration(SettingsSecurity configuration) throws IOException;

    /**
     * The validation response.
     */
    final class ValidationResponse {
        public enum Level {
            INFO,
            WARNING,
            ERROR
        };

        private final String source;
        private final boolean valid;
        private final Map<Level, List<String>> report;
        private final List<ValidationResponse> subsystems;

        public ValidationResponse(
                String source, boolean valid, Map<Level, List<String>> report, List<ValidationResponse> subsystems) {
            this.source = source;
            this.valid = valid;
            this.report = report;
            this.subsystems = subsystems;
        }

        public String getSource() {
            return source;
        }

        public boolean isValid() {
            return valid;
        }

        public Map<Level, List<String>> getReport() {
            return report;
        }

        public List<ValidationResponse> getSubsystems() {
            return subsystems;
        }
    }

    /**
     * Performs a "deep validation" and reports the status. If return instance {@link ValidationResponse#isValid()}
     * is {@code true}, configuration is usable.
     */
    ValidationResponse validateConfiguration();
}
