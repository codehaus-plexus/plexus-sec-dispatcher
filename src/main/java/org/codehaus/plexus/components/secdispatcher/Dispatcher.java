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

import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Dispatcher.
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public interface Dispatcher {
    /**
     * The "encrypt payload" prepared by dispatcher.
     */
    final class EncryptPayload {
        private final Map<String, String> attributes;
        private final String encrypted;

        public EncryptPayload(Map<String, String> attributes, String encrypted) {
            this.attributes = requireNonNull(attributes);
            this.encrypted = requireNonNull(encrypted);
        }

        public Map<String, String> getAttributes() {
            return attributes;
        }

        public String getEncrypted() {
            return encrypted;
        }
    }

    /**
     * Encrypt given plaintext string. Implementation must return at least same attributes it got, but may add more
     * attributes to returned payload.
     *
     * @param str string to encrypt, never {@code null}
     * @param attributes attributes, never {@code null}
     * @param config configuration from settings-security.xml, never {@code null}
     * @return encrypted string and attributes in {@link EncryptPayload}
     */
    EncryptPayload encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException;

    /**
     * Decrypt given encrypted string.
     *
     * @param str string to decrypt, never {@code null}
     * @param attributes attributes, never {@code null}
     * @param config configuration from settings-security.xml, never {@code null}
     * @return decrypted string
     */
    String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException;

    /**
     * Validates dispatcher configuration.
     */
    SecDispatcher.ValidationResponse validateConfiguration(Map<String, String> config);
}
