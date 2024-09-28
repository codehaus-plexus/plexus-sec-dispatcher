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
import java.util.Map;
import java.util.Set;

import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;

/**
 * This component decrypts a string, passed to it
 *
 * @author Oleg Gusakov
 */
public interface SecDispatcher {
    /**
     * The default path of configuration.
     * <p>
     * The character {@code ~} (tilde) may be present as first character ONLY and is
     * interpreted as "user.home" system property, and it MUST be followed by path separator.
     */
    String DEFAULT_CONFIGURATION = "~/.m2/settings-security.xml";

    /**
     * Java System Property that may be set, to override configuration path.
     */
    String SYSTEM_PROPERTY_CONFIGURATION_LOCATION = "settings.security";

    /**
     * Attribute that selects a dispatcher.
     *
     * @see #availableDispatchers()
     */
    String DISPATCHER_NAME_ATTR = "name";

    /**
     * Returns the set of available dispatcher names, never {@code null}.
     */
    Set<String> availableDispatchers();

    /**
     * Returns the set of available ciphers, never {@code null}.
     */
    Set<String> availableCiphers();

    /**
     * Encrypt given plaintext string.
     *
     * @param str the plaintext to encrypt
     * @param attr the attributes, may be {@code null}
     * @return encrypted string
     * @throws SecDispatcherException in case of problem
     */
    String encrypt(String str, Map<String, String> attr) throws SecDispatcherException;

    /**
     * Decrypt given encrypted string.
     *
     * @param str the encrypted string
     * @return decrypted string
     * @throws SecDispatcherException in case of problem
     */
    String decrypt(String str) throws SecDispatcherException;

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
}
