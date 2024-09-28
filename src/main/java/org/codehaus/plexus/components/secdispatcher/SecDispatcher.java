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
import java.util.Set;

/**
 * This component decrypts a string, passed to it
 *
 * @author Oleg Gusakov
 */
public interface SecDispatcher {
    String DEFAULT_CONFIGURATION = "~/.m2/settings-security.xml";
    String SYSTEM_PROPERTY_CONFIGURATION_LOCATION = "settings.security";
    String DISPATCHER_NAME_ATTR = "name";

    /**
     * Returns the set of available dispatcher names, never {@code null}.
     */
    Set<String> availableDispatchers();

    /**
     * encrypt given plaintext string
     *
     * @param str the plaintext to encrypt
     * @param attr the attributes, may be {@code null}
     * @return encrypted string
     * @throws SecDispatcherException in case of problem
     */
    String encrypt(String str, Map<String, String> attr) throws SecDispatcherException;

    /**
     * decrypt given encrypted string
     *
     * @param str the encrypted string
     * @return plaintext string
     * @throws SecDispatcherException in case of problem
     */
    String decrypt(String str) throws SecDispatcherException;
}
