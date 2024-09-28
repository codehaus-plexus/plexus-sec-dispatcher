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

import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Dispatcher.
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public interface Dispatcher {
    /**
     * Configuration key for masterPassword. It may be present, if SecDispatcher could
     * obtain it, but presence is optional. Still, dispatcher may throw and fail the operation
     * if it requires it.
     */
    String CONF_MASTER_PASSWORD = "masterPassword";

    /**
     * encrypt given plaintext string
     *
     * @param str string to encrypt
     * @param attributes attributes, never {@code null}
     * @param config configuration from settings-security.xml, never {@code null}
     * @return encrypted string
     */
    String encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException;

    /**
     * decrypt given encrypted string
     *
     * @param str string to decrypt
     * @param attributes attributes, never {@code null}
     * @param config configuration from settings-security.xml, never {@code null}
     * @return decrypted string
     */
    String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException;
}
