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

package org.codehaus.plexus.components.secdispatcher.internal.dispatcher;

import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.Dispatcher;

import static java.util.Objects.requireNonNull;

public class StaticDispatcher implements Dispatcher {
    private final String decrypted;
    private final String encrypted;

    public StaticDispatcher(String decrypted, String encrypted) {
        this.decrypted = requireNonNull(decrypted);
        this.encrypted = requireNonNull(encrypted);
    }

    @Override
    public String encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        return encrypted;
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        return decrypted;
    }
}
