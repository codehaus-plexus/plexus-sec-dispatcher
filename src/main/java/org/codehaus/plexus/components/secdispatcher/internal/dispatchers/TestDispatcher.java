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

import org.codehaus.plexus.components.secdispatcher.Meta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.Dispatcher;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * This dispatcher is purely for test purposes, is obviously NOT a true encryption implementation.
 */
@Singleton
@Named(TestDispatcher.NAME)
public class TestDispatcher implements Dispatcher {
    public static final String NAME = "test";

    @Override
    public Meta meta() {
        return new Meta() {
            @Override
            public String id() {
                return NAME;
            }

            @Override
            public String displayName() {
                return "Test Dispatcher (for testing only)";
            }

            @Override
            public Collection<Field> fields() {
                return List.of(Field.builder("salt")
                        .optional(false)
                        .description("The salt for testing")
                        .build());
            }
        };
    }

    protected String getSalt(Map<String, String> config) throws SecDispatcherException {
        String salt = config.get("salt");
        if (salt == null) {
            throw new SecDispatcherException("The configuration is incomplete; missing salt");
        }
        return salt;
    }

    @Override
    public String encrypt(String str, Map<String, String> attributes, Map<String, String> config) throws SecDispatcherException {
        return new StringBuilder(str).reverse() + "@" + getSalt(config);
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config) throws SecDispatcherException {
        return new StringBuilder(str).reverse().substring(getSalt(config).length() + 1);
    }
}
