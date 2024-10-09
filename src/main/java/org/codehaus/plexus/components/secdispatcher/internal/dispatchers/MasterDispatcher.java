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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;
import org.codehaus.plexus.components.secdispatcher.Meta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.Dispatcher;
import org.codehaus.plexus.components.secdispatcher.internal.MasterSource;

/**
 * This dispatcher is logically equivalent (but much more secure) that Maven3 "master password" encryption.
 */
@Singleton
@Named(MasterDispatcher.NAME)
public class MasterDispatcher implements Dispatcher {
    public static final String NAME = "master";

    private final PlexusCipher cipher;
    protected final Map<String, MasterSource> masterSources;

    @Inject
    public MasterDispatcher(PlexusCipher cipher, Map<String, MasterSource> masterSources) {
        this.cipher = cipher;
        this.masterSources = masterSources;
    }

    @Override
    public Meta meta() {
        return new Meta() {
            @Override
            public String name() {
                return NAME;
            }

            @Override
            public String displayName() {
                return "Master Password Dispatcher";
            }

            @Override
            public Collection<Field> fields() {
                return List.of(
                        Field.builder("masterSource")
                                .optional(false)
                                .description("The source of master password")
                                .build(),
                        Field.builder("masterCipher")
                                .optional(false)
                                .description("The cipher to use")
                                .build());
            }
        };
    }

    @Override
    public String encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        try {
            return cipher.encrypt(getMasterCipher(config), str, getMasterPassword(config));
        } catch (PlexusCipherException e) {
            throw new SecDispatcherException("Encrypt failed", e);
        }
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        try {
            return cipher.decrypt(getMasterCipher(config), str, getMasterPassword(config));
        } catch (PlexusCipherException e) {
            throw new SecDispatcherException("Decrypt failed", e);
        }
    }

    private String getMasterPassword(Map<String, String> config) throws SecDispatcherException {
        String masterSource = config.get("masterSource");
        if (masterSource == null) {
            throw new SecDispatcherException("Illegal configuration; masterSource is null");
        }
        for (MasterSource masterPasswordSource : masterSources.values()) {
            String masterPassword = masterPasswordSource.handle(masterSource);
            if (masterPassword != null) return masterPassword;
        }
        throw new SecDispatcherException("No source handled the masterSource");
    }

    private String getMasterCipher(Map<String, String> config) throws SecDispatcherException {
        String masterCipher = config.get("masterCipher");
        if (masterCipher == null) {
            throw new SecDispatcherException("Illegal configuration; masterCipher is null");
        }
        return masterCipher;
    }
}
