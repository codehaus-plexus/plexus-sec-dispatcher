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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;
import org.codehaus.plexus.components.secdispatcher.Dispatcher;
import org.codehaus.plexus.components.secdispatcher.DispatcherMeta;
import org.codehaus.plexus.components.secdispatcher.MasterSource;
import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * This dispatcher is logically equivalent (but much more secure) that Maven3 "master password" encryption.
 */
@Singleton
@Named(MasterDispatcher.NAME)
public class MasterDispatcher implements Dispatcher, DispatcherMeta {
    public static final String NAME = "master";

    private static final String MASTER_CIPHER = "cipher";
    private static final String MASTER_SOURCE = "source";

    private final PlexusCipher cipher;
    protected final Map<String, MasterSource> masterSources;

    @Inject
    public MasterDispatcher(PlexusCipher cipher, Map<String, MasterSource> masterSources) {
        this.cipher = cipher;
        this.masterSources = masterSources;
    }

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
                Field.builder(MASTER_SOURCE)
                        .optional(false)
                        .description("The source of master password")
                        .options(masterSources.entrySet().stream()
                                .map(e -> {
                                    if (e instanceof MasterSourceMeta m) {
                                        Field.Builder b =
                                                Field.builder(e.getKey()).description(m.description());
                                        if (m.configTemplate().isPresent()) {
                                            b = b.defaultValue(
                                                    m.configTemplate().get());
                                        }
                                        return b.build();
                                    } else {
                                        return Field.builder(e.getKey())
                                                .description("Field not described (needs manual configuration)")
                                                .build();
                                    }
                                })
                                .toList())
                        .build(),
                Field.builder(MASTER_CIPHER)
                        .optional(false)
                        .description("The cipher to use with master password")
                        .options(cipher.availableCiphers().stream()
                                .map(c -> Field.builder(c).description(c).build())
                                .toList())
                        .build());
    }

    @Override
    public EncryptPayload encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        try {
            String masterCipher = getMasterCipher(config, true);
            String encrypted = cipher.encrypt(masterCipher, str, getMasterPassword(config));
            HashMap<String, String> attr = new HashMap<>(attributes);
            attr.put(SecDispatcher.DISPATCHER_NAME_ATTR, NAME);
            attr.put(MASTER_CIPHER, masterCipher);
            return new EncryptPayload(attr, encrypted);
        } catch (PlexusCipherException e) {
            throw new SecDispatcherException("Encrypt failed", e);
        }
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        try {
            String masterCipher = getMasterCipher(attributes, false);
            return cipher.decrypt(masterCipher, str, getMasterPassword(config));
        } catch (PlexusCipherException e) {
            throw new SecDispatcherException("Decrypt failed", e);
        }
    }

    private String getMasterPassword(Map<String, String> config) throws SecDispatcherException {
        String masterSource = config.get(MASTER_SOURCE);
        if (masterSource == null) {
            throw new SecDispatcherException("Invalid configuration: Missing configuration " + MASTER_SOURCE);
        }
        for (MasterSource masterPasswordSource : masterSources.values()) {
            String masterPassword = masterPasswordSource.handle(masterSource);
            if (masterPassword != null) return masterPassword;
        }
        throw new SecDispatcherException("No source handled the given masterSource: " + masterSource);
    }

    private String getMasterCipher(Map<String, String> source, boolean config) throws SecDispatcherException {
        String masterCipher = source.get(MASTER_CIPHER);
        if (masterCipher == null) {
            if (config) {
                throw new SecDispatcherException("Invalid configuration: Missing configuration " + MASTER_CIPHER);
            } else {
                throw new SecDispatcherException("Malformed attributes: Missing attribute " + MASTER_CIPHER);
            }
        }
        return masterCipher;
    }
}
