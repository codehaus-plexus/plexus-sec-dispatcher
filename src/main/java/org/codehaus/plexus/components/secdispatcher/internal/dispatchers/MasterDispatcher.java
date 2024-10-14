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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.Cipher;
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

    private static final String CONF_MASTER_CIPHER = "cipher";
    private static final String CONF_MASTER_SOURCE = "source";
    /**
     * Attribute holding the Cipher name used to encrypt the password.
     */
    private static final String MASTER_CIPHER_ATTR = CONF_MASTER_CIPHER;

    protected final Map<String, Cipher> masterCiphers;
    protected final Map<String, MasterSource> masterSources;

    @Inject
    public MasterDispatcher(Map<String, Cipher> masterCiphers, Map<String, MasterSource> masterSources) {
        this.masterCiphers = masterCiphers;
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
                Field.builder(CONF_MASTER_SOURCE)
                        .optional(false)
                        .description("Source of the master password")
                        .options(masterSources.entrySet().stream()
                                .map(e -> {
                                    MasterSource ms = e.getValue();
                                    if (ms instanceof MasterSourceMeta m) {
                                        Field.Builder b =
                                                Field.builder(e.getKey()).description(m.description());
                                        if (m.configTemplate().isPresent()) {
                                            b.defaultValue(m.configTemplate().get());
                                        }
                                        return b.build();
                                    } else {
                                        return Field.builder(e.getKey())
                                                .description(e.getKey()
                                                        + "(Field not described, needs manual configuration)")
                                                .build();
                                    }
                                })
                                .toList())
                        .build(),
                Field.builder(CONF_MASTER_CIPHER)
                        .optional(false)
                        .description("Cipher to use with master password")
                        .options(masterCiphers.keySet().stream()
                                .map(c -> Field.builder(c).description(c).build())
                                .toList())
                        .build());
    }

    @Override
    public EncryptPayload encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        String masterCipher = getMasterCipher(config, true);
        String encrypted = requireCipher(masterCipher).encrypt(str, getMasterPassword(config));
        HashMap<String, String> attr = new HashMap<>(attributes);
        attr.put(MASTER_CIPHER_ATTR, masterCipher);
        return new EncryptPayload(attr, encrypted);
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        String masterCipher = getMasterCipher(attributes, false);
        return requireCipher(masterCipher).decrypt(str, getMasterPassword(config));
    }

    @Override
    public SecDispatcher.ValidationResponse validateConfiguration(Map<String, String> config) {
        HashMap<SecDispatcher.ValidationResponse.Level, List<String>> report = new HashMap<>();
        ArrayList<SecDispatcher.ValidationResponse> subsystems = new ArrayList<>();
        boolean valid = false;
        String masterCipher = config.get(CONF_MASTER_CIPHER);
        if (masterCipher == null) {
            report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                    .add("Cipher configuration missing");
        } else {
            if (!masterCiphers.containsKey(masterCipher)) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("Configured Cipher not supported");
            } else {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.INFO, k -> new ArrayList<>())
                        .add("Configured Cipher supported");
            }
        }
        String masterSource = config.get(CONF_MASTER_SOURCE);
        if (masterSource == null) {
            report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                    .add("Source configuration missing");
        } else {
            SecDispatcher.ValidationResponse masterSourceResponse = null;
            for (MasterSource masterPasswordSource : masterSources.values()) {
                masterSourceResponse = masterPasswordSource.validateConfiguration(masterSource);
                if (masterSourceResponse != null) {
                    break;
                }
            }
            if (masterSourceResponse == null) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("Configured Source configuration not handled");
            } else {
                subsystems.add(masterSourceResponse);
                if (!masterSourceResponse.isValid()) {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                            .add("Configured Source configuration invalid");
                } else {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.INFO, k -> new ArrayList<>())
                            .add("Configured Source configuration valid");
                    valid = true;
                }
            }
        }
        return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), valid, report, subsystems);
    }

    protected String getMasterPassword(Map<String, String> config) throws SecDispatcherException {
        String masterSource = config.get(CONF_MASTER_SOURCE);
        if (masterSource == null) {
            throw new SecDispatcherException("Invalid configuration: Missing configuration " + CONF_MASTER_SOURCE);
        }
        for (MasterSource masterPasswordSource : masterSources.values()) {
            String masterPassword = masterPasswordSource.handle(masterSource);
            if (masterPassword != null) return masterPassword;
        }
        throw new SecDispatcherException("No source handled the given masterSource: " + masterSource);
    }

    protected String getMasterCipher(Map<String, String> source, boolean config) throws SecDispatcherException {
        if (config) {
            String masterCipher = source.get(CONF_MASTER_CIPHER);
            if (masterCipher == null) {
                throw new SecDispatcherException("Invalid configuration: Missing configuration " + CONF_MASTER_CIPHER);
            }
            return masterCipher;
        } else {
            String masterCipher = source.get(MASTER_CIPHER_ATTR);
            if (masterCipher == null) {
                throw new SecDispatcherException("Malformed attributes: Missing attribute " + MASTER_CIPHER_ATTR);
            }
            return masterCipher;
        }
    }

    protected Cipher requireCipher(String name) {
        Cipher masterCipher = masterCiphers.get(name);
        if (masterCipher == null) {
            throw new SecDispatcherException("No cipher exist with name " + name);
        }
        return masterCipher;
    }
}
