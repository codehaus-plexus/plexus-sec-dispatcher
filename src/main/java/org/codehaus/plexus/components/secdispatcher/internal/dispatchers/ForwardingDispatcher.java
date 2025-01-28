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

import org.codehaus.plexus.components.secdispatcher.Dispatcher;
import org.codehaus.plexus.components.secdispatcher.DispatcherMeta;
import org.codehaus.plexus.components.secdispatcher.MasterSource;
import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This dispatcher forwards requests fully to defined sources.
 */
@Singleton
@Named(ForwardingDispatcher.NAME)
public class ForwardingDispatcher implements Dispatcher, DispatcherMeta {
    public static final String NAME = "forwarding";

    private static final String CONF_SOURCE = "source";

    protected final Map<String, MasterSource> sources;

    @Inject
    public ForwardingDispatcher(Map<String, MasterSource> sources) {
        this.sources = sources;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String displayName() {
        return "Forwarding Password Dispatcher";
    }

    @Override
    public Collection<Field> fields() {
        return List.of(
                Field.builder(CONF_SOURCE)
                        .optional(false)
                        .description("Source of the password")
                        .options(sources.entrySet().stream()
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
                        .build());
    }

    @Override
    public EncryptPayload encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        throw new UnsupportedOperationException("Forwarding dispatcher does not support encryption");
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        MasterSource masterSource = getPasswordSource(config);
        return masterSource.handle(str);
    }

    @Override
    public SecDispatcher.ValidationResponse validateConfiguration(Map<String, String> config) {
        HashMap<SecDispatcher.ValidationResponse.Level, List<String>> report = new HashMap<>();
        ArrayList<SecDispatcher.ValidationResponse> subsystems = new ArrayList<>();
        boolean valid = false;
        String masterSource = config.get(CONF_SOURCE);
        if (masterSource == null) {
            report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                    .add("Source configuration missing");
        } else {
            SecDispatcher.ValidationResponse masterSourceResponse = null;
            for (MasterSource masterPasswordSource : sources.values()) {
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

    protected MasterSource getPasswordSource(Map<String, String> config) throws SecDispatcherException {
        String masterSource = config.get(CONF_SOURCE);
        if (masterSource == null) {
            throw new SecDispatcherException("Invalid configuration: Missing configuration " + CONF_SOURCE);
        }
        MasterSource source = sources.get(masterSource);
        if (source != null) {
            return source;
        }
        throw new SecDispatcherException("No source found the given masterSource: " + masterSource);
    }
}
