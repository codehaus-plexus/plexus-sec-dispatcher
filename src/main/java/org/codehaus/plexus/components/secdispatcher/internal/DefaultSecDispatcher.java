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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.stream.Collectors;

import org.codehaus.plexus.components.secdispatcher.Dispatcher;
import org.codehaus.plexus.components.secdispatcher.DispatcherMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.dispatchers.LegacyDispatcher;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;

import static java.util.Objects.requireNonNull;

/**
 * Note: this implementation is NOT a JSR330 component. Integrating apps anyway want to customize it (at least
 * the name and location of configuration file), so instead as before (providing "bad" configuration file just
 * to have one), it is the duty of integrator to wrap and "finish" the implementation in a way it suits the
 * integrator. Also, using "globals" like Java System Properties are bad thing, and it is integrator who knows
 * what is needed anyway.
 * <p>
 * Recommended way for integration is to create JSR330 {@link javax.inject.Provider}.
 *
 * @author Oleg Gusakov
 */
public class DefaultSecDispatcher implements SecDispatcher {
    public static final String SHIELD_BEGIN = "{";
    public static final String SHIELD_END = "}";
    public static final String ATTR_START = "[";
    public static final String ATTR_STOP = "]";

    protected final Map<String, Dispatcher> dispatchers;
    protected final Path configurationFile;

    public DefaultSecDispatcher(Map<String, Dispatcher> dispatchers, Path configurationFile) {
        this.dispatchers = requireNonNull(dispatchers);
        this.configurationFile = requireNonNull(configurationFile);

        // file may or may not exist, but one thing is certain: it cannot be an exiting directory
        if (Files.isDirectory(configurationFile)) {
            throw new IllegalArgumentException("configurationFile cannot be a directory");
        }
    }

    @Override
    public Set<DispatcherMeta> availableDispatchers() {
        return Set.copyOf(
                dispatchers.entrySet().stream().map(this::dispatcherMeta).collect(Collectors.toSet()));
    }

    private DispatcherMeta dispatcherMeta(Map.Entry<String, Dispatcher> dispatcher) {
        // sisu components are lazy!
        Dispatcher d = dispatcher.getValue();
        if (d instanceof DispatcherMeta meta) {
            return meta;
        } else {
            return new DispatcherMeta() {
                @Override
                public String name() {
                    return dispatcher.getKey();
                }

                @Override
                public String displayName() {
                    return dispatcher.getKey() + " (needs manual configuration)";
                }

                @Override
                public Collection<Field> fields() {
                    return List.of();
                }
            };
        }
    }

    @Override
    public String encrypt(String str, Map<String, String> attr) throws SecDispatcherException, IOException {
        if (isEncryptedString(str)) return str;
        if (attr == null) {
            attr = new HashMap<>();
        } else {
            attr = new HashMap<>(attr);
        }
        if (attr.get(DISPATCHER_NAME_ATTR) == null) {
            SettingsSecurity conf = readConfiguration(false);
            if (conf == null) {
                throw new SecDispatcherException("No configuration found");
            }
            String defaultDispatcher = conf.getDefaultDispatcher();
            if (defaultDispatcher == null) {
                throw new SecDispatcherException("No defaultDispatcher set in configuration");
            }
            attr.put(DISPATCHER_NAME_ATTR, defaultDispatcher);
        }
        String name = attr.get(DISPATCHER_NAME_ATTR);
        Dispatcher dispatcher = dispatchers.get(name);
        if (dispatcher == null) throw new SecDispatcherException("No dispatcher exist with name " + name);
        Dispatcher.EncryptPayload payload = dispatcher.encrypt(str, attr, prepareDispatcherConfig(name));
        HashMap<String, String> resultAttributes = new HashMap<>(payload.getAttributes());
        resultAttributes.put(SecDispatcher.DISPATCHER_NAME_ATTR, name);
        resultAttributes.put(SecDispatcher.DISPATCHER_VERSION_ATTR, SecUtil.specVersion());
        return SHIELD_BEGIN
                + ATTR_START
                + resultAttributes.entrySet().stream()
                        .map(e -> e.getKey() + "=" + e.getValue())
                        .collect(Collectors.joining(","))
                + ATTR_STOP
                + payload.getEncrypted()
                + SHIELD_END;
    }

    @Override
    public String decrypt(String str) throws SecDispatcherException, IOException {
        if (!isEncryptedString(str)) return str;
        String bare = unDecorate(str);
        Map<String, String> attr = requireNonNull(stripAttributes(bare));
        if (isLegacyEncryptedString(str)) {
            attr.put(DISPATCHER_NAME_ATTR, LegacyDispatcher.NAME);
        }
        String name = attr.get(DISPATCHER_NAME_ATTR);
        Dispatcher dispatcher = dispatchers.get(name);
        if (dispatcher == null) throw new SecDispatcherException("No dispatcher exist with name " + name);
        return dispatcher.decrypt(strip(bare), attr, prepareDispatcherConfig(name));
    }

    /**
     * <ul>
     *     <li>Current: {[name=master,cipher=AES/GCM/NoPadding,version=4.0]vvq66pZ7rkvzSPStGTI9q4QDnsmuDwo+LtjraRel2b0XpcGJFdXcYAHAS75HUA6GLpcVtEkmyQ==}</li>
     * </ul>
     */
    @Override
    public boolean isEncryptedString(String str) {
        boolean looksLike = str != null
                && !str.isBlank()
                && str.startsWith(SHIELD_BEGIN)
                && str.endsWith(SHIELD_END)
                && !unDecorate(str).contains(SHIELD_BEGIN)
                && !unDecorate(str).contains(SHIELD_END);
        if (looksLike) {
            Map<String, String> attributes = stripAttributes(unDecorate(str));
            return attributes.containsKey(DISPATCHER_NAME_ATTR) && attributes.containsKey(DISPATCHER_VERSION_ATTR);
        }
        return false;
    }

    /**
     * <ul>
     *     <li>Legacy: {jSMOWnoPFgsHVpMvz5VrIt5kRbzGpI8u+9EF1iFQyJQ=}</li>
     * </ul>
     */
    @Override
    public boolean isLegacyEncryptedString(String str) {
        boolean looksLike = str != null
                && !str.isBlank()
                && str.startsWith(SHIELD_BEGIN)
                && str.endsWith(SHIELD_END)
                && !unDecorate(str).contains(SHIELD_BEGIN)
                && !unDecorate(str).contains(SHIELD_END);
        if (looksLike) {
            return stripAttributes(unDecorate(str)).isEmpty();
        }
        return false;
    }

    @Override
    public SettingsSecurity readConfiguration(boolean createIfMissing) throws IOException {
        SettingsSecurity configuration = SecUtil.read(configurationFile);
        if (configuration == null && createIfMissing) {
            configuration = new SettingsSecurity();
        }
        return configuration;
    }

    @Override
    public void writeConfiguration(SettingsSecurity configuration) throws IOException {
        requireNonNull(configuration, "configuration is null");
        SecUtil.write(configurationFile, configuration, true);
    }

    @Override
    public ValidationResponse validateConfiguration() {
        HashMap<ValidationResponse.Level, List<String>> report = new HashMap<>();
        ArrayList<ValidationResponse> subsystems = new ArrayList<>();
        boolean valid = false;
        try {
            SettingsSecurity config = readConfiguration(false);
            if (config == null) {
                report.computeIfAbsent(ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("No configuration file found on path " + configurationFile);
            } else {
                report.computeIfAbsent(ValidationResponse.Level.INFO, k -> new ArrayList<>())
                        .add("Configuration file present on path " + configurationFile);
                String defaultDispatcher = config.getDefaultDispatcher();
                if (defaultDispatcher == null) {
                    report.computeIfAbsent(ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                            .add("No default dispatcher set in configuration");
                } else {
                    report.computeIfAbsent(ValidationResponse.Level.INFO, k -> new ArrayList<>())
                            .add("Default dispatcher configured");
                    Dispatcher dispatcher = dispatchers.get(defaultDispatcher);
                    if (dispatcher == null) {
                        report.computeIfAbsent(ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                                .add("Configured default dispatcher not present in system");
                    } else {
                        ValidationResponse dispatcherResponse =
                                dispatcher.validateConfiguration(prepareDispatcherConfig(defaultDispatcher));
                        subsystems.add(dispatcherResponse);
                        if (!dispatcherResponse.isValid()) {
                            report.computeIfAbsent(ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                                    .add("Configured default dispatcher configuration is invalid");
                        } else {
                            valid = true;
                            report.computeIfAbsent(ValidationResponse.Level.INFO, k -> new ArrayList<>())
                                    .add("Configured default dispatcher configuration is valid");
                        }
                    }
                }
            }

            // below is legacy check, that does not affect validity of config, is merely informational
            Dispatcher legacy = dispatchers.get(LegacyDispatcher.NAME);
            if (legacy == null) {
                report.computeIfAbsent(ValidationResponse.Level.INFO, k -> new ArrayList<>())
                        .add("Legacy dispatcher not present in system");
            } else {
                report.computeIfAbsent(ValidationResponse.Level.INFO, k -> new ArrayList<>())
                        .add("Legacy dispatcher present in system");
                ValidationResponse legacyResponse =
                        legacy.validateConfiguration(prepareDispatcherConfig(LegacyDispatcher.NAME));
                subsystems.add(legacyResponse);
                if (!legacyResponse.isValid()) {
                    report.computeIfAbsent(ValidationResponse.Level.WARNING, k -> new ArrayList<>())
                            .add("Legacy dispatcher not operational; transparent fallback not possible");
                } else {
                    report.computeIfAbsent(ValidationResponse.Level.INFO, k -> new ArrayList<>())
                            .add("Legacy dispatcher is operational; transparent fallback possible");
                }
            }
        } catch (IOException e) {
            report.computeIfAbsent(ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                    .add(e.getMessage());
        }

        return new ValidationResponse(getClass().getSimpleName(), valid, report, subsystems);
    }

    protected Map<String, String> prepareDispatcherConfig(String name) throws IOException {
        HashMap<String, String> dispatcherConf = new HashMap<>();
        Map<String, String> conf = SecUtil.getConfig(SecUtil.read(configurationFile), name);
        if (conf != null) {
            dispatcherConf.putAll(conf);
        }
        return dispatcherConf;
    }

    protected String strip(String str) {
        int start = str.indexOf(ATTR_START);
        int stop = str.indexOf(ATTR_STOP);
        if (start != -1 && stop != -1 && stop > start) {
            return str.substring(stop + 1);
        }
        return str;
    }

    protected Map<String, String> stripAttributes(String str) {
        HashMap<String, String> result = new HashMap<>();
        int start = str.indexOf(ATTR_START);
        int stop = str.indexOf(ATTR_STOP);
        if (start != -1 && stop != -1 && stop > start) {
            if (start != 0) throw new SecDispatcherException("Attributes can be prefix only");
            if (stop == start + 1) return null;
            String attrs = str.substring(start + 1, stop).trim();
            if (attrs.isEmpty()) return null;
            StringTokenizer st = new StringTokenizer(attrs, ",");
            while (st.hasMoreTokens()) {
                String pair = st.nextToken();
                int pos = pair.indexOf('=');
                if (pos == -1) throw new SecDispatcherException("Attribute malformed: " + pair);
                String key = pair.substring(0, pos).trim();
                String val = pair.substring(pos + 1).trim();
                result.put(key, val);
            }
        }
        return result;
    }

    protected String unDecorate(String str) {
        return str.substring(SHIELD_BEGIN.length(), str.length() - SHIELD_END.length());
    }
}
