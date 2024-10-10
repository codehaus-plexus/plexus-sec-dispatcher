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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.stream.Collectors;

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;
import org.codehaus.plexus.components.secdispatcher.Dispatcher;
import org.codehaus.plexus.components.secdispatcher.DispatcherMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;

import static java.util.Objects.requireNonNull;

/**
 * @author Oleg Gusakov
 */
@Singleton
@Named
public class DefaultSecDispatcher implements SecDispatcher {
    public static final String ATTR_START = "[";
    public static final String ATTR_STOP = "]";

    protected final PlexusCipher cipher;
    protected final Map<String, Dispatcher> dispatchers;
    protected final String configurationFile;

    @Inject
    public DefaultSecDispatcher(
            PlexusCipher cipher,
            Map<String, Dispatcher> dispatchers,
            @Named("${configurationFile:-" + DEFAULT_CONFIGURATION + "}") final String configurationFile) {
        this.cipher = requireNonNull(cipher);
        this.dispatchers = requireNonNull(dispatchers);
        this.configurationFile = requireNonNull(configurationFile);
    }

    @Override
    public Set<DispatcherMeta> availableDispatchers() {
        return Set.copyOf(
                dispatchers.entrySet().stream().map(this::dispatcherMeta).collect(Collectors.toSet()));
    }

    private DispatcherMeta dispatcherMeta(Map.Entry<String, Dispatcher> dispatcher) {
        if (dispatcher instanceof DispatcherMeta) {
            return (DispatcherMeta) dispatcher;
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
    public String encrypt(String str, Map<String, String> attr) throws SecDispatcherException {
        if (isEncryptedString(str)) return str;

        try {
            if (attr == null) {
                attr = new HashMap<>();
            } else {
                attr = new HashMap<>(attr);
            }
            if (attr.get(DISPATCHER_NAME_ATTR) == null) {
                attr.put(
                        DISPATCHER_NAME_ATTR,
                        requireNonNull(
                                getConfiguration().getDefaultDispatcher(),
                                "no default dispatcher set in configuration"));
            }
            String name = attr.get(DISPATCHER_NAME_ATTR);
            Dispatcher dispatcher = dispatchers.get(name);
            if (dispatcher == null) throw new SecDispatcherException("no dispatcher for name " + name);
            Dispatcher.EncryptPayload payload = dispatcher.encrypt(str, attr, prepareDispatcherConfig(name));
            if (!Objects.equals(payload.getAttributes().get(DISPATCHER_NAME_ATTR), name)) {
                throw new SecDispatcherException("Dispatcher " + name + " bug: mismatched name attribute");
            }
            String res = ATTR_START
                    + payload.getAttributes().entrySet().stream()
                            .map(e -> e.getKey() + "=" + e.getValue())
                            .collect(Collectors.joining(","))
                    + ATTR_STOP;
            res += payload.getEncrypted();
            return cipher.decorate(res);
        } catch (PlexusCipherException e) {
            throw new SecDispatcherException(e.getMessage(), e);
        }
    }

    @Override
    public String decrypt(String str) throws SecDispatcherException {
        if (!isEncryptedString(str)) return str;
        try {
            String bare = cipher.unDecorate(str);
            Map<String, String> attr = requireNonNull(stripAttributes(bare));
            if (attr.get(DISPATCHER_NAME_ATTR) == null) {
                throw new SecDispatcherException("malformed password: no attribute with name");
            }
            String name = attr.get(DISPATCHER_NAME_ATTR);
            Dispatcher dispatcher = dispatchers.get(name);
            if (dispatcher == null) throw new SecDispatcherException("no dispatcher for name " + name);
            return dispatcher.decrypt(strip(bare), attr, prepareDispatcherConfig(name));
        } catch (PlexusCipherException e) {
            throw new SecDispatcherException(e.getMessage(), e);
        }
    }

    @Override
    public SettingsSecurity readConfiguration(boolean createIfMissing) throws IOException {
        SettingsSecurity configuration = SecUtil.read(getConfigurationPath());
        if (configuration == null && createIfMissing) {
            configuration = new SettingsSecurity();
        }
        return configuration;
    }

    @Override
    public void writeConfiguration(SettingsSecurity configuration) throws IOException {
        requireNonNull(configuration, "configuration is null");
        SecUtil.write(getConfigurationPath(), configuration, true);
    }

    private Map<String, String> prepareDispatcherConfig(String type) {
        HashMap<String, String> dispatcherConf = new HashMap<>();
        Map<String, String> conf = SecUtil.getConfig(getConfiguration(), type);
        if (conf != null) {
            dispatcherConf.putAll(conf);
        }
        return dispatcherConf;
    }

    private String strip(String str) {
        int start = str.indexOf(ATTR_START);
        int stop = str.indexOf(ATTR_STOP);
        if (start != -1 && stop != -1 && stop > start) {
            return str.substring(stop + 1);
        }
        return str;
    }

    private Map<String, String> stripAttributes(String str) {
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

    private boolean isEncryptedString(String str) {
        if (str == null) return false;
        return cipher.isEncryptedString(str);
    }

    private Path getConfigurationPath() {
        String location = System.getProperty(SYSTEM_PROPERTY_CONFIGURATION_LOCATION, getConfigurationFile());
        location = location.charAt(0) == '~' ? System.getProperty("user.home") + location.substring(1) : location;
        return Paths.get(location);
    }

    private SettingsSecurity getConfiguration() throws SecDispatcherException {
        Path path = getConfigurationPath();
        try {
            SettingsSecurity sec = SecUtil.read(path);
            if (sec == null)
                throw new SecDispatcherException("Please check that configuration file on path " + path + " exists");
            return sec;
        } catch (IOException e) {
            throw new SecDispatcherException(e.getMessage(), e);
        }
    }

    public String getConfigurationFile() {
        return configurationFile;
    }
}
