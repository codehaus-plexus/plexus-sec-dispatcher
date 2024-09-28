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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.stream.Collectors;

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;
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
    protected final Map<String, MasterPasswordSource> masterPasswordSources;
    protected final Map<String, Dispatcher> dispatchers;
    protected final String configurationFile;

    @Inject
    public DefaultSecDispatcher(
            PlexusCipher cipher,
            Map<String, MasterPasswordSource> masterPasswordSources,
            Map<String, Dispatcher> dispatchers,
            @Named("${configurationFile:-" + DEFAULT_CONFIGURATION + "}") final String configurationFile) {
        this.cipher = requireNonNull(cipher);
        this.masterPasswordSources = requireNonNull(masterPasswordSources);
        this.dispatchers = requireNonNull(dispatchers);
        this.configurationFile = requireNonNull(configurationFile);
    }

    @Override
    public Set<String> availableDispatchers() {
        return Set.copyOf(dispatchers.keySet());
    }

    @Override
    public String encrypt(String str, Map<String, String> attr) throws SecDispatcherException {
        if (isEncryptedString(str)) return str;

        try {
            String res;
            SettingsSecurity sec = getSec();
            if (attr == null || attr.get(DISPATCHER_NAME_ATTR) == null) {
                String master = getMaster(sec);
                res = cipher.encrypt(str, master);
            } else {
                String type = attr.get(DISPATCHER_NAME_ATTR);
                Map<String, String> conf = SecUtil.getConfig(sec, type);
                Dispatcher dispatcher = dispatchers.get(type);
                if (dispatcher == null) throw new SecDispatcherException("no dispatcher for type " + type);
                res = dispatcher.encrypt(str, attr, conf);
                res += ATTR_START
                        + attr.entrySet().stream()
                                .map(e -> e.getKey() + "=" + e.getValue())
                                .collect(Collectors.joining(","))
                        + ATTR_STOP;
            }
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
            Map<String, String> attr = stripAttributes(bare);
            SettingsSecurity sec = getSec();
            if (attr == null || attr.get(DISPATCHER_NAME_ATTR) == null) {
                String master = getMaster(sec);
                return cipher.decrypt(bare, master);
            } else {
                String type = attr.get(DISPATCHER_NAME_ATTR);
                Map<String, String> conf = SecUtil.getConfig(sec, type);
                Dispatcher dispatcher = dispatchers.get(type);
                if (dispatcher == null) throw new SecDispatcherException("no dispatcher for type " + type);
                String pass = strip(bare);
                return dispatcher.decrypt(pass, attr, conf);
            }
        } catch (PlexusCipherException e) {
            throw new SecDispatcherException(e.getMessage(), e);
        }
    }

    private String strip(String str) {
        int pos = str.indexOf(ATTR_STOP);
        if (pos != -1) return str.substring(pos + 1);
        return str;
    }

    private Map<String, String> stripAttributes(String str) {
        int start = str.indexOf(ATTR_START);
        int stop = str.indexOf(ATTR_STOP);
        if (start != -1 && stop != -1 && stop > start) {
            if (stop == start + 1) return null;

            String attrs = str.substring(start + 1, stop).trim();

            if (attrs.isEmpty()) return null;

            Map<String, String> res = null;

            StringTokenizer st = new StringTokenizer(attrs, ",");

            while (st.hasMoreTokens()) {
                if (res == null) res = new HashMap<>(st.countTokens());

                String pair = st.nextToken();

                int pos = pair.indexOf('=');

                if (pos == -1) continue;

                String key = pair.substring(0, pos).trim();

                String val = pair.substring(pos + 1);

                res.put(key, val.trim());
            }

            return res;
        }

        return null;
    }

    // ----------------------------------------------------------------------------

    private boolean isEncryptedString(String str) {
        if (str == null) return false;
        return cipher.isEncryptedString(str);
    }

    // ----------------------------------------------------------------------------

    private SettingsSecurity getSec() throws SecDispatcherException {
        String location = System.getProperty(SYSTEM_PROPERTY_CONFIGURATION_LOCATION, getConfigurationFile());
        String realLocation =
                location.charAt(0) == '~' ? System.getProperty("user.home") + location.substring(1) : location;

        SettingsSecurity sec = SecUtil.read(realLocation, true);

        if (sec == null)
            throw new SecDispatcherException(
                    "cannot retrieve master password. Please check that " + realLocation + " exists and has data");

        return sec;
    }

    private String getMaster(SettingsSecurity sec) throws SecDispatcherException {
        String masterSource = requireNonNull(sec.getMasterSource(), "masterSource is null");
        for (MasterPasswordSource masterPasswordSource : masterPasswordSources.values()) {
            String master = masterPasswordSource.handle(masterSource);
            if (master != null) return master;
        }
        throw new SecDispatcherException("master password could not be fetched");
    }

    public String getConfigurationFile() {
        return configurationFile;
    }
}
