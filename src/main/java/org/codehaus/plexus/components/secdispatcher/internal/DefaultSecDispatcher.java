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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;
import org.codehaus.plexus.components.cipher.internal.DefaultPlexusCipher;
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
    public static final String DEFAULT_CONFIGURATION = "~/.m2/settings-security.xml";

    public static final String SYSTEM_PROPERTY_SEC_LOCATION = "settings.security";

    public static final String TYPE_ATTR = "type";
    public static final char ATTR_START = '[';
    public static final char ATTR_STOP = ']';

    protected final PlexusCipher cipher;
    protected final Map<String, MasterPasswordSource> masterPasswordSources;
    protected final Map<String, PasswordDecryptor> decryptors;
    protected String configurationFile;

    @Inject
    public DefaultSecDispatcher(
            PlexusCipher cipher,
            Map<String, MasterPasswordSource> masterPasswordSources,
            Map<String, PasswordDecryptor> decryptors,
            @Named("${configurationFile:-" + DEFAULT_CONFIGURATION + "}") final String configurationFile) {
        this.cipher = cipher;
        this.masterPasswordSources = masterPasswordSources;
        this.decryptors = decryptors;
        this.configurationFile = configurationFile;
    }

    // ---------------------------------------------------------------

    @Override
    public String decrypt(String str) throws SecDispatcherException {
        if (!isEncryptedString(str)) return str;

        String bare;

        try {
            bare = cipher.unDecorate(str);

            Map<String, String> attr = stripAttributes(bare);

            String res;

            SettingsSecurity sec = getSec();

            if (attr == null || attr.get("type") == null) {
                String master = getMaster(sec);

                res = cipher.decrypt(bare, master);
            } else {
                String type = attr.get(TYPE_ATTR);

                if (decryptors == null)
                    throw new SecDispatcherException(
                            "plexus container did not supply any required dispatchers - cannot lookup " + type);

                Map<String, String> conf = SecUtil.getConfig(sec, type);

                PasswordDecryptor dispatcher = decryptors.get(type);

                if (dispatcher == null) throw new SecDispatcherException("no dispatcher for hint " + type);

                String pass = strip(bare);

                return dispatcher.decrypt(pass, attr, conf);
            }

            return res;
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
        String location = System.getProperty(SYSTEM_PROPERTY_SEC_LOCATION, getConfigurationFile());
        String realLocation =
                location.charAt(0) == '~' ? System.getProperty("user.home") + location.substring(1) : location;

        SettingsSecurity sec = SecUtil.read(realLocation, true);

        if (sec == null)
            throw new SecDispatcherException(
                    "cannot retrieve master password. Please check that " + realLocation + " exists and has data");

        return sec;
    }

    // ----------------------------------------------------------------------------

    private String getMaster(SettingsSecurity sec) throws SecDispatcherException {
        String masterSource = requireNonNull(sec.getMasterSource(), "masterSource is null");
        try {
            URI masterSourceUri = new URI(masterSource);
            for (MasterPasswordSource masterPasswordSource : masterPasswordSources.values()) {
                String master = masterPasswordSource.handle(masterSourceUri);
                if (master != null) return master;
            }
        } catch (URISyntaxException e) {
            throw new SecDispatcherException("Invalid master source URI", e);
        }
        throw new SecDispatcherException("master password could not be fetched");
    }
    // ---------------------------------------------------------------
    public String getConfigurationFile() {
        return configurationFile;
    }

    public void setConfigurationFile(String file) {
        configurationFile = file;
    }

    // ---------------------------------------------------------------

    private static boolean propertyExists(String[] values, String[] av) {
        if (values != null) {
            for (String item : values) {
                String p = System.getProperty(item);

                if (p != null) {
                    return true;
                }
            }

            if (av != null)
                for (String value : values)
                    for (String s : av) {
                        if (("--" + value).equals(s)) {
                            return true;
                        }
                    }
        }

        return false;
    }

    private static void usage() {
        System.out.println("usage: java -jar ...jar [-m|-p]\n-m: encrypt master password\n-p: encrypt password");
    }

    // ---------------------------------------------------------------

    private static final String[] SYSTEM_PROPERTY_MASTER_PASSWORD =
            new String[] {"settings.master.password", "settings-master-password"};

    private static final String[] SYSTEM_PROPERTY_SERVER_PASSWORD =
            new String[] {"settings.server.password", "settings-server-password"};

    public static void main(String[] args) throws Exception {
        if (args == null || args.length < 1) {
            usage();
            return;
        }

        if ("-m".equals(args[0]) || propertyExists(SYSTEM_PROPERTY_MASTER_PASSWORD, args)) show(true);
        else if ("-p".equals(args[0]) || propertyExists(SYSTEM_PROPERTY_SERVER_PASSWORD, args)) show(false);
        else usage();
    }

    // ---------------------------------------------------------------

    private static void show(boolean showMaster) throws Exception {
        if (showMaster) System.out.print("\nsettings master password\n");
        else System.out.print("\nsettings server password\n");

        System.out.print("enter password: ");

        BufferedReader r = new BufferedReader(new InputStreamReader(System.in));

        String pass = r.readLine();

        System.out.println("\n");

        DefaultPlexusCipher dc = new DefaultPlexusCipher();
        DefaultSecDispatcher dd =
                new DefaultSecDispatcher(dc, Collections.emptyMap(), Collections.emptyMap(), DEFAULT_CONFIGURATION);

        if (showMaster)
            System.out.println(dc.encryptAndDecorate(pass, DefaultSecDispatcher.SYSTEM_PROPERTY_SEC_LOCATION));
        else {
            SettingsSecurity sec = dd.getSec();
            System.out.println(dc.encryptAndDecorate(pass, dd.getMaster(sec)));
        }
    }
}
