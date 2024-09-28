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

import javax.xml.stream.XMLStreamException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxReader;

import static java.util.Objects.requireNonNull;

/**
 *
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public final class SecUtil {
    private SecUtil() {}

    private static final int MAX_RELOCATIONS = 5;

    /**
     * Reads the configuration model up, optionally resolving relocation too.
     */
    public static SettingsSecurity read(Path configurationFile, boolean followRelocation)
            throws SecDispatcherException {
        requireNonNull(configurationFile, "configurationFile must not be null");
        LinkedHashSet<Path> paths = new LinkedHashSet<>();
        return read(paths, configurationFile, followRelocation);
    }

    private static SettingsSecurity read(LinkedHashSet<Path> paths, Path configurationFile, boolean follow)
            throws SecDispatcherException {
        if (!paths.add(configurationFile)) {
            throw new SecDispatcherException("Configuration relocation form a cycle: " + paths);
        }
        if (paths.size() > MAX_RELOCATIONS) {
            throw new SecDispatcherException("Configuration relocation is too deep: " + paths);
        }
        SettingsSecurity sec;
        try {
            try (InputStream in = Files.newInputStream(configurationFile)) {
                sec = new SecurityConfigurationStaxReader().read(in);
            }
            if (follow && sec.getRelocation() != null)
                return read(paths, configurationFile.getParent().resolve(sec.getRelocation()), true);
            return sec;
        } catch (NoSuchFileException e) {
            return null;
        } catch (IOException e) {
            throw new SecDispatcherException("IO Problem", e);
        } catch (XMLStreamException e) {
            throw new SecDispatcherException("Parsing error", e);
        }
    }

    public static Map<String, String> getConfig(SettingsSecurity sec, String name) {
        if (sec != null && name != null) {
            List<Config> cl = sec.getConfigurations();
            if (!cl.isEmpty()) {
                for (Config cf : cl) {
                    if (!name.equals(cf.getName())) {
                        continue;
                    }
                    List<ConfigProperty> pl = cf.getProperties();
                    if (pl.isEmpty()) {
                        break;
                    }
                    Map<String, String> res = new HashMap<>(pl.size());
                    for (ConfigProperty p : pl) {
                        res.put(p.getName(), p.getValue());
                    }
                    return res;
                }
            }
        }
        return null;
    }
}
