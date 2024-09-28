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
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.model.Config;
import org.codehaus.plexus.components.secdispatcher.model.ConfigProperty;
import org.codehaus.plexus.components.secdispatcher.model.SettingsSecurity;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxReader;
import org.codehaus.plexus.components.secdispatcher.model.io.stax.SecurityConfigurationStaxWriter;

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

    /**
     * Reads the configuration model up, optionally resolving relocation too.
     */
    public static SettingsSecurity read(Path configurationFile) throws IOException {
        requireNonNull(configurationFile, "configurationFile must not be null");
        SettingsSecurity sec;
        try {
            try (InputStream in = Files.newInputStream(configurationFile)) {
                sec = new SecurityConfigurationStaxReader().read(in);
            }
            return sec;
        } catch (NoSuchFileException e) {
            return null;
        } catch (XMLStreamException e) {
            throw new IOException("Parsing error", e);
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

    public static void write(Path target, SettingsSecurity configuration) throws IOException {
        requireNonNull(target, "file must not be null");
        requireNonNull(configuration, "sec must not be null");
        writeFile(target, configuration, false);
    }

    public static void writeWithBackup(Path target, SettingsSecurity configuration) throws IOException {
        requireNonNull(target, "file must not be null");
        requireNonNull(configuration, "sec must not be null");
        writeFile(target, configuration, true);
    }

    private static final boolean IS_WINDOWS =
            System.getProperty("os.name", "unknown").startsWith("Windows");

    private static void writeFile(Path target, SettingsSecurity configuration, boolean doBackup) throws IOException {
        requireNonNull(target, "target is null");
        Path parent = requireNonNull(target.getParent(), "target must have parent");
        Files.createDirectories(parent);
        Path tempFile = parent.resolve(target.getFileName() + "."
                + Long.toUnsignedString(ThreadLocalRandom.current().nextLong()) + ".tmp");

        configuration.setModelVersion(SecDispatcher.class.getPackage().getSpecificationVersion());
        configuration.setModelEncoding(StandardCharsets.UTF_8.name());

        try (OutputStream out = Files.newOutputStream(tempFile)) {
            new SecurityConfigurationStaxWriter().write(out, configuration);
            if (doBackup && Files.isRegularFile(target)) {
                Files.copy(target, parent.resolve(target.getFileName() + ".bak"), StandardCopyOption.REPLACE_EXISTING);
            }
            if (IS_WINDOWS) {
                copy(tempFile, target);
            } else {
                Files.move(tempFile, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (XMLStreamException e) {
            throw new IOException("XML Processing error", e);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    /**
     * On Windows we use pre-NIO2 way to copy files, as for some reason it works. Beat me why.
     */
    private static void copy(Path source, Path target) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024 * 32);
        byte[] array = buffer.array();
        try (InputStream is = Files.newInputStream(source);
                OutputStream os = Files.newOutputStream(target)) {
            while (true) {
                int bytes = is.read(array);
                if (bytes < 0) {
                    break;
                }
                os.write(array, 0, bytes);
            }
        }
    }
}
