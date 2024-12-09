/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.codehaus.plexus.components.secdispatcher.internal.sources;

import javax.inject.Named;
import javax.inject.Singleton;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Password source that uses a plain file with plaintext master password (residing on things like an encrypted pen-drive
 * or partition). Idea is to "delegate" all the security to that data carrier (for example, it may ask for permission
 * or password on access to that path). Not recommended to be used on any unprotected data storage or partition.
 * <p>
 * Config: {@code file:$fileName}
 * <p>
 * The file may start with "#" for human comments, and first non-commented line (trimmed) will be used
 * as master password.
 */
@Singleton
@Named(FileMasterSource.NAME)
public final class FileMasterSource extends PrefixMasterSourceSupport implements MasterSourceMeta {
    public static final String NAME = "file";

    public FileMasterSource() {
        super(NAME + ":");
    }

    @Override
    public String description() {
        return "File (file name should be edited; use absolute path)";
    }

    @Override
    public Optional<String> configTemplate() {
        return Optional.of(NAME + ":$fileName");
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        String value = readFile(transformed);
        if (value == null) {
            throw new SecDispatcherException("File '" + transformed + "' not found or is not readable");
        }
        return value;
    }

    @Override
    protected SecDispatcher.ValidationResponse doValidateConfiguration(String transformed) {
        String value = readFile(transformed);
        if (value == null) {
            return new SecDispatcher.ValidationResponse(
                    getClass().getSimpleName(),
                    true,
                    Map.of(
                            SecDispatcher.ValidationResponse.Level.WARNING,
                            List.of("Configured file does not exist or is not readable")),
                    List.of());
        } else {
            return new SecDispatcher.ValidationResponse(
                    getClass().getSimpleName(),
                    true,
                    Map.of(
                            SecDispatcher.ValidationResponse.Level.INFO,
                            List.of("Configured file exist and is readable")),
                    List.of());
        }
    }

    private String readFile(String transformed) throws SecDispatcherException {
        Path file = Paths.get(transformed);
        if (file.isAbsolute() && Files.exists(file)) {
            try {
                return Files.readAllLines(file).stream()
                        .filter(l -> !l.startsWith("#"))
                        .map(String::trim)
                        .findFirst()
                        .orElse(null);
            } catch (IOException e) {
                throw new SecDispatcherException("Failed to read file '" + transformed + "'", e);
            }
        }
        return null;
    }
}
