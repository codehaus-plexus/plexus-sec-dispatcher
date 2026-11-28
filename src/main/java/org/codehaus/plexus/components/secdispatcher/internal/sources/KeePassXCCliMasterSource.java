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
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
package org.codehaus.plexus.components.secdispatcher.internal.sources;

import javax.inject.Named;
import javax.inject.Singleton;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Password source that reads a secret from KeePassXC through {@code keepassxc-cli show}.
 *
 * <p>Config: {@code keepassxc:<database>:<entry>?field=password}. The database is opened for every call; the CLI
 * asks for the database password each time because it has no session caching (upstream issue 11746). The secret is
 * never logged. The entry path must not contain {@code :}, because the database and entry are split on the last
 * one.</p>
 *
 * <p>The browser protocol would allow session reuse and is a separate, larger feature; this source deliberately
 * uses the CLI only.</p>
 *
 * @see <a href="https://github.com/keepassxreboot/keepassxc/blob/develop/docs/man/keepassxc-cli.1.adoc">keepassxc-cli</a>
 */
@Singleton
@Named(KeePassXCCliMasterSource.NAME)
public final class KeePassXCCliMasterSource extends PrefixMasterSourceSupport implements MasterSourceMeta {

    public static final String NAME = "keepassxc";

    private static final String CONFIG_FORMAT = NAME + ":database.kdbx:entry/path?field=password";

    private static final int CLI_TIMEOUT_SECONDS = 30;

    private final String cliCommand;

    public KeePassXCCliMasterSource() {
        this("keepassxc-cli");
    }

    KeePassXCCliMasterSource(String cliCommand) {
        super(NAME + ":");
        this.cliCommand = cliCommand;
    }

    @Override
    public String description() {
        return "KeePassXC CLI (database, entry and field should be edited; prompts for the database password)";
    }

    @Override
    public Optional<String> configTemplate() {
        return Optional.of(CONFIG_FORMAT);
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        Config config = config(transformed);
        try {
            return retrieve(cliCommand, config, CLI_TIMEOUT_SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw failure(config, e);
        } catch (IOException e) {
            throw failure(config, e);
        }
    }

    private static SecDispatcherException failure(Config config, Exception e) {
        return new SecDispatcherException(
                "Failed to read '" + config.field + "' from KeePassXC entry '" + config.entry + "': " + e.getMessage(),
                e);
    }

    @Override
    protected SecDispatcher.ValidationResponse doValidateConfiguration(String transformed) {
        Map<SecDispatcher.ValidationResponse.Level, List<String>> report = new HashMap<>();
        Config config;
        try {
            config = config(transformed);
        } catch (SecDispatcherException e) {
            report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                    .add(e.getMessage());
            return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), false, report, List.of());
        }
        report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.INFO, k -> new ArrayList<>())
                .add("KeePassXC source is configured for entry '" + config.entry + "', field '" + config.field
                        + "'. The CLI prompts for the database password on every call.");
        return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), true, report, List.of());
    }

    private static Config config(String transformed) throws SecDispatcherException {
        int queryIndex = transformed.indexOf('?');
        if (queryIndex < 0) {
            throw new SecDispatcherException("Invalid KeePassXC configuration. Expected format: " + CONFIG_FORMAT);
        }
        String target = transformed.substring(0, queryIndex);
        String query = transformed.substring(queryIndex + 1);
        if (!query.startsWith("field=") || query.length() == 6 || query.indexOf('&') >= 0) {
            throw new SecDispatcherException(
                    "Invalid KeePassXC configuration. Expected a single field parameter: field=attribute-name");
        }
        int separator = target.lastIndexOf(':');
        if (separator <= 0 || separator == target.length() - 1) {
            throw new SecDispatcherException(
                    "Invalid KeePassXC configuration. Expected database and entry: " + CONFIG_FORMAT);
        }
        return new Config(target.substring(0, separator), target.substring(separator + 1), query.substring(6));
    }

    static String retrieve(String cliCommand, Config config, long timeoutSeconds)
            throws IOException, InterruptedException {
        Process process =
                new ProcessBuilder(cliCommand, "show", "-a", config.field, config.database, config.entry).start();
        ExecutorService readers = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "keepassxc-cli-reader");
            thread.setDaemon(true);
            return thread;
        });
        try {
            // Close stdin: the prompt is shown on the terminal by the CLI, not fed through the pipe.
            process.getOutputStream().close();
            Future<String> stdout =
                    readers.submit(() -> new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            Future<String> stderr =
                    readers.submit(() -> new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8));

            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IOException("keepassxc-cli timed out after " + timeoutSeconds + " seconds");
            }
            String out = await(stdout);
            String err = await(stderr);
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                // The CLI prints errors on stderr; neither the secret nor the database password is in the message.
                throw new IOException("keepassxc-cli exited with code " + exitCode + ": " + err.trim());
            }
            String secret = out.strip();
            if (secret.isEmpty()) {
                throw new IOException("keepassxc-cli returned an empty " + config.field);
            }
            return secret;
        } finally {
            readers.shutdownNow();
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private static String await(Future<String> future) throws IOException {
        try {
            return future.get(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while reading from keepassxc-cli", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IOException("Failed to read from keepassxc-cli: " + e.getMessage(), e);
        }
    }

    /** Parsed, validated configuration. */
    static final class Config {
        final String database;
        final String entry;
        final String field;

        Config(String database, String entry, String field) {
            this.database = database;
            this.entry = entry;
            this.field = field;
        }
    }
}
