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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Password source that uses Git Credential Helpers.
 * <p>
 * Git credential helpers have a common interface for retrieving credentials.
 * This master source allows using any git credential helper to retrieve passwords.
 * <p>
 * Config: {@code git-credential:helper-name?url=protocol://host/path}
 * <p>
 * Examples:
 * <ul>
 *   <li>{@code git-credential:cache?url=https://maven.apache.org/master}</li>
 *   <li>{@code git-credential:store?url=https://maven.apache.org/master}</li>
 *   <li>{@code git-credential:/usr/local/bin/git-credential-osxkeychain?url=https://maven.apache.org/master}</li>
 * </ul>
 *
 * @see <a href="https://git-scm.com/docs/gitcredentials">Git Credentials</a>
 * @see <a href="https://git-scm.com/doc/credential-helpers">Git Credential Helpers</a>
 */
@Singleton
@Named(GitCredentialHelperMasterSource.NAME)
public final class GitCredentialHelperMasterSource extends PrefixMasterSourceSupport implements MasterSourceMeta {
    public static final String NAME = "git-credential";

    public GitCredentialHelperMasterSource() {
        super(NAME + ":");
    }

    @Override
    public String description() {
        return "Git Credential Helper (helper name and URL should be edited)";
    }

    @Override
    public Optional<String> configTemplate() {
        return Optional.of(NAME + ":helper-name?url=protocol://host/path");
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        String helperName;
        String url;

        // Parse configuration: helper-name?url=protocol://host/path
        int queryIndex = transformed.indexOf('?');
        if (queryIndex < 0) {
            throw new SecDispatcherException(
                    "Invalid git-credential configuration. Expected format: git-credential:helper-name?url=protocol://host/path");
        }

        helperName = transformed.substring(0, queryIndex);
        String query = transformed.substring(queryIndex + 1);

        if (!query.startsWith("url=")) {
            throw new SecDispatcherException(
                    "Invalid git-credential configuration. Expected URL parameter: url=protocol://host/path");
        }

        url = query.substring(4);

        try {
            return retrievePassword(helperName, url);
        } catch (IOException | InterruptedException e) {
            throw new SecDispatcherException(
                    String.format(
                            "Failed to retrieve password from git credential helper '%s': %s",
                            helperName, e.getMessage()),
                    e);
        }
    }

    @Override
    protected SecDispatcher.ValidationResponse doValidateConfiguration(String transformed) {
        HashMap<SecDispatcher.ValidationResponse.Level, List<String>> report = new HashMap<>();
        boolean isValid = false;

        try {
            int queryIndex = transformed.indexOf('?');
            if (queryIndex < 0) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add(
                                "Invalid configuration format. Expected: git-credential:helper-name?url=protocol://host/path");
                return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), false, report, List.of());
            }

            String helperName = transformed.substring(0, queryIndex);
            String query = transformed.substring(queryIndex + 1);

            if (!query.startsWith("url=")) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("Invalid configuration. Expected URL parameter: url=protocol://host/path");
                return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), false, report, List.of());
            }

            String url = query.substring(4);

            // Validate URL format
            try {
                new URI(url);
            } catch (URISyntaxException e) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add(String.format("Invalid URL format: %s", e.getMessage()));
                return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), false, report, List.of());
            }

            // Try to execute the helper to see if it's available
            String helperCommand = buildHelperCommand(helperName);
            try {
                Process process = new ProcessBuilder(helperCommand, "get").start();
                // Close stdin to prevent the helper from waiting for input
                process.getOutputStream().close();

                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.WARNING, k -> new ArrayList<>())
                            .add(String.format(
                                    "Git credential helper '%s' did not respond in time. It may still work.",
                                    helperName));
                    isValid = true; // Still consider it valid, just warn
                } else if (process.exitValue() == 127 || process.exitValue() == 126) {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                            .add(String.format("Git credential helper '%s' not found or not executable", helperName));
                } else {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.INFO, k -> new ArrayList<>())
                            .add(String.format("Git credential helper '%s' is available", helperName));
                    isValid = true;
                }
            } catch (IOException e) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add(String.format(
                                "Failed to execute git credential helper '%s': %s", helperName, e.getMessage()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("Validation was interrupted");
            }
        } catch (Exception e) {
            report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                    .add(String.format("Validation error: %s", e.getMessage()));
        }

        return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), isValid, report, List.of());
    }

    private String retrievePassword(String helperName, String url) throws IOException, InterruptedException {
        String helperCommand = buildHelperCommand(helperName);

        ProcessBuilder pb = new ProcessBuilder(helperCommand, "get");
        Process process = pb.start();

        // Write credential request to helper's stdin
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(process.getOutputStream()))) {
            URI uri = new URI(url);
            if (uri.getScheme() != null) {
                writer.println("protocol=" + uri.getScheme());
            }
            if (uri.getHost() != null && !uri.getHost().isEmpty()) {
                if (uri.getPort() != -1) {
                    writer.println("host=" + uri.getHost() + ":" + uri.getPort());
                } else {
                    writer.println("host=" + uri.getHost());
                }
            }
            if (uri.getPath() != null && !uri.getPath().isEmpty()) {
                writer.println("path=" + uri.getPath());
            }
            writer.println(); // Blank line signals end of input
            writer.flush();
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URL format: " + e.getMessage(), e);
        }

        // Read response from helper's stdout
        String password = null;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("password=")) {
                    password = line.substring(9);
                    break;
                }
            }
        }

        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("Git credential helper timed out");
        }

        int exitCode = process.exitValue();
        if (exitCode != 0) {
            String errorOutput = readProcessError(process);
            throw new IOException(
                    String.format("Git credential helper exited with code %d. Error: %s", exitCode, errorOutput));
        }

        if (password == null || password.isEmpty()) {
            throw new IOException("Git credential helper did not return a password");
        }

        return password;
    }

    private String buildHelperCommand(String helperName) {
        // If helper name contains a path separator, use it as-is (absolute or relative path)
        // Otherwise, prefix with "git-credential-"
        if (helperName.contains("/") || helperName.contains("\\")) {
            return helperName;
        }
        return "git-credential-" + helperName;
    }

    private String readProcessError(Process process) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (sb.length() > 0) {
                    sb.append("; ");
                }
                sb.append(line);
            }
            return sb.toString();
        } catch (IOException e) {
            return "(failed to read error output)";
        }
    }
}
