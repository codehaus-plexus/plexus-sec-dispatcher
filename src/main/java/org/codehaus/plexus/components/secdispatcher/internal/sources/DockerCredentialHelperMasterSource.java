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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Password source that uses Docker credential helpers.
 * <p>
 * A Docker credential helper is an executable named {@code docker-credential-<name>}. For the {@code get} command it
 * reads the server URL from standard input and prints a JSON document such as
 * {@code {"ServerURL":"...","Username":"...","Secret":"..."}} to standard output. The {@code Secret} is returned as
 * the master password.
 * <p>
 * Config: {@code docker-credential:helper-name?url=server-url}
 * <p>
 * Examples:
 * <ul>
 *   <li>{@code docker-credential:osxkeychain?url=https://index.docker.io/v1/}</li>
 *   <li>{@code docker-credential:pass?url=registry.example.com}</li>
 *   <li>{@code docker-credential:/usr/local/bin/docker-credential-desktop?url=https://index.docker.io/v1/}</li>
 * </ul>
 *
 * @see <a href="https://docs.docker.com/reference/cli/docker/login/#credential-helper-protocol">Docker credential
 * helper protocol</a>
 */
@Singleton
@Named(DockerCredentialHelperMasterSource.NAME)
public final class DockerCredentialHelperMasterSource extends PrefixMasterSourceSupport implements MasterSourceMeta {
    public static final String NAME = "docker-credential";

    private static final String CONFIG_FORMAT = NAME + ":helper-name?url=server-url";

    public DockerCredentialHelperMasterSource() {
        super(NAME + ":");
    }

    @Override
    public String description() {
        return "Docker Credential Helper (helper name and server URL should be edited)";
    }

    @Override
    public Optional<String> configTemplate() {
        return Optional.of(CONFIG_FORMAT);
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        int queryIndex = transformed.indexOf('?');
        if (queryIndex < 0) {
            throw new SecDispatcherException(
                    "Invalid docker-credential configuration. Expected format: " + CONFIG_FORMAT);
        }

        String helperName = transformed.substring(0, queryIndex);
        String query = transformed.substring(queryIndex + 1);

        if (!query.startsWith("url=")) {
            throw new SecDispatcherException(
                    "Invalid docker-credential configuration. Expected URL parameter: url=server-url");
        }

        String url = query.substring(4);
        if (url.isEmpty()) {
            throw new SecDispatcherException("Invalid docker-credential configuration. Server URL is empty");
        }

        try {
            return retrieveSecret(helperName, url);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new SecDispatcherException(
                    String.format(
                            "Failed to retrieve secret from docker credential helper '%s': %s",
                            helperName, e.getMessage()),
                    e);
        }
    }

    @Override
    protected SecDispatcher.ValidationResponse doValidateConfiguration(String transformed) {
        Map<SecDispatcher.ValidationResponse.Level, List<String>> report = new HashMap<>();
        boolean isValid = false;

        try {
            int queryIndex = transformed.indexOf('?');
            if (queryIndex < 0) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("Invalid configuration format. Expected: " + CONFIG_FORMAT);
                return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), false, report, List.of());
            }

            String helperName = transformed.substring(0, queryIndex);
            String query = transformed.substring(queryIndex + 1);

            if (!query.startsWith("url=") || query.length() == 4) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add("Invalid configuration. Expected non-empty URL parameter: url=server-url");
                return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), false, report, List.of());
            }

            try {
                new URI(query.substring(4));
            } catch (URISyntaxException e) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add(String.format("Invalid URL format: %s", e.getMessage()));
                return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), false, report, List.of());
            }

            // The "list" command does not need a server URL, so it is safe to use to probe the helper
            try {
                Process process = new ProcessBuilder(buildHelperCommand(helperName), "list").start();
                process.getOutputStream().close();

                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.WARNING, k -> new ArrayList<>())
                            .add(String.format(
                                    "Docker credential helper '%s' did not respond in time. It may still work.",
                                    helperName));
                    isValid = true;
                } else if (process.exitValue() == 127 || process.exitValue() == 126) {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                            .add(String.format(
                                    "Docker credential helper '%s' not found or not executable", helperName));
                } else {
                    report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.INFO, k -> new ArrayList<>())
                            .add(String.format("Docker credential helper '%s' is available", helperName));
                    isValid = true;
                }
            } catch (IOException e) {
                report.computeIfAbsent(SecDispatcher.ValidationResponse.Level.ERROR, k -> new ArrayList<>())
                        .add(String.format(
                                "Failed to execute docker credential helper '%s': %s", helperName, e.getMessage()));
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

    private String retrieveSecret(String helperName, String url) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(buildHelperCommand(helperName), "get").start();

        // The protocol passes the server URL on stdin and signals the end of input by closing it
        try (var out = process.getOutputStream()) {
            out.write(url.getBytes(StandardCharsets.UTF_8));
        }

        // Helpers report errors on stdout, so both streams are needed to explain a failure
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);

        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("Docker credential helper timed out");
        }

        int exitCode = process.exitValue();
        if (exitCode != 0) {
            String message = !stdout.isBlank() ? stdout.trim() : stderr.trim();
            throw new IOException(
                    String.format("Docker credential helper exited with code %d. Error: %s", exitCode, message));
        }

        Map<String, String> reply;
        try {
            reply = parseJsonObject(stdout);
        } catch (IllegalArgumentException e) {
            throw new IOException("Docker credential helper returned invalid JSON: " + e.getMessage(), e);
        }

        String secret = reply.get("Secret");
        if (secret == null || secret.isEmpty()) {
            throw new IOException("Docker credential helper did not return a secret");
        }
        return secret;
    }

    static String buildHelperCommand(String helperName) {
        // If helper name contains a path separator, use it as-is (absolute or relative path)
        // Otherwise, prefix with "docker-credential-"
        if (helperName.contains("/") || helperName.contains("\\")) {
            return helperName;
        }
        return "docker-credential-" + helperName;
    }

    /**
     * Parses a flat JSON object into its string members. Members whose value is not a string (for example
     * {@code null}) are skipped, as the credential helper protocol only returns strings.
     */
    static Map<String, String> parseJsonObject(String json) {
        Map<String, String> result = new HashMap<>();
        int[] pos = {0};
        skipWhitespace(json, pos);
        expect(json, pos, '{');
        skipWhitespace(json, pos);
        if (peek(json, pos) == '}') {
            return result;
        }
        while (true) {
            skipWhitespace(json, pos);
            String key = readString(json, pos);
            skipWhitespace(json, pos);
            expect(json, pos, ':');
            skipWhitespace(json, pos);
            if (peek(json, pos) == '"') {
                result.put(key, readString(json, pos));
            } else {
                skipLiteral(json, pos);
            }
            skipWhitespace(json, pos);
            char c = next(json, pos);
            if (c == '}') {
                return result;
            } else if (c != ',') {
                throw new IllegalArgumentException("Expected ',' or '}' at position " + (pos[0] - 1));
            }
        }
    }

    private static char peek(String json, int[] pos) {
        if (pos[0] >= json.length()) {
            throw new IllegalArgumentException("Unexpected end of input");
        }
        return json.charAt(pos[0]);
    }

    private static char next(String json, int[] pos) {
        char c = peek(json, pos);
        pos[0]++;
        return c;
    }

    private static void expect(String json, int[] pos, char expected) {
        char c = next(json, pos);
        if (c != expected) {
            throw new IllegalArgumentException("Expected '" + expected + "' at position " + (pos[0] - 1));
        }
    }

    private static void skipWhitespace(String json, int[] pos) {
        while (pos[0] < json.length() && Character.isWhitespace(json.charAt(pos[0]))) {
            pos[0]++;
        }
    }

    private static void skipLiteral(String json, int[] pos) {
        while (pos[0] < json.length() && ",}".indexOf(json.charAt(pos[0])) < 0) {
            pos[0]++;
        }
    }

    private static String readString(String json, int[] pos) {
        expect(json, pos, '"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = next(json, pos);
            if (c == '"') {
                return sb.toString();
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            char e = next(json, pos);
            switch (e) {
                case '"':
                case '\\':
                case '/':
                    sb.append(e);
                    break;
                case 'b':
                    sb.append('\b');
                    break;
                case 'f':
                    sb.append('\f');
                    break;
                case 'n':
                    sb.append('\n');
                    break;
                case 'r':
                    sb.append('\r');
                    break;
                case 't':
                    sb.append('\t');
                    break;
                case 'u':
                    if (pos[0] + 4 > json.length()) {
                        throw new IllegalArgumentException("Truncated unicode escape");
                    }
                    try {
                        sb.append((char) Integer.parseInt(json.substring(pos[0], pos[0] + 4), 16));
                    } catch (NumberFormatException nfe) {
                        throw new IllegalArgumentException("Invalid unicode escape at position " + pos[0], nfe);
                    }
                    pos[0] += 4;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid escape '\\" + e + "'");
            }
        }
    }
}
