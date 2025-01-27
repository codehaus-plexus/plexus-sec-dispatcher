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
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Password source that uses <a href="https://developer.1password.com/docs/cli/get-started">1Password CLI</a> with its
 * <a href="https://developer.1password.com/docs/cli/reference/commands/read/">read command</a> to retrieve passwords from
 * 1Password vaults.
 * <p>
 * Config: {@code onepassword:$SECRET_REFERENCE_URI}.
 * The secret reference URI format is outlined at <a href="https://developer.1password.com/docs/cli/secret-reference-syntax">Secret Reference Syntax</a>.
 * @see <a href="https://developer.1password.com/">1Password</a>
 */
@Singleton
@Named(OnePasswordCliMasterSource.NAME)
public final class OnePasswordCliMasterSource extends PrefixMasterSourceSupport implements MasterSourceMeta {
    public static final String NAME = "onepassword";

    private static final String OP_CLI_EXECUTABLE = "op";

    public OnePasswordCliMasterSource() {
        super(NAME + ":");
    }

    @Override
    public String description() {
        return "1Password CLI (secret reference URI should be edited)";
    }

    @Override
    public Optional<String> configTemplate() {
        return Optional.of(NAME + ":$SECRET_REFERENCE_URI");
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        try {
            return execute1PasswordCli(Arrays.asList("read", transformed, "--no-newline"), 30);
        } catch (Exception e) {
            throw new SecDispatcherException(
                    String.format("1Password CLI reported an error reading %s: %s", transformed, e.getMessage()), e);
        }
    }

    @Override
    protected SecDispatcher.ValidationResponse doValidateConfiguration(String transformed) {
        HashMap<SecDispatcher.ValidationResponse.Level, List<String>> report = new HashMap<>();
        boolean isValid = false;
        try {
            execute1PasswordCli(Collections.singleton("--version"), 2);
            try {
                execute1PasswordCli(Arrays.asList("read", transformed, "--no-newline"), 30);
                report.put(
                        SecDispatcher.ValidationResponse.Level.INFO,
                        List.of("Configured 1Password secret reference exists and is accessible!"));
                isValid = true;
            } catch (IllegalStateException e) {
                report.put(
                        SecDispatcher.ValidationResponse.Level.ERROR,
                        List.of(String.format(
                                "1Password CLI reported an error reading secret item %s: %s",
                                transformed, e.getMessage())));
            } catch (IOException e) {
                report.put(
                        SecDispatcher.ValidationResponse.Level.ERROR,
                        List.of(String.format("General issue executing 1Password CLI: %s", e.getMessage())));
            }
        } catch (IllegalStateException e) {
            report.put(
                    SecDispatcher.ValidationResponse.Level.ERROR,
                    List.of(String.format("1Password CLI reported an error exposing the version: %s", e.getMessage())));
        } catch (IOException e) {
            report.put(
                    SecDispatcher.ValidationResponse.Level.ERROR,
                    List.of(String.format("Seems 1Password CLI is not installed: %s", e.getMessage())));
        }
        return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), isValid, report, List.of());
    }

    public String execute1PasswordCli(Collection<String> arguments, int timeoutSeconds) throws IOException {
        List<String> cmd = new ArrayList<>();
        cmd.add(OP_CLI_EXECUTABLE);
        cmd.addAll(arguments);
        StringWriter output = new StringWriter();
        Process process = new ProcessBuilder(cmd.toArray(new String[0])).start();
        try (BufferedReader reader = process.inputReader()) {
            reader.transferTo(output);
        }
        try {
            process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            StringWriter error = new StringWriter();
            try (BufferedReader reader = process.errorReader()) {
                reader.transferTo(error);
            }
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                throw new IllegalStateException(String.format(
                        "1Password CLI process exited with code %d, Error: %s", exitCode, error.toString()));
            } else {
                return output.toString();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("1Password CLI process was interrupted", e);
        }
    }
}
