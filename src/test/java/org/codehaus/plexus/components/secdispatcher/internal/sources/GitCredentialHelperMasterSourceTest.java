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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitCredentialHelperMasterSourceTest {

    @TempDir
    static Path tempDir;

    static Path mockHelperPath;

    @BeforeAll
    static void setup() throws IOException {
        // Create a mock git credential helper script
        // On Windows, create a batch file; on Unix-like systems, create a shell script
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            mockHelperPath = tempDir.resolve("mock-git-credential-helper.bat");
            String batchScript = "@echo off\r\n"
                    + "if \"%1\"==\"get\" (\r\n"
                    + "  REM Read input until empty line\r\n"
                    + "  :loop\r\n"
                    + "  set /p line=\r\n"
                    + "  if not defined line goto output\r\n"
                    + "  goto loop\r\n"
                    + "  :output\r\n"
                    + "  echo protocol=https\r\n"
                    + "  echo host=maven.apache.org\r\n"
                    + "  echo username=testuser\r\n"
                    + "  echo password=testPassword123\r\n"
                    + ")\r\n";
            Files.writeString(mockHelperPath, batchScript);
        } else {
            mockHelperPath = tempDir.resolve("mock-git-credential-helper");
            String script = "#!/bin/sh\n"
                    + "if [ \"$1\" = \"get\" ]; then\n"
                    + "  # Read input (we don't actually parse it in this simple mock)\n"
                    + "  while IFS= read -r line; do\n"
                    + "    [ -z \"$line\" ] && break\n"
                    + "  done\n"
                    + "  # Return mock credentials\n"
                    + "  echo \"protocol=https\"\n"
                    + "  echo \"host=maven.apache.org\"\n"
                    + "  echo \"username=testuser\"\n"
                    + "  echo \"password=testPassword123\"\n"
                    + "fi\n";

            Files.writeString(mockHelperPath, script);
            // Make it executable on Unix-like systems
            Files.setPosixFilePermissions(
                    mockHelperPath,
                    Set.of(
                            PosixFilePermission.OWNER_READ,
                            PosixFilePermission.OWNER_WRITE,
                            PosixFilePermission.OWNER_EXECUTE));
        }
    }

    @Test
    void testMetadata() {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        assertNotNull(source.description());
        assertTrue(source.description().contains("Git Credential Helper"));

        assertTrue(source.configTemplate().isPresent());
        assertEquals(
                "git-credential:helper-name?url=protocol://host/path",
                source.configTemplate().get());
    }

    @Test
    void testHandleReturnsNullForNonMatchingPrefix() throws SecDispatcherException {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        assertNull(source.handle("env:SOME_VAR"));
        assertNull(source.handle("file:/path/to/file"));
        assertNull(source.handle("other-prefix:value"));
    }

    @Test
    void testHandleThrowsExceptionForMissingUrlParameter() {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        SecDispatcherException exception =
                assertThrows(SecDispatcherException.class, () -> source.handle("git-credential:helper-name"));

        assertTrue(exception.getMessage().contains("Expected format"));
    }

    @Test
    void testHandleThrowsExceptionForInvalidUrlParameter() {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        SecDispatcherException exception = assertThrows(
                SecDispatcherException.class, () -> source.handle("git-credential:helper-name?invalid=value"));

        assertTrue(exception.getMessage().contains("Expected URL parameter"));
    }

    @Test
    void testHandleWithMockHelper() throws SecDispatcherException {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        String config = mockHelperPath.toString() + "?url=https://maven.apache.org/master";
        String password = source.handle("git-credential:" + config);

        assertEquals("testPassword123", password);
    }

    @Test
    void testValidateConfigurationWithInvalidFormat() {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        SecDispatcher.ValidationResponse response = source.validateConfiguration("git-credential:invalid-format");

        assertNotNull(response);
        assertFalse(response.isValid());
        assertTrue(response.getReport().containsKey(SecDispatcher.ValidationResponse.Level.ERROR));
    }

    @Test
    void testValidateConfigurationWithInvalidUrl() {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        SecDispatcher.ValidationResponse response =
                source.validateConfiguration("git-credential:helper?url=invalid url with spaces");

        assertNotNull(response);
        assertFalse(response.isValid());
        assertTrue(response.getReport().containsKey(SecDispatcher.ValidationResponse.Level.ERROR));
    }

    @Test
    void testValidateConfigurationWithNonMatchingPrefix() {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        SecDispatcher.ValidationResponse response = source.validateConfiguration("env:SOME_VAR");

        assertNull(response);
    }

    @Test
    void testValidateConfigurationWithMockHelper() {
        GitCredentialHelperMasterSource source = new GitCredentialHelperMasterSource();

        String config = mockHelperPath.toString() + "?url=https://maven.apache.org/master";
        SecDispatcher.ValidationResponse response = source.validateConfiguration("git-credential:" + config);

        assertNotNull(response);
        assertTrue(response.isValid());
        assertTrue(response.getReport().containsKey(SecDispatcher.ValidationResponse.Level.INFO));
    }

    @Test
    void testBuildHelperCommandWithShortName() {
        String result = GitCredentialHelperMasterSource.buildHelperCommand("cache");
        assertEquals("git-credential-cache", result);

        result = GitCredentialHelperMasterSource.buildHelperCommand("store");
        assertEquals("git-credential-store", result);
    }

    @Test
    void testBuildHelperCommandWithPath() {
        String result = GitCredentialHelperMasterSource.buildHelperCommand("/usr/local/bin/git-credential-osxkeychain");
        assertEquals("/usr/local/bin/git-credential-osxkeychain", result);

        result = GitCredentialHelperMasterSource.buildHelperCommand("./relative/path/helper");
        assertEquals("./relative/path/helper", result);
    }
}
