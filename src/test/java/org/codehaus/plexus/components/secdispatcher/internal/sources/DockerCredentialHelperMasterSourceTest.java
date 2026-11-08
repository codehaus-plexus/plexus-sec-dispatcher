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
import java.util.Map;
import java.util.Set;

import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisabledOnOs(value = OS.WINDOWS, disabledReason = "The fake helper is a POSIX shell script")
class DockerCredentialHelperMasterSourceTest {

    private static final String SERVER = "https://registry.example.com/v2/";

    @TempDir
    static Path tempDir;

    static Path helperDir;

    /**
     * Writes a fake {@code docker-credential-fake} helper: it only knows {@code SERVER}, answering with JSON in
     * which the secret contains escapes, and reports the protocol's error text on stdout otherwise.
     */
    @BeforeAll
    static void setup() throws IOException {
        helperDir = tempDir.resolve("bin");
        Files.createDirectories(helperDir);
        Path helper = helperDir.resolve("docker-credential-fake");
        String script = "#!/bin/sh\n"
                + "case \"$1\" in\n"
                + "  list)\n"
                + "    echo '{\"" + SERVER + "\":\"testuser\"}'\n"
                + "    ;;\n"
                + "  get)\n"
                + "    url=$(cat)\n"
                + "    if [ \"$url\" = \"" + SERVER + "\" ]; then\n"
                + "      printf '%s\\n' '{\"ServerURL\":\"" + SERVER + "\",\"Username\":\"testuser\","
                + "\"Secret\":\"p\\\"ass\\\\word\\u0021\"}'\n"
                + "    else\n"
                + "      echo 'credentials not found in native keychain'\n"
                + "      exit 1\n"
                + "    fi\n"
                + "    ;;\n"
                + "  *)\n"
                + "    exit 2\n"
                + "    ;;\n"
                + "esac\n";
        Files.writeString(helper, script);
        Files.setPosixFilePermissions(
                helper,
                Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE));
    }

    @Test
    void testMetadata() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        assertTrue(source.description().contains("Docker Credential Helper"));
        assertEquals(
                "docker-credential:helper-name?url=server-url",
                source.configTemplate().orElseThrow());
    }

    @Test
    void testHandleReturnsNullForNonMatchingPrefix() throws SecDispatcherException {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        assertNull(source.handle("env:SOME_VAR"));
        assertNull(source.handle("git-credential:cache?url=https://example.com"));
    }

    @Test
    void testHandleThrowsExceptionForMissingUrlParameter() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        SecDispatcherException e =
                assertThrows(SecDispatcherException.class, () -> source.handle("docker-credential:fake"));
        assertTrue(e.getMessage().contains("Expected format"));
    }

    @Test
    void testHandleThrowsExceptionForInvalidParameter() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        SecDispatcherException e =
                assertThrows(SecDispatcherException.class, () -> source.handle("docker-credential:fake?invalid=value"));
        assertTrue(e.getMessage().contains("Expected URL parameter"));
    }

    @Test
    void testHandleThrowsExceptionForEmptyUrl() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        assertThrows(SecDispatcherException.class, () -> source.handle("docker-credential:fake?url="));
    }

    @Test
    void testHandleWithHelperByPath() throws SecDispatcherException {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        String secret =
                source.handle("docker-credential:" + helperDir.resolve("docker-credential-fake") + "?url=" + SERVER);

        assertEquals("p\"ass\\word!", secret);
    }

    @Test
    void testHandleReportsHelperErrorFromStdout() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        SecDispatcherException e = assertThrows(
                SecDispatcherException.class,
                () -> source.handle("docker-credential:" + helperDir.resolve("docker-credential-fake")
                        + "?url=https://other.example.com"));
        assertTrue(e.getMessage().contains("credentials not found in native keychain"), e.getMessage());
    }

    @Test
    void testHandleWithMissingHelper() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        assertThrows(
                SecDispatcherException.class,
                () -> source.handle("docker-credential:" + helperDir.resolve("no-such-helper") + "?url=" + SERVER));
    }

    @Test
    void testValidateConfigurationWithInvalidFormat() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        SecDispatcher.ValidationResponse response = source.validateConfiguration("docker-credential:fake");

        assertNotNull(response);
        assertFalse(response.isValid());
        assertTrue(response.getReport().containsKey(SecDispatcher.ValidationResponse.Level.ERROR));
    }

    @Test
    void testValidateConfigurationWithInvalidUrl() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        SecDispatcher.ValidationResponse response =
                source.validateConfiguration("docker-credential:fake?url=invalid url with spaces");

        assertFalse(response.isValid());
    }

    @Test
    void testValidateConfigurationWithNonMatchingPrefix() {
        assertNull(new DockerCredentialHelperMasterSource().validateConfiguration("env:SOME_VAR"));
    }

    @Test
    void testValidateConfigurationWithHelper() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        SecDispatcher.ValidationResponse response = source.validateConfiguration(
                "docker-credential:" + helperDir.resolve("docker-credential-fake") + "?url=" + SERVER);

        assertTrue(response.isValid());
        assertTrue(response.getReport().containsKey(SecDispatcher.ValidationResponse.Level.INFO));
    }

    @Test
    void testValidateConfigurationWithMissingHelper() {
        DockerCredentialHelperMasterSource source = new DockerCredentialHelperMasterSource();

        SecDispatcher.ValidationResponse response = source.validateConfiguration(
                "docker-credential:" + helperDir.resolve("no-such-helper") + "?url=" + SERVER);

        assertFalse(response.isValid());
    }

    @Test
    void testBuildHelperCommand() {
        assertEquals(
                "docker-credential-osxkeychain", DockerCredentialHelperMasterSource.buildHelperCommand("osxkeychain"));
        assertEquals(
                "/usr/local/bin/docker-credential-desktop",
                DockerCredentialHelperMasterSource.buildHelperCommand("/usr/local/bin/docker-credential-desktop"));
    }

    @Test
    void testParseJsonObject() {
        Map<String, String> parsed = DockerCredentialHelperMasterSource.parseJsonObject(
                " { \"ServerURL\" : \"u\", \"Count\": 3, \"Nothing\": null, \"Secret\": \"a\\n\\u00e9\\/b\" } ");

        assertEquals("u", parsed.get("ServerURL"));
        assertEquals("a\né/b", parsed.get("Secret"));
        assertFalse(parsed.containsKey("Count"));
        assertTrue(DockerCredentialHelperMasterSource.parseJsonObject("{}").isEmpty());
        assertThrows(IllegalArgumentException.class, () -> DockerCredentialHelperMasterSource.parseJsonObject("nope"));
        assertThrows(
                IllegalArgumentException.class,
                () -> DockerCredentialHelperMasterSource.parseJsonObject("{\"Secret\":\"unterminated"));
    }
}
