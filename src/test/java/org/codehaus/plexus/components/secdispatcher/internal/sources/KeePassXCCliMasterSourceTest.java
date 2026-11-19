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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisabledOnOs(value = OS.WINDOWS, disabledReason = "the fake CLI is a POSIX shell script")
class KeePassXCCliMasterSourceTest {

    @TempDir
    static Path tempDir;

    private static Path fakeCli;

    @BeforeAll
    static void setup() throws IOException {
        Path bin = tempDir.resolve("bin");
        Files.createDirectories(bin);
        fakeCli = bin.resolve("keepassxc-cli");
        Files.writeString(
                fakeCli,
                "#!/bin/sh\n"
                        + "case \" $* \" in *missing*) echo 'Entry not found' >&2; exit 1;; esac\n"
                        + "printf '%s\\n' 's3cret'\n");
        Files.setPosixFilePermissions(
                fakeCli,
                Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE));
    }

    private static KeePassXCCliMasterSource source() {
        return new KeePassXCCliMasterSource(fakeCli.toString());
    }

    private static String config(String entry) {
        return "keepassxc:db.kdbx:" + entry + "?field=password";
    }

    @Test
    void metadata() {
        KeePassXCCliMasterSource source = source();
        assertEquals("keepassxc", KeePassXCCliMasterSource.NAME);
        assertTrue(source.description().contains("KeePassXC"));
        assertTrue(source.configTemplate().orElseThrow().contains("field=password"));
    }

    @Test
    void readsTheSecretAndNeverLogsIt() throws Exception {
        String secret = source().handle(config("root/credential"));
        assertEquals("s3cret", secret);
    }

    @Test
    void reportsCliFailure() {
        SecDispatcherException e = assertThrows(SecDispatcherException.class, () -> source().handle(config("missing")));
        assertTrue(e.getMessage().contains("Entry not found"), e.getMessage());
    }

    @Test
    void validatesTheConfiguration() {
        KeePassXCCliMasterSource source = source();
        SecDispatcher.ValidationResponse response = source.validateConfiguration(config("root/credential"));
        assertTrue(response.isValid());
        assertTrue(response.getReport().containsKey(SecDispatcher.ValidationResponse.Level.INFO));

        assertFalse(source.validateConfiguration("keepassxc:db.kdbx:entry").isValid());
        assertFalse(
                source.validateConfiguration("keepassxc:db.kdbx?field=password").isValid());
        assertFalse(
                source.validateConfiguration("keepassxc:db.kdbx:entry?other=x").isValid());
    }

    @Test
    void emptyFieldOrEntryIsRejected() {
        KeePassXCCliMasterSource source = source();
        assertThrows(SecDispatcherException.class, () -> source.handle("keepassxc:db.kdbx:entry?field="));
        assertThrows(SecDispatcherException.class, () -> source.handle("keepassxc:db.kdbx:?field=password"));
    }
}
