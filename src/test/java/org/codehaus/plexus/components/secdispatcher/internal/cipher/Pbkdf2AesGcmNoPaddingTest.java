/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the Apache License Version 2.0 is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations
under the License.
 */

package org.codehaus.plexus.components.secdispatcher.internal.cipher;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Pbkdf2AesGcmNoPaddingTest {

    @Test
    void nameIdentifiesBothTheKdfAndTheCipher() {
        assertTrue(Pbkdf2AesGcmNoPadding.CIPHER_ALG.contains("PBKDF2WithHmacSHA512"));
        assertTrue(Pbkdf2AesGcmNoPadding.CIPHER_ALG.contains("AES/GCM/NoPadding"));
    }

    @Test
    void newNameCanDecryptLegacyCiphertext() throws Exception {
        String ciphertext = new AESGCMNoPadding().encrypt("secret", "password");
        assertEquals("secret", new Pbkdf2AesGcmNoPadding().decrypt(ciphertext, "password"));
    }

    @Test
    void legacyNameCanDecryptNewCiphertext() throws Exception {
        String ciphertext = new Pbkdf2AesGcmNoPadding().encrypt("secret", "password");
        assertEquals("secret", new AESGCMNoPadding().decrypt(ciphertext, "password"));
    }
}
