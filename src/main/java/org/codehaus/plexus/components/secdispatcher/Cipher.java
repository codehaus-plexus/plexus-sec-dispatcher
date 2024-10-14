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
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.codehaus.plexus.components.secdispatcher;

/**
 * Cipher interface.
 *
 * @since 4.0.1
 */
public interface Cipher {
    /**
     * Encrypts the clear text data with password and returns result. No argument is allowed to be {@code null}.
     *
     * @throws CipherException if encryption failed (is unexpected to happen, as it would mean that Java Runtime
     * lacks some Crypto elements).
     */
    String encrypt(final String clearText, final String password) throws CipherException;

    /**
     * Decrypts the encrypted text with password and returns clear text result. No argument is allowed to be {@code null}.
     *
     * @throws CipherException if decryption failed. It may happen as with {@link #encrypt(String, String)} due Java
     * Runtime lacking some Crypto elements (less likely). Most likely decrypt will fail due wrong provided password
     * or maybe corrupted encrypted text.
     */
    String decrypt(final String encryptedText, final String password) throws CipherException;
}
