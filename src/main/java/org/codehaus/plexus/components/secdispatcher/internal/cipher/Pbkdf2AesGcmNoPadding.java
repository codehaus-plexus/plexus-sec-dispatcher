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

import javax.inject.Named;
import javax.inject.Singleton;

/**
 * The AES/GCM cipher under a name that also identifies its key derivation function.
 *
 * <p>The clear-text name of this cipher is {@value #CIPHER_ALG}. It produces exactly the same format as
 * {@link AESGCMNoPadding} under its legacy {@code AES/GCM/NoPadding} name, so both names can decrypt each other's
 * output. New configurations should use the KDF-qualified name: a future KDF can then be added without reusing a name
 * that hides how the key was derived.</p>
 *
 * @since 4.0.3
 */
@Singleton
@Named(Pbkdf2AesGcmNoPadding.CIPHER_ALG)
public class Pbkdf2AesGcmNoPadding extends AESGCMNoPadding {

    /** Cipher name that names both the KDF and the symmetric cipher. */
    public static final String CIPHER_ALG = "PBKDF2WithHmacSHA512/AES/GCM/NoPadding";
}
