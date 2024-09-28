/*
 * Copyright (c) 2008 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */

package org.codehaus.plexus.components.secdispatcher.internal;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Source of master password.
 */
public interface MasterPasswordSource {
    /**
     * Handles the URI to get master password. Implementation may do one of the following things:
     * <ul>
     *     <li>if the URI cannot be handled by given source, return {@code null}</li>
     *     <li>if master password retrieval was attempted, but failed throw {@link SecDispatcherException}</li>
     *     <li>happy path: return the master password.</li>
     * </ul>
     *
     * @param masterSource the source of master password, and opaque string.
     * @return the master password, or {@code null} if implementation does not handle this masterSource
     * @throws SecDispatcherException If implementation does handle this masterSource, but cannot obtain it
     */
    String handle(String masterSource) throws SecDispatcherException;
}
