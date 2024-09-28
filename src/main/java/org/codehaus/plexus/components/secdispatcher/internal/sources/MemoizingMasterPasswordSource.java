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

package org.codehaus.plexus.components.secdispatcher.internal.sources;

import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.MasterPasswordSource;

import static java.util.Objects.requireNonNull;

public class MemoizingMasterPasswordSource implements MasterPasswordSource {
    private final MasterPasswordSource masterPasswordSource;
    private final ConcurrentHashMap<URI, String> memo;

    public MemoizingMasterPasswordSource(MasterPasswordSource masterPasswordSource) {
        this.masterPasswordSource = requireNonNull(masterPasswordSource);
        this.memo = new ConcurrentHashMap<>();
    }

    @Override
    public String handle(URI uri) throws SecDispatcherException {
        return memo.computeIfAbsent(uri, k -> masterPasswordSource.handle(uri));
    }
}
