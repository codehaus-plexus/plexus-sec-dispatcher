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
import java.util.function.Predicate;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.MasterPasswordSource;

import static java.util.Objects.requireNonNull;

public class MatchingMasterPasswordSource implements MasterPasswordSource {
    private final Predicate<URI> matcher;
    private final MasterPasswordSource masterPasswordSource;

    public MatchingMasterPasswordSource(Predicate<URI> matcher, MasterPasswordSource masterPasswordSource) {
        this.matcher = requireNonNull(matcher);
        this.masterPasswordSource = requireNonNull(masterPasswordSource);
    }

    @Override
    public String handle(URI uri) throws SecDispatcherException {
        if (matcher.test(uri)) {
            return masterPasswordSource.handle(uri);
        }
        return null;
    }
}
