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

import java.util.function.Function;
import java.util.function.Predicate;

import static java.util.Objects.requireNonNull;

/**
 * Master password source support class for simple "prefix" use case.
 */
public abstract class PrefixMasterPasswordSourceSupport extends MasterPasswordSourceSupport {
    public PrefixMasterPasswordSourceSupport(String prefix) {
        super(prefixMatcher(prefix), prefixRemover(prefix));
    }

    private static Predicate<String> prefixMatcher(String prefix) {
        requireNonNull(prefix, "prefix cannot be null");
        return s -> s != null && s.startsWith(prefix);
    }

    private static Function<String, String> prefixRemover(String prefix) {
        requireNonNull(prefix, "prefix cannot be null");
        return s -> s.substring(prefix.length());
    }
}
