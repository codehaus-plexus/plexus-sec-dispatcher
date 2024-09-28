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

import javax.inject.Named;
import javax.inject.Singleton;

import java.net.URI;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;
import org.codehaus.plexus.components.secdispatcher.internal.MasterPasswordSource;

/**
 * Password source that uses env.
 */
@Singleton
@Named(EnvMasterPasswordSource.NAME)
public final class EnvMasterPasswordSource implements MasterPasswordSource {
    public static final String NAME = "env";

    @Override
    public String handle(URI uri) throws SecDispatcherException {
        if (!NAME.equals(uri.getScheme())) {
            return null;
        }
        String value = System.getenv(uri.getPath().substring(1));
        if (value == null) {
            throw new SecDispatcherException("Environment variable '" + uri.getPath() + "' not found");
        }
        return value;
    }
}
