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

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.codehaus.plexus.components.secdispatcher.MasterSourceMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Password source that uses env.
 * <p>
 * Config: {@code env:$ENVIRONMENT_VARIABLE_NAME}
 */
@Singleton
@Named(EnvMasterSource.NAME)
public final class EnvMasterSource extends PrefixMasterSourceSupport implements MasterSourceMeta {
    public static final String NAME = "env";

    public EnvMasterSource() {
        super(NAME + ":");
    }

    @Override
    public String description() {
        return "Environment variable (variable name should be edited)";
    }

    @Override
    public Optional<String> configTemplate() {
        return Optional.of(NAME + ":$VARIABLE_NAME");
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        String value = System.getenv(transformed);
        if (value == null) {
            throw new SecDispatcherException("Environment variable '" + transformed + "' not found");
        }
        return value;
    }

    @Override
    protected SecDispatcher.ValidationResponse doValidateConfiguration(String transformed) {
        String value = System.getenv(transformed);
        if (value == null) {
            return new SecDispatcher.ValidationResponse(
                    getClass().getSimpleName(),
                    true,
                    Map.of(
                            SecDispatcher.ValidationResponse.Level.WARNING,
                            List.of("Configured environment variable not exist")),
                    List.of());
        } else {
            return new SecDispatcher.ValidationResponse(
                    getClass().getSimpleName(),
                    true,
                    Map.of(
                            SecDispatcher.ValidationResponse.Level.INFO,
                            List.of("Configured environment variable exist")),
                    List.of());
        }
    }
}
