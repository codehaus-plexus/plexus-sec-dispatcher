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

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.MasterMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

import static java.util.Objects.requireNonNull;

/**
 * Password source that uses env.
 */
@Singleton
@Named(SystemPropertyMasterSource.NAME)
public final class SystemPropertyMasterSource extends PrefixMasterSourceSupport {
    public static final String NAME = "prop";

    public SystemPropertyMasterSource() {
        super(NAME + ":");
    }

    @Override
    public MasterMeta meta() {
        return new MasterMeta() {
            @Override
            public String id() {
                return NAME;
            }

            @Override
            public String displayName() {
                return "Java System Property Source";
            }

            @Override
            public Collection<Field> fields() {
                return List.of(Field.builder("name")
                        .optional(false)
                        .description("Name of the Java System property")
                        .build());
            }

            @Override
            public String createConfig(Map<String, String> data) {
                return NAME + ":" + requireNonNull(data.get("name"), "Config incomplete");
            }
        };
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        String value = System.getProperty(transformed);
        if (value == null) {
            throw new SecDispatcherException("System property '" + transformed + "' not found");
        }
        return value;
    }
}
