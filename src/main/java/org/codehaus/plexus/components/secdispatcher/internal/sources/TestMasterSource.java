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

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.codehaus.plexus.components.secdispatcher.MasterMeta;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

import javax.inject.Named;
import javax.inject.Singleton;

import static java.util.Objects.requireNonNull;

/**
 * Master source for testing purposes, stores the master password plaintext in configuration.
 */
@Singleton
@Named(TestMasterSource.NAME)
public class TestMasterSource extends PrefixMasterSourceSupport {
    public static final String NAME = "test";

    public TestMasterSource() {
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
                return "Test Source (for testing only)";
            }

            @Override
            public Collection<Field> fields() {
                return List.of(Field.builder("password")
                        .optional(false)
                        .description("The password for testing")
                        .build());
            }

            @Override
            public String createConfig(Map<String, String> data) {
                return NAME + ":" + requireNonNull(data.get("password"), "Config incomplete");
            }
        };
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        return transformed;
    }
}
