/*
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */

package org.codehaus.plexus.components.secdispatcher.internal.dispatchers;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.codehaus.plexus.components.secdispatcher.Dispatcher;
import org.codehaus.plexus.components.secdispatcher.DispatcherMeta;
import org.codehaus.plexus.components.secdispatcher.MasterSource;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher;
import org.codehaus.plexus.components.secdispatcher.SecDispatcher.ValidationResponse.Level;
import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * This dispatcher does not actually perform any crypto operations, but just forwards the string to be decrypted
 * to a {@link MasterSource}. The given string is supposed to contain a valid source reference which is resolvable
 * by one of the bound {@link MasterSource} implementations (and not actually an encrypted value).
 * This dispatcher doesn't support encryption, but just validates and returns the given master source reference.
 */
@Singleton
@Named(MasterSourceLookupDispatcher.NAME)
public class MasterSourceLookupDispatcher implements Dispatcher, DispatcherMeta {
    public static final String NAME = "masterSourceLookup";

    protected final Collection<MasterSource> sources;

    @Inject
    public MasterSourceLookupDispatcher(Collection<MasterSource> sources) {
        this.sources = sources;
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public String displayName() {
        return "Master Source Lookup Dispatcher";
    }

    @Override
    public Collection<Field> fields() {
        return Collections.emptyList();
    }

    @Override
    public EncryptPayload encrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        // just make sure the given string is a valid reference!
        decrypt(str, attributes, config);
        return new EncryptPayload(attributes, str);
    }

    @Override
    public String decrypt(String str, Map<String, String> attributes, Map<String, String> config)
            throws SecDispatcherException {
        Optional<String> plain = sources.stream()
                .map(source -> source.handle(str))
                .filter(Objects::nonNull)
                .findFirst();
        if (plain.isPresent()) {
            return plain.get();
        } else {
            throw new SecDispatcherException("No master source found for : " + str);
        }
    }

    @Override
    public SecDispatcher.ValidationResponse validateConfiguration(Map<String, String> config) {
        // there is nothing really to validate without having a master reference at hand (which is outside the config)
        Map<Level, List<String>> report = Collections.singletonMap(
                SecDispatcher.ValidationResponse.Level.INFO, List.of("Configured Source configuration valid"));
        return new SecDispatcher.ValidationResponse(getClass().getSimpleName(), true, report, Collections.emptyList());
    }
}
