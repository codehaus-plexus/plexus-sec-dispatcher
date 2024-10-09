package org.codehaus.plexus.components.secdispatcher;

import java.util.Map;

/**
 * Meta description of master password source.
 */
public interface MasterMeta extends Meta {
    /**
     * Creates source configuration that can be used as "masterSource".
     */
    String createConfig(Map<String, String> data);
}
