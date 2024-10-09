package org.codehaus.plexus.components.secdispatcher;

import java.util.Collection;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Meta description of dispatcher.
 */
public interface Meta {
    class Field {
        private final String key;
        private final boolean optional;
        private final String defaultValue;
        private final String description;

        private Field(String key, boolean optional, String defaultValue, String description) {
            this.key = requireNonNull(key);
            this.optional = optional;
            this.defaultValue = defaultValue;
            this.description = requireNonNull(description);
        }

        public String getKey() {
            return key;
        }

        public boolean isOptional() {
            return optional;
        }

        public Optional<String> getDefaultValue() {
            return Optional.ofNullable(defaultValue);
        }

        public String getDescription() {
            return description;
        }

        public static Builder builder(String key) {
            return new Builder(key);
        }

        public static class Builder {
            private final String key;
            private boolean optional;
            private String defaultValue;
            private String description;

            private Builder(String key) {
                this.key = requireNonNull(key);
            }

            public Builder optional(boolean optional) {
                this.optional = optional;
                return this;
            }

            public Builder defaultValue(String defaultValue) {
                this.defaultValue = defaultValue;
                return this;
            }

            public Builder description(String description) {
                this.description = requireNonNull(description);
                return this;
            }

            public Field build() {
                return new Field(key, optional, defaultValue, description);
            }
        }
    }

    /**
     * The key of the item.
     */
    String id();

    /**
     * Returns the display (human) name of the item.
     */
    String displayName();

    /**
     * Returns the configuration fields of the item.
     */
    Collection<Field> fields();
}
