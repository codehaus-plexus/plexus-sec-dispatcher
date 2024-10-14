package org.codehaus.plexus.components.secdispatcher;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Meta description of dispatcher.
 */
public interface DispatcherMeta {
    final class Field {
        private final String key;
        private final boolean optional;
        private final String defaultValue;
        private final String description;
        private final List<Field> options;

        private Field(String key, boolean optional, String defaultValue, String description, List<Field> options) {
            this.key = requireNonNull(key);
            this.optional = optional;
            this.defaultValue = defaultValue;
            this.description = requireNonNull(description);
            this.options = options;
        }

        /**
         * The key to be used in configuration map for field.
         */
        public String getKey() {
            return key;
        }

        /**
         * Is configuration optional?
         */
        public boolean isOptional() {
            return optional;
        }

        /**
         * Optional default value of the configuration.
         */
        public Optional<String> getDefaultValue() {
            return Optional.ofNullable(defaultValue);
        }

        /**
         * The human description of the configuration.
         */
        public String getDescription() {
            return description;
        }

        /**
         * Optional list of options, if this configuration accepts limited values. Each option is represented
         * as field, where {@link #getKey()} represents the value to be used, and {@link #displayName()} represents
         * the description of option. The {@link #getDefaultValue()}, if present represents the value to be used
         * instead of {@link #getKey()}.
         */
        public Optional<List<Field>> getOptions() {
            return Optional.ofNullable(options);
        }

        public static Builder builder(String key) {
            return new Builder(key);
        }

        public static final class Builder {
            private final String key;
            private boolean optional;
            private String defaultValue;
            private String description;
            private List<Field> options;

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

            public Builder options(List<Field> options) {
                this.options = requireNonNull(options);
                return this;
            }

            public Field build() {
                return new Field(key, optional, defaultValue, description, options);
            }
        }
    }

    /**
     * Option to hide this instance from users, like for migration or legacy purposes.
     */
    default boolean isHidden() {
        return false;
    }

    /**
     * The name of the dispatcher.
     */
    String name();

    /**
     * Returns the display (human) name of the dispatcher.
     */
    String displayName();

    /**
     * Returns the configuration fields of the dispatcher.
     */
    Collection<Field> fields();
}
