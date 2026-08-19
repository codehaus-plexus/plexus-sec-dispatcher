# Plexus Security Dispatcher

[![Maven Central](https://img.shields.io/maven-central/v/org.codehaus.plexus/plexus-sec-dispatcher.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/org.codehaus.plexus/plexus-sec-dispatcher)
[![GitHub CI](https://github.com/codehaus-plexus/plexus-sec-dispatcher/actions/workflows/maven.yml/badge.svg)](https://github.com/codehaus-plexus/plexus-sec-dispatcher/actions)
[![Reproducible Builds](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jvm-repo-rebuild/reproducible-central/master/content/org/codehaus/plexus/plexus-sec-dispatcher/badge.json)](https://github.com/jvm-repo-rebuild/reproducible-central/blob/master/content/org/codehaus/plexus/plexus-sec-dispatcher/README.md)

Encrypts and decrypts passwords in Maven's `settings.xml` — the `{...}` values you get from
`mvn --encrypt-password`. Ciphers and password sources are pluggable.

As of 4.x it also contains the cipher implementation itself; the separate `plexus-cipher` artifact is
archived and should not be used for new work.

## Status

Maintained, and **4.x requires Java 17**, in step with Maven 4.

Because this handles credentials, please report any suspected vulnerability privately rather than in a
public issue — see [SECURITY.md](https://github.com/codehaus-plexus/.github/blob/master/SECURITY.md).

## Using it

```xml
<dependency>
  <groupId>org.codehaus.plexus</groupId>
  <artifactId>plexus-sec-dispatcher</artifactId>
</dependency>
```

Check the badge above for the current version.

If you are a Maven *user* rather than a tool author, you probably want the
[Maven password encryption guide](https://maven.apache.org/guides/mini/guide-encryption-4.html) instead —
this artifact is the implementation behind it.

## Requirements

Java 17 or later for `4.x`.

## Documentation

- [Project site](https://codehaus-plexus.github.io/plexus-sec-dispatcher/)
- [Javadoc](https://javadoc.io/doc/org.codehaus.plexus/plexus-sec-dispatcher)
- [Maven password encryption guide](https://maven.apache.org/guides/mini/guide-encryption-4.html)
- [Release notes](https://github.com/codehaus-plexus/plexus-sec-dispatcher/releases)

## Contributing

See [CONTRIBUTING.md](https://github.com/codehaus-plexus/.github/blob/master/CONTRIBUTING.md). In short:
`mvn verify` builds, and run `mvn spotless:apply` before pushing or CI will fail on formatting.
