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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HexFormat;

import org.codehaus.plexus.components.secdispatcher.SecDispatcherException;

/**
 * Password source that uses GnuPG Agent.
 */
@Singleton
@Named(GpgAgentMasterPasswordSource.NAME)
public final class GpgAgentMasterPasswordSource extends PrefixMasterPasswordSourceSupport {
    public static final String NAME = "gpg-agent";

    public GpgAgentMasterPasswordSource() {
        super(NAME + ":");
    }

    @Override
    protected String doHandle(String transformed) throws SecDispatcherException {
        String extra = "";
        if (transformed.contains("?")) {
            extra = transformed.substring(transformed.indexOf("?"));
            transformed = transformed.substring(0, transformed.indexOf("?"));
        }
        String socketLocation = transformed;
        boolean interactive = !extra.contains("non-interactive");
        try {
            Path socketLocationPath = Paths.get(socketLocation);
            if (!socketLocationPath.isAbsolute()) {
                socketLocationPath = Paths.get(System.getProperty("user.home"))
                        .resolve(socketLocationPath)
                        .toAbsolutePath();
            }
            return load(socketLocationPath, interactive);
        } catch (IOException e) {
            throw new SecDispatcherException(e.getMessage(), e);
        }
    }

    private String load(Path socketPath, boolean interactive) throws IOException {
        try (SocketChannel sock = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            sock.connect(UnixDomainSocketAddress.of(socketPath));
            try (BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(sock)));
                    OutputStream os = Channels.newOutputStream(sock)) {

                expectOK(in);
                String display = System.getenv("DISPLAY");
                if (display != null) {
                    os.write(("OPTION display=" + display + "\n").getBytes());
                    os.flush();
                    expectOK(in);
                }
                String term = System.getenv("TERM");
                if (term != null) {
                    os.write(("OPTION ttytype=" + term + "\n").getBytes());
                    os.flush();
                    expectOK(in);
                }
                // https://unix.stackexchange.com/questions/71135/how-can-i-find-out-what-keys-gpg-agent-has-cached-like-how-ssh-add-l-shows-yo
                String instruction = "GET_PASSPHRASE "
                        + (!interactive ? "--no-ask " : "")
                        + "plexus:secDispatcherMasterPassword"
                        + " "
                        + "X "
                        + "Maven+Master+Password "
                        + "Please+enter+your+Maven+master+password"
                        + "+to+use+it+for+decrypting+Maven+Settings\n";
                os.write((instruction).getBytes());
                os.flush();
                return mayExpectOK(in);
            }
        }
    }

    private void expectOK(BufferedReader in) throws IOException {
        String response = in.readLine();
        if (!response.startsWith("OK")) {
            throw new IOException("Expected OK but got this instead: " + response);
        }
    }

    private String mayExpectOK(BufferedReader in) throws IOException {
        String response = in.readLine();
        if (response.startsWith("ERR")) {
            return null;
        } else if (!response.startsWith("OK")) {
            throw new IOException("Expected OK/ERR but got this instead: " + response);
        }
        return new String(HexFormat.of()
                .parseHex(response.substring(Math.min(response.length(), 3)).trim()));
    }
}
