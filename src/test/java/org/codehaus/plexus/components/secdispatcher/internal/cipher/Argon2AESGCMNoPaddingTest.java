package org.codehaus.plexus.components.secdispatcher.internal.cipher;

import java.security.Security;

import org.codehaus.plexus.components.secdispatcher.Cipher;

public class Argon2AESGCMNoPaddingTest extends CipherTestSupport {

    @Override
    Cipher getCipher() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        return new Argon2AESGCMNoPadding();
    }
}
