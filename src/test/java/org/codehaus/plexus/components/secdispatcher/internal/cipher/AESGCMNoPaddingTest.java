package org.codehaus.plexus.components.secdispatcher.internal.cipher;

import org.codehaus.plexus.components.secdispatcher.Cipher;

public class AESGCMNoPaddingTest extends CipherTestSupport {
    @Override
    Cipher getCipher() {
        return new AESGCMNoPadding();
    }
}
