package org.codehaus.plexus.digest;

/*
 * Copyright 2001-2006 The Codehaus.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.codehaus.plexus.testing.PlexusTest;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.File;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the digester.
 *
 * @author <a href="mailto:brett@apache.org">Brett Porter</a>
 */
@PlexusTest
class DigesterTest
{
    private static final String MD5 = "adbc688ce77fa2aece4bb72cad9f98ba";

    private static final String SHA1 = "2a7b459938e12a2dc35d1bf6cff35e9c2b592fa9";

    private static final String SHA256 = "56bfadc51bd0591ae1af06d28f4b3f86736007b213bfa95016681c7f8b27090c";

    private static final String WRONG_SHA1 = "4d8703779816556cdb8be7f6bb5c954f4b5730e2";

    private final File file = new File(Objects.requireNonNull(getClass().getResource("/test-file.txt")).getPath());

    @Inject
    @Named( "sha1" )
    private Digester sha1Digest;

    @Inject
    @Named( "sha256" )
    private Digester sha256Digest;

    @Inject
    @Named( "md5" )
    private Digester md5Digest;

    @Test
    void algorithm()
    {
        assertEquals( "SHA-256", sha256Digest.getAlgorithm() );
        assertEquals( "SHA-1", sha1Digest.getAlgorithm() );
        assertEquals( "MD5", md5Digest.getAlgorithm() );
    }

    @Test
    void md5DigestFormat() {
        assertDoesNotThrow(() -> md5Digest.verify(file, MD5), "Bare format MD5 must not throw exception");
    }

    @Test
    void sha1DigestFormat() {
        assertDoesNotThrow( () -> sha1Digest.verify( file, SHA1 ), "Bare format SHA1 must not throw exception" );
    }

    @Test
    void wrongSha1DigestFormat() {
        assertThrows( DigesterException.class, () -> sha1Digest.verify( file, WRONG_SHA1 ), "Wrong SHA1 must throw exception" );
    }

    @Test
    void sha256DigestFormat() {
        assertDoesNotThrow( () -> sha256Digest.verify( file , SHA256 ), "Bare format SHA256 must not throw exception" );
    }

    @Test
    void opensslDigestMd5Format() {
        assertDoesNotThrow( () -> md5Digest.verify( file, "MD5(test-file.txt)= " + MD5 ), "OpenSSL MD5 format must not cause exception" );

        assertDoesNotThrow( () -> md5Digest.verify( file, "MD5 (test-file.txt) = " + MD5 ), "FreeBSD MD5 format must not cause exception" );
    }

    @Test
    void opensslDigestSha1Format() {
        assertDoesNotThrow( () -> sha1Digest.verify( file, "SHA1 (test-file.txt) = " + SHA1 ), "FreeBSD SHA1 format must not cause exception");

        assertThrows( DigesterException.class,
                () -> sha1Digest.verify( file, "SHA1 (FOO) = " + SHA1 ), "Wrong filename must throw exception");

        assertThrows( DigesterException.class,
                () -> sha1Digest.verify( file, "SHA1 (test-file.txt) = " + WRONG_SHA1 ), "Wrong SHA1 must throw exception" );
    }

    @Test
    void opensslDigestSha256Format() {
        assertDoesNotThrow( () -> sha256Digest.verify( file, "SHA256(test-file.txt) = " + SHA256 ), "FreeBSD SHA256 format must not cause exception" );

        assertThrows( DigesterException.class,
                () -> sha256Digest.verify( file, "SHA256(FOO) = " + SHA256 ), "Wrong filename must throw exception" );
    }

    @Test
    void gnuDigestMd5Format() {
        assertDoesNotThrow( () -> md5Digest.verify( file, MD5 + " *test-file.txt" ), "GNU format MD5 must not cause exception" );

        assertDoesNotThrow( () -> md5Digest.verify( file, MD5 + " test-file.txt" ), "GNU text format MD5 must not cause exception" );
    }

    @Test
    void gnuDigestSha1Format() {
        assertDoesNotThrow( () -> sha1Digest.verify( file, SHA1 + " *test-file.txt" ), "GNU format SHA1 must not cause exception");

        assertDoesNotThrow( () -> sha1Digest.verify( file, SHA1 + " test-file.txt" ), "GNU text format SHA1 must not cause exception");

        assertThrows( DigesterException.class,
                () -> sha1Digest.verify( file, SHA1 + " FOO" ), "Wrong filename must throw exception" );

        assertThrows( DigesterException.class,
                () -> sha1Digest.verify( file, WRONG_SHA1 + " test-file.txt" ), "Wrong SHA1 must throw exception" );
    }

    @Test
    void gnuDigestSha256Format() {
        assertDoesNotThrow( () -> sha256Digest.verify( file, SHA256 + " *test-file.txt" ), "GNU format SHA256 must not cause exception" );

        assertDoesNotThrow( () -> sha256Digest.verify( file, SHA256 + " test-file.txt" ), "GNU text format SHA256 must not cause exception" );
    }

    @Test
    void untrimmedContent() {
        assertDoesNotThrow( () -> sha1Digest.verify( file, SHA1 + " *test-file.txt \n" ), "GNU untrimmed SHA1 must not cause exception" );
    }
}
