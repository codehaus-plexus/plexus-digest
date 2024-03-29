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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.codehaus.plexus.util.IOUtil;
import org.codehaus.plexus.util.StringUtils;

/**
 * Create a digest for a file.
 *
 * @author <a href="mailto:brett@apache.org">Brett Porter</a>
 */
public abstract class AbstractDigester implements Digester {
    private final StreamingDigester streamingDigester;

    /**
     * <p>Constructor for AbstractDigester.</p>
     *
     * @param streamingDigester a {@link org.codehaus.plexus.digest.StreamingDigester} object.
     */
    protected AbstractDigester(StreamingDigester streamingDigester) {
        this.streamingDigester = streamingDigester;
    }

    /**
     * <p>getAlgorithm.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getAlgorithm() {
        return streamingDigester.getAlgorithm();
    }

    /** {@inheritDoc} */
    public String calc(File file) throws DigesterException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            streamingDigester.reset();
            streamingDigester.update(fis);
            return streamingDigester.calc();
        } catch (IOException e) {
            throw new DigesterException(
                    "Unable to calculate the " + streamingDigester.getAlgorithm() + " hashcode for "
                            + file.getAbsolutePath() + ": " + e.getMessage(),
                    e);
        } finally {
            IOUtil.close(fis);
        }
    }

    /** {@inheritDoc} */
    public void verify(File file, String checksum) throws DigesterException {
        String trimmedChecksum = DigestUtils.cleanChecksum(checksum, streamingDigester.getAlgorithm(), file.getName());

        // Create checksum for file
        String sum = calc(file);
        if (!StringUtils.equalsIgnoreCase(trimmedChecksum, sum)) {
            throw new DigesterException("Checksum failed (expected=" + trimmedChecksum + ", actual=" + sum + ")");
        }
    }

    /**
     * <p>toString.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String toString() {
        return "[Digester:" + streamingDigester.getAlgorithm() + "]";
    }
}
