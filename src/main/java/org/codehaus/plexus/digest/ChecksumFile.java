package org.codehaus.plexus.digest;

/*
 * Copyright 2001-2007 The Codehaus.
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

import javax.inject.Inject;
import javax.inject.Named;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.codehaus.plexus.util.FileUtils;
import org.codehaus.plexus.util.StringUtils;

/**
 * ChecksumFile
 *
 * @author <a href="mailto:joakim@erdfelt.com">Joakim Erdfelt</a>
 */
@Named
public class ChecksumFile {
    @Inject
    @Named("sha256")
    private Digester digestSha256;

    @Inject
    @Named("sha1")
    private Digester digestSha1;

    @Inject
    @Named("md5")
    private Digester digestMd5;

    /**
     * <p>
     * Given a checksum file, check to see if the file it represents is valid according to the checksum.
     * </p>
     * <p>Terminology:</p>
     * <p>Checksum File</p>
     * <p>The file that contains the previously calculated checksum value for the reference file.
     *     This is a text file with the extension ".sha1" or ".md5", and contains a single entry
     *     consisting of an optional reference filename, and a checksum string.
     * </p>
     * <p>Reference File</p>
     * <p>The file that is being referenced in the checksum file.</p>
     * <p>
     * NOTE: Only supports single file checksums of type MD5 or SHA1.
     * </p>
     *
     * @param checksumFile the checksum file (must end in ".sha1" or ".md5")
     * @return true if the checksum is valid for the file it represents.
     * @throws org.codehaus.plexus.digest.DigesterException if there is a digester problem during the check of the reference file.
     * @throws java.io.FileNotFoundException if the checksumFile itself or the file it refers to is not found.
     * @throws java.io.IOException if the reading of the checksumFile or the file it refers to fails.
     */
    public boolean isValidChecksum(File checksumFile) throws DigesterException, FileNotFoundException, IOException {
        if (!checksumFile.exists()) {
            throw new FileNotFoundException("Unable to find checksum file " + checksumFile.getAbsolutePath());
        }

        if (!checksumFile.isFile()) {
            throw new IOException("Unable to load checksum from non-file " + checksumFile.getAbsolutePath());
        }

        String path = checksumFile.getAbsolutePath();
        Digester digester = findDigesterByFileSuffix(path);

        File referenceFile = new File(path.substring(
                0, path.length() - digester.getFilenameExtension().length()));

        String rawChecksum = FileUtils.fileRead(checksumFile, "UTF-8");
        String expectedChecksum = DigestUtils.cleanChecksum(rawChecksum, digester, referenceFile.getName());

        String actualChecksum = digester.calc(referenceFile);

        return StringUtils.equalsIgnoreCase(expectedChecksum, actualChecksum);
    }

    private Digester findDigesterByFileSuffix(String path) throws DigesterException {
        if (path.endsWith(digestMd5.getFilenameExtension())) {
            return digestMd5;
        } else if (path.endsWith(digestSha1.getFilenameExtension())) {
            return digestSha1;
        } else if (path.endsWith(digestSha256.getFilenameExtension())) {
            return digestSha256;
        }
        // TODO: Add more digester implementations here.

        throw new DigesterException("Unable to determine digester type from filename " + path);
    }

    /**
     * Creates a checksum file of the provided referenceFile.
     *
     * @param referenceFile the file to checksum.
     * @param digester the digester to use.
     * @return the checksum File that was created.
     * @throws org.codehaus.plexus.digest.DigesterException if there was a problem calculating the checksum of the referenceFile.
     * @throws java.io.IOException if there was a problem either reading the referenceFile, or writing the checksum file.
     */
    public File createChecksum(File referenceFile, Digester digester) throws DigesterException, IOException {
        File checksumFile = new File(referenceFile.getAbsolutePath() + digester.getFilenameExtension());
        String checksum = digester.calc(referenceFile);
        FileUtils.fileWrite(checksumFile.getAbsolutePath(), "UTF-8", checksum + "  " + referenceFile.getName());
        return checksumFile;
    }
}
