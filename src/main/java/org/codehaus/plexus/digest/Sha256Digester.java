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

import javax.inject.Named;

/**
 * Digester that does SHA256 Message Digesting Only.
 *
 */
@Named("sha256")
public class Sha256Digester extends AbstractDigester {
    public String getFilenameExtension() {
        return ".sha256";
    }

    public Sha256Digester() {
        super(new StreamingSha256Digester());
    }
}
