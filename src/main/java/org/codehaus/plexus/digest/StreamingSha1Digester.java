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

/**
 * An SHA-1 implementation of the streaming digester.
 *
 * @author <a href="mailto:brett@apache.org">Brett Porter</a>
 * @plexus.component role="org.codehaus.plexus.digest.StreamingDigester" role-hint="sha1"
 */
public class StreamingSha1Digester
    extends AbstractStreamingDigester
{
    /**
     * <p>Constructor for StreamingSha1Digester.</p>
     */
    public StreamingSha1Digester()
    {
        super( "SHA-1" );
    }
}
