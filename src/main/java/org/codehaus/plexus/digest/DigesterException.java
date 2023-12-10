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
 * <p>DigesterException class.</p>
 *
 * @author Edwin Punzalan
 */
public class DigesterException
    extends Exception
{
    /**
     * <p>Constructor for DigesterException.</p>
     */
    public DigesterException()
    {
        super();
    }

    /**
     * <p>Constructor for DigesterException.</p>
     *
     * @param message a {@link java.lang.String} object.
     */
    public DigesterException( String message )
    {
        super( message );
    }

    /**
     * <p>Constructor for DigesterException.</p>
     *
     * @param message a {@link java.lang.String} object.
     * @param cause a {@link java.lang.Throwable} object.
     */
    public DigesterException( String message, Throwable cause )
    {
        super( message, cause );
    }

    /**
     * <p>Constructor for DigesterException.</p>
     *
     * @param cause a {@link java.lang.Throwable} object.
     */
    public DigesterException( Throwable cause )
    {
        super( cause );
    }
}
