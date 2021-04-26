/**
 * Copyright (c) 2008 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
 
package org.sonatype.plexus.components.sec.dispatcher;

/**
 *
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public class PasswordDecrypterException
    extends Exception
{

    /**
     * 
     */
    public PasswordDecrypterException()
    {
        // TODO Auto-generated constructor stub
    }

    /**
     * @param message
     */
    public PasswordDecrypterException( String message )
    {
        super( message );
        // TODO Auto-generated constructor stub
    }

    /**
     * @param cause
     */
    public PasswordDecrypterException( Throwable cause )
    {
        super( cause );
        // TODO Auto-generated constructor stub
    }

    /**
     * @param message
     * @param cause
     */
    public PasswordDecrypterException( String message, Throwable cause )
    {
        super( message, cause );
        // TODO Auto-generated constructor stub
    }

}
