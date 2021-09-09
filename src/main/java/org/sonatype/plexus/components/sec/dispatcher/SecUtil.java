/*
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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.sonatype.plexus.components.sec.dispatcher.model.Config;
import org.sonatype.plexus.components.sec.dispatcher.model.ConfigProperty;
import org.sonatype.plexus.components.sec.dispatcher.model.SettingsSecurity;
import org.sonatype.plexus.components.sec.dispatcher.model.io.xpp3.SecurityConfigurationXpp3Reader;

/**
 *
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public class SecUtil
{
    
    public static final String PROTOCOL_DELIM = "://";
    public static final int    PROTOCOL_DELIM_LEN = PROTOCOL_DELIM.length();
    public static final String [] URL_PROTOCOLS = new String [] {"http","https","dav","file","davs","webdav","webdavs","dav+http","dav+https"};

    public static SettingsSecurity read( String location, boolean cycle )
    throws SecDispatcherException
    {
        if( location == null )
            throw new SecDispatcherException("location to read from is null");
        
        InputStream in = null;
        
        try
        {
            in = toStream( location );
            
            SettingsSecurity sec = new SecurityConfigurationXpp3Reader().read( in );
            
            in.close();
            
            if( cycle && sec.getRelocation() != null )
                return read( sec.getRelocation(), true );
            
            return sec;
        }
        catch ( Exception e )
        {
            throw new SecDispatcherException(e);
        }
        finally
        {
            if( in != null )
                try { in.close(); } catch( Exception e ) {}
        }
    }
    //---------------------------------------------------------------------------------------------------------------
    private static InputStream toStream( String resource )
    throws IOException
    {
      if( resource == null )
        return null;
      
      int ind = resource.indexOf( PROTOCOL_DELIM );
      
      if( ind > 1 )
      {
          String protocol = resource.substring( 0, ind );
          resource = resource.substring( ind + PROTOCOL_DELIM_LEN );

          for ( String p : URL_PROTOCOLS ) {
              if ( protocol.regionMatches( true, 0, p, 0, p.length() ) ) {
                  return new URL( p + PROTOCOL_DELIM + resource ).openStream();
              }
          }
      }

      return new FileInputStream( resource );
    }
    //---------------------------------------------------------------------------------------------------------------
    public static Map<String, String> getConfig( SettingsSecurity sec, String name )
    {
        if( name == null )
            return null;
        
        List<Config> cl = sec.getConfigurations();
        
        if( cl == null || cl.isEmpty() )
            return null;

        for ( Config cf : cl ) {
            if ( !name.equals( cf.getName() ) ) {
                continue;
            }

            List<ConfigProperty> pl = cf.getProperties();

            if ( pl == null || pl.isEmpty() ) {
                return null;
            }

            Map<String, String> res = new HashMap<>( pl.size() );

            for ( ConfigProperty p : pl ) {
                res.put( p.getName(), p.getValue() );
            }

            return res;
        }
        
        return null;
    }
}
