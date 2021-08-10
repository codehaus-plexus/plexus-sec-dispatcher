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

import java.io.FileWriter;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.sonatype.plexus.components.cipher.DefaultPlexusCipher;
import org.sonatype.plexus.components.sec.dispatcher.model.Config;
import org.sonatype.plexus.components.sec.dispatcher.model.ConfigProperty;
import org.sonatype.plexus.components.sec.dispatcher.model.SettingsSecurity;
import org.sonatype.plexus.components.sec.dispatcher.model.io.xpp3.SecurityConfigurationXpp3Writer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 *
 *
 * @author Oleg Gusakov
 * @version $Id$
 *
 */
public class SecUtilTest
{
    String _pw = "{1wQaa6S/o8MH7FnaTNL53XmhT5O0SEGXQi3gC49o6OY=}";
    
    String _clear = "testtest";
    
    String _encrypted = "{BteqUEnqHecHM7MZfnj9FwLcYbdInWxou1C929Txa0A=}";
    
    String _confName = "cname";
    
    String _propName = "pname";
    
    String _propVal = "pval";

    @Before
    public void prepare()
    throws Exception
    {
        System.setProperty( DefaultSecDispatcher.SYSTEM_PROPERTY_SEC_LOCATION, "./target/sec.xml" );
        
//DefaultPlexusCipher c = new DefaultPlexusCipher();
//System.out.println(_clear+" -> "+c.encrypt( _clear, "testtest" ));

        
        SettingsSecurity sec = new SettingsSecurity();
        
        sec.setRelocation( "./target/sec1.xml" );
        new SecurityConfigurationXpp3Writer().write( new FileWriter("./target/sec.xml"), sec );
        
        sec.setRelocation( null );
        sec.setMaster( _pw );
        
        ConfigProperty cp = new ConfigProperty();
        cp.setName( _propName );
        cp.setValue( _propVal );
        
        Config conf = new Config();
        conf.setName( _confName );
        conf.addProperty( cp );
        
        sec.addConfiguration( conf );
        
        new SecurityConfigurationXpp3Writer().write( new FileWriter("./target/sec1.xml"), sec );
    }

    @Test
    public void testRead()
    throws Exception
    {
        SettingsSecurity sec = SecUtil.read( "./target/sec.xml", true );

        assertNotNull( sec );

        assertEquals( _pw, sec.getMaster() );
        
        Map conf = SecUtil.getConfig( sec, _confName );
        
        assertNotNull( conf );
        
        assertNotNull( conf.get( _propName ) );
        
        assertEquals( _propVal, conf.get( _propName ) );
    }

    @Test
    public void testDecrypt()
    throws Exception
    {
        DefaultSecDispatcher sd = new DefaultSecDispatcher(new DefaultPlexusCipher());

        String pass = sd.decrypt( _encrypted );
        
        assertNotNull( pass );
        
        assertEquals( _clear, pass );
    }
}
