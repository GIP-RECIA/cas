/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 
 */
package org.esco.cas.authentication;

import java.util.ArrayList;
import java.util.List;

import org.esco.cas.authentication.exception.EmptySamlCredentialsException;
import org.esco.cas.authentication.exception.MultiValuedSamlCredentialsException;
import org.esco.cas.authentication.handler.SamlAttributesAuthenticationHandler;
import org.esco.cas.authentication.principal.MultiValuedAttributeCredentials;
import org.esco.cas.authentication.principal.Saml20Credentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Integration test for SamlAttributeAuthenticationHandler.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:authenticationHandlerContext.xml")
public class SamlAttributeAuthenticationHandlerTest implements InitializingBean {

	private static final String ATTR_FRIENDLY_NAME = "ctemail";
	
	private static final String ATTR_VALID_VALUE = "correctValue";
	private static final String ATTR_BAD_VALUE_1 = "badValue1";
	private static final String ATTR_BAD_VALUE_2 = "badValue2";
	
	private static final List<String> ATTR_VALID_VALUES = new ArrayList<String>();
	static {
		ATTR_VALID_VALUES.add(ATTR_VALID_VALUE);
	}
	
	private static final List<String> ATTR_VALID_MV_VALUES = new ArrayList<String>();
	static {
		ATTR_VALID_MV_VALUES.add(ATTR_BAD_VALUE_1);
		ATTR_VALID_MV_VALUES.add(ATTR_VALID_VALUE);
		ATTR_VALID_MV_VALUES.add(ATTR_BAD_VALUE_2);
	}
	
	private static final List<String> ATTR_BAD_VALUES = new ArrayList<String>();
	static {
		ATTR_BAD_VALUES.add(ATTR_BAD_VALUE_1);
	}
	
	private static final List<String> ATTR_MV_VALUES = new ArrayList<String>();
	static {
		ATTR_MV_VALUES.add(ATTR_VALID_VALUE);
		ATTR_MV_VALUES.add(ATTR_VALID_VALUE);
	}
	
	@Autowired
	@Qualifier("handlerSupportingMonoValue")
	private SamlAttributesAuthenticationHandler monoValueHandler;
	
	@Autowired
	@Qualifier("handlerSupportingMultiValue")
	private SamlAttributesAuthenticationHandler multiValueHandler;

	@Test
	public void testValidSamlCreds() throws Exception {
		Saml20Credentials creds = new Saml20Credentials();
		creds.setAttributeFriendlyName(ATTR_FRIENDLY_NAME);
		creds.setAttributeValues(ATTR_VALID_VALUES);
		
		Assert.assertTrue("Credentials should be authenticated !", performAuth(creds, monoValueHandler));
	}

	@Test
	public void testBadSamlCreds() throws Exception {
		Saml20Credentials creds = new Saml20Credentials();
		creds.setAttributeFriendlyName(ATTR_FRIENDLY_NAME);
		creds.setAttributeValues(ATTR_BAD_VALUES);
		
		Assert.assertFalse("Credentials should not be authenticated !", performAuth(creds, monoValueHandler));
	}
	
	@Test(expected=MultiValuedSamlCredentialsException.class)
	public void testBadMultiValuedSamlCreds() throws Exception {
		Saml20Credentials creds = new Saml20Credentials();
		creds.setAttributeFriendlyName(ATTR_FRIENDLY_NAME);
		creds.setAttributeValues(ATTR_MV_VALUES);
		
		performAuth(creds, monoValueHandler);
	}

	@Test
	public void testNonSamlCreds() throws Exception {
		MultiValuedAttributeCredentials creds = new MultiValuedAttributeCredentials();
		creds.setAttributeValues(ATTR_VALID_VALUES);
		
		Assert.assertFalse("Credentials should not be authenticated !", performAuth(creds, monoValueHandler));
	}
	
	@Test(expected=EmptySamlCredentialsException.class)
	public void testEmpty1SamlCreds() throws Exception {
		Saml20Credentials creds = new Saml20Credentials();
		creds.setAttributeValues(null);
		
		performAuth(creds, monoValueHandler);
	}
	
	@Test(expected=EmptySamlCredentialsException.class)
	public void testEmpty2SamlCreds() throws Exception {
		Saml20Credentials creds = new Saml20Credentials();
		creds.setAttributeValues(new ArrayList<String>());
		
		performAuth(creds, monoValueHandler);
	}
	
	@Test
	public void testValidMultiValuedSamlCreds() throws Exception {
		Saml20Credentials creds = new Saml20Credentials();
		creds.setAttributeFriendlyName(ATTR_FRIENDLY_NAME);
		creds.setAttributeValues(ATTR_MV_VALUES);
		
		Assert.assertTrue("Credentials should be authenticated !", performAuth(creds, multiValueHandler));
	}
	
	protected boolean performAuth(Credentials creds, SamlAttributesAuthenticationHandler handler) throws AuthenticationException {
		boolean authenticated = false;
		
		if (handler.supports(creds)) {
			authenticated = handler.authenticate(creds);
		}
		
		return authenticated;
	}
	
	@Override
	public void afterPropertiesSet() throws Exception {
		this.monoValueHandler.setBackingHandler(new SpyingHauthHandler());
		this.multiValueHandler.setBackingHandler(new SpyingHauthHandler());
	}
	
	public class SpyingHauthHandler implements AuthenticationHandler {

		@Override
		public boolean authenticate(Credentials credentials) throws AuthenticationException {
			MultiValuedAttributeCredentials mvCreds = (MultiValuedAttributeCredentials) credentials;
			
			boolean authenticated = mvCreds.getAttributeValues().contains(ATTR_VALID_VALUE);

			return authenticated;
		}

		@Override
		public boolean supports(Credentials credentials) {
			return credentials != null && credentials instanceof MultiValuedAttributeCredentials;
			
		}
		
	}

}
