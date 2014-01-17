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
package org.esco.cas.authentication.handler;

import java.util.ArrayList;
import java.util.List;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;

import org.esco.cas.authentication.principal.IInformingCredentials;
import org.esco.cas.authentication.principal.MultiValuedAttributeCredentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Integration test for LdapFiltersAuthenticationHandler.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:authenticationHandlerContext.xml")
public class LdapFiltersAuthenticationHandlerTest implements InitializingBean {

	public static final String LDAP_SEARCH_BASE = "fakedBase";
	public static final String LDAP_PRINCIPAL_ATTR_NAME = "uid";
	
	private static final String LDAP_PRINCIPAL_ATTR_VALUE = "correctUidFromLdap";
	
	private static final String LDAP_FILTER_1 = "(foo = %u)";
	private static final String LDAP_FILTER_2 = "(bar = %u)";
	private static final String LDAP_FILTER_3 = "(baz = %u)";
	public static final List<String> LDAP_SEARCH_FILTERS = new ArrayList<String>();
	static {
		LDAP_SEARCH_FILTERS.add(LDAP_FILTER_1);
		LDAP_SEARCH_FILTERS.add(LDAP_FILTER_2);
		LDAP_SEARCH_FILTERS.add(LDAP_FILTER_3);
	}
	
	private static final String ATTR_VALID_VALUE = "correctValue";
	private static final String ATTR_BAD_MV_VALUE = "multiValued";
	private static final String ATTR_BAD_MAM_VALUE = "multipleAccountsMatching";
	private static final String ATTR_BAD_VALUE_1 = "badValue1";
	private static final String ATTR_BAD_VALUE_2 = "badValue2";

	/** LDAP_CORRECT_FILTER allow mocked LDAP to return THE valid mono valued answer. */
	private static final String LDAP_CORRECT_FILTER = "(bar = " + ATTR_VALID_VALUE + ")";
	/** LDAP_MV_FILTER allow mocked LDAP to return a valid multi valued answer. */
	private static final String LDAP_MV_FILTER = "(baz = " + ATTR_BAD_MV_VALUE + ")";
	/** LDAP_MAM_FILTER allow mocked LDAP to return a multiples account with valid answer. */
	private static final String LDAP_MAM_FILTER = "(baz = " + ATTR_BAD_MAM_VALUE + ")";
	
	
	/** ATTR_VALID_VALUES allow mocked LDAP to return a valid mono valued answer. */
	private static final List<String> ATTR_VALID_VALUES = new ArrayList<String>();
	static {
		ATTR_VALID_VALUES.add(ATTR_BAD_VALUE_1);
		ATTR_VALID_VALUES.add(ATTR_VALID_VALUE);
		ATTR_VALID_VALUES.add(ATTR_BAD_VALUE_2);
	}
	
	/** ATTR_BAD_VALUES doesn't allow mocked LDAP to return an answer. */
	private static final List<String> ATTR_BAD_VALUES = new ArrayList<String>();
	static {
		ATTR_BAD_VALUES.add(ATTR_BAD_VALUE_1);
		ATTR_BAD_VALUES.add(ATTR_BAD_VALUE_2);
	}
	
	/** ATTR_BAD_MV_VALUES doesn't allow mocked LDAP to return an answer. */
	private static final List<String> ATTR_VALID_MV_VALUES = new ArrayList<String>();
	static {
		ATTR_VALID_MV_VALUES.add(ATTR_BAD_VALUE_1);
		ATTR_VALID_MV_VALUES.add(ATTR_BAD_VALUE_2);
		ATTR_VALID_MV_VALUES.add(ATTR_BAD_MV_VALUE);
	}
	
	/** ATTR_BAD_MV_VALUES doesn't allow mocked LDAP to return an answer. */
	private static final List<String> ATTR_BAD_MAM_VALUES = new ArrayList<String>();
	static {
		ATTR_BAD_MAM_VALUES.add(ATTR_BAD_VALUE_1);
		ATTR_BAD_MAM_VALUES.add(ATTR_BAD_VALUE_2);
		ATTR_BAD_MAM_VALUES.add(ATTR_BAD_MAM_VALUE);
	}

	@Autowired
	@Mock
	private LdapFiltersAuthenticationHandler handler;

	@Test
	public void testValidCreds() throws Exception {
		MultiValuedAttributeCredentials creds = new MultiValuedAttributeCredentials();
		creds.setAttributeValues(ATTR_VALID_VALUES);
		
		Assert.assertTrue("Credentials should be authenticated !", performAuth(creds, handler));
		this.assertAuthenticationStatus(creds, AuthenticationStatusEnum.AUTHENTICATED);
	}

	@Test
	public void testBadCreds() throws Exception {
		MultiValuedAttributeCredentials creds = new MultiValuedAttributeCredentials();
		creds.setAttributeValues(ATTR_BAD_VALUES);
		
		Assert.assertFalse("Credentials should not be authenticated !", performAuth(creds, handler));
		this.assertAuthenticationStatus(creds, AuthenticationStatusEnum.NO_ACCOUNT);
	}

	@Test
	public void testEmptyCreds() throws Exception {
		MultiValuedAttributeCredentials creds = new MultiValuedAttributeCredentials();
		creds.setAttributeValues(new ArrayList<String>());
		
		Assert.assertFalse("Credentials should not be authenticated !", performAuth(creds, handler));
		this.assertAuthenticationStatus(creds, AuthenticationStatusEnum.EMPTY_CREDENTIAL);
	}

	@Test
	public void testNullCreds() throws Exception {
		Assert.assertFalse("Credentials should not be authenticated !", performAuth(null, handler));
	}
	
	@Test
	public void testLdapMultiValuedAnswer() throws Exception {
		MultiValuedAttributeCredentials creds = new MultiValuedAttributeCredentials();
		creds.setAttributeValues(ATTR_VALID_MV_VALUES);
		
		Assert.assertTrue("Credentials should be authenticated !", performAuth(creds, handler));
		this.assertAuthenticationStatus(creds, AuthenticationStatusEnum.AUTHENTICATED);
	}
	
	@Test
	public void testLdapMultipleAccountsMatching() throws Exception {
		MultiValuedAttributeCredentials creds = new MultiValuedAttributeCredentials();
		creds.setAttributeValues(ATTR_BAD_MAM_VALUES);
		
		Assert.assertFalse("Credentials should not be authenticated !", performAuth(creds, handler));
		this.assertAuthenticationStatus(creds, AuthenticationStatusEnum.MULTIPLE_ACCOUNTS);
	}

	protected boolean performAuth(Credentials creds, AuthenticationHandler handler) throws AuthenticationException {
		boolean authenticated = false;
		
		if (handler.supports(creds)) {
			authenticated = handler.authenticate(creds);
		}
		
		return authenticated;
	}
	
	protected void assertAuthenticationStatus(Credentials creds, AuthenticationStatusEnum status) {
		if (IInformingCredentials.class.isAssignableFrom(creds.getClass())) {
			IInformingCredentials informingCreds = (IInformingCredentials) creds;
			Assert.assertEquals("Bad value for InformingCredentials authentication status !", 
					status, informingCreds.getAuthenticationStatus());
		}
	}
	
	@Override
	public void afterPropertiesSet() throws Exception {
		// Mock LdapTemplate in handler to answer when the authentication is correct.
		LdapTemplate mockedLdapTemplate = handler.getLdapTemplate();
		Mockito.when(mockedLdapTemplate.search(Mockito.anyString(), Mockito.anyString(), 
				Mockito.any(SearchControls.class), Mockito.any(AttributesMapper.class))).then(new Answer<Void>() {

					@Override
					public Void answer(InvocationOnMock invocation) throws Throwable {
						String base = (String) invocation.getArguments()[0];
						String filter = (String) invocation.getArguments()[1];
						@SuppressWarnings("unused")
						SearchControls searchControls = (SearchControls) invocation.getArguments()[2];
						AttributesMapper attrMapper = (AttributesMapper) invocation.getArguments()[3];
						
						if (LDAP_SEARCH_BASE.equals(base) && LDAP_CORRECT_FILTER.equals(filter)) {
							attrMapper.mapFromAttributes(LdapFiltersAuthenticationHandlerTest.this.ldapAuthenticatedAttributes());
						}
						
						if (LDAP_SEARCH_BASE.equals(base) && LDAP_MV_FILTER.equals(filter)) {
							attrMapper.mapFromAttributes(LdapFiltersAuthenticationHandlerTest.this.ldapMuliValuedAttributes());
						}
						
						if (LDAP_SEARCH_BASE.equals(base) && LDAP_MAM_FILTER.equals(filter)) {
							attrMapper.mapFromAttributes(LdapFiltersAuthenticationHandlerTest.this.ldapMuliValuedAttributes());
							attrMapper.mapFromAttributes(LdapFiltersAuthenticationHandlerTest.this.ldapMuliValuedAttributes());
						}

						return null;
					}

				});
	}

	protected Attributes ldapAuthenticatedAttributes() {
		BasicAttributes uidAttr = new BasicAttributes(LDAP_PRINCIPAL_ATTR_NAME, LDAP_PRINCIPAL_ATTR_VALUE);
		
		return uidAttr;
	}

	protected Attributes ldapMuliValuedAttributes() {
		BasicAttributes uidAttr = new BasicAttributes(LDAP_PRINCIPAL_ATTR_NAME, LDAP_PRINCIPAL_ATTR_VALUE);
		// Add second value
		uidAttr.put(LDAP_PRINCIPAL_ATTR_NAME, LDAP_PRINCIPAL_ATTR_VALUE);
		return uidAttr;
	}

}
