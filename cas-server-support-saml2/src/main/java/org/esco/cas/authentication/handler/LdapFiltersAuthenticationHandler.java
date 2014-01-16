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
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.exception.AbstractSamlCredentialsException;
import org.esco.cas.authentication.exception.NoAccountSamlCredentialsException;
import org.esco.cas.authentication.principal.IInformingCredentials;
import org.esco.cas.authentication.principal.IResolvingCredentials;
import org.esco.cas.authentication.principal.MultiValuedAttributeCredentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.util.LdapUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * LDAP authentication handler for EmailAddressesCredentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class LdapFiltersAuthenticationHandler extends AbstractLdapAuthentificationHandler implements InitializingBean {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(LdapFiltersAuthenticationHandler.class);

	/** Ordered list of all LDAP filters to try for authenticate credentials. */
	private List<String> authenticationLdapFilters;

	@Override
	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (MultiValuedAttributeCredentials.class.isAssignableFrom(credentials.getClass()));
	}

	@Override
	protected boolean doAuthentication(final Credentials credentials) throws AuthenticationException {
		boolean auth = false;

		if (credentials != null) {
			MultiValuedAttributeCredentials mvCredentials = (MultiValuedAttributeCredentials) credentials;

			if (LdapFiltersAuthenticationHandler.LOGGER.isDebugEnabled()) {
				LdapFiltersAuthenticationHandler.LOGGER.debug(String.format(
						"Try to authenticate SAML 2.0 Response with attributes: [%s]",
						mvCredentials.getAttributeValues()));
			}

			// Default is not authenticated
			updateAuthenticationStatus(mvCredentials, AuthenticationStatusEnum.NOT_AUTHENTICATED);
			
			try {
				auth = this.authenticateAttributeValuesInternal(mvCredentials);
			} catch(AbstractSamlCredentialsException e) {
				updateAuthenticationStatus(mvCredentials, e.getStatusCode());

				LdapFiltersAuthenticationHandler.LOGGER.warn(
						String.format("Error while performing SAML via ldap authentication ! Attributes [%s] produced the following error code : [%s].",
								mvCredentials.getAttributeValues(), e.getStatusCode()));
			}

			if (auth) {
				updateAuthenticationStatus(mvCredentials, AuthenticationStatusEnum.AUTHENTICATED);
			}
			
			if (LdapFiltersAuthenticationHandler.LOGGER.isInfoEnabled()) {
				if (auth) {
					LdapFiltersAuthenticationHandler.LOGGER.info(String.format(
							"Successfully authenticated SAML 2.0 Response with attributes: [%s]",
							mvCredentials.getAttributeValues()));
				} else {
					LdapFiltersAuthenticationHandler.LOGGER.info(String.format(
							"Unable to authenticate SAML 2.0 Response with attributes: [%s]",
							mvCredentials.getAttributeValues()));
				}
			}
		}

		return auth;
	}

	protected void updateAuthenticationStatus(final Credentials creds, final AuthenticationStatusEnum authStatus) {
		if (creds != null && IInformingCredentials.class.isAssignableFrom(creds.getClass())) {
			final IInformingCredentials informingCreds = (IInformingCredentials) creds;
			informingCreds.setAuthenticationStatus(authStatus);
		}
	}
	
	/**
	 * Try to authenticate some attribute values.
	 * Try a list of LDAP filters and stop on the first successful attempt.
	 * 
	 * @param credentials the MultiValuedAttributeCredentials
	 * @return true if authenticated
	 * @throws AuthenticationException
	 */
	protected boolean authenticateAttributeValuesInternal(final MultiValuedAttributeCredentials credentials) throws AuthenticationException {
		boolean authenticated = false;

		final List<String> attrValues = credentials.getAttributeValues();

		String attrValue = null;
		final Iterator<String> valuesIterator = attrValues.iterator();				
		while (!authenticated && valuesIterator.hasNext()) {
			attrValue = valuesIterator.next();
			final Iterator<String> filterIterator = this.authenticationLdapFilters.iterator();
			while (!authenticated && filterIterator.hasNext()) {
				final String currentFilter = filterIterator.next();
				final String filledFilter = LdapUtils.getFilterWithValues(currentFilter, attrValue);
				final String principalId = this.searchAccount(filledFilter);
				
				authenticated = StringUtils.hasText(principalId);
				if (authenticated && IResolvingCredentials.class.isAssignableFrom(credentials.getClass())) {
					IResolvingCredentials resolvingCreds = (IResolvingCredentials) credentials;
					resolvingCreds.setResolvedPrincipalId(principalId);
				}
			}
		}

		if (!authenticated) {
			// we cannoud found an account linked to the email address
			throw new NoAccountSamlCredentialsException();
		}

		return authenticated;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		Assert.notEmpty(this.authenticationLdapFilters, "No authentication filter list provided !");
		for (String filter : this.authenticationLdapFilters) {
			Assert.isTrue(filter.contains("%u") || filter.contains("%U"), "filter must contain %u or %U");
		}
	}

	/**
	 * Array representation of ordered list of all LDAP filters to try for authenticate an email Address.
	 * 
	 * @param authenticationLdapFilters the ordered filters
	 */
	public void setAuthenticationLdapFiltersArray(final String[] authenticationLdapFilters) {
		Assert.noNullElements(authenticationLdapFilters, "Array is null !");

		List<String> list = new ArrayList<String>();
		CollectionUtils.mergeArrayIntoCollection(authenticationLdapFilters, list);

		this.authenticationLdapFilters = list;
	}

	/**
	 * Ordered list of all LDAP filters to try for authenticate an email Address.
	 * 
	 * @return the ordered filters
	 */
	public List<String> getAuthenticationLdapFilters() {
		return this.authenticationLdapFilters;
	}

	/**
	 * Ordered list of all LDAP filters to try for authenticate an email Address.
	 * 
	 * @param authenticationLdapFilters the ordered filters
	 */
	public void setAuthenticationLdapFilters(final List<String> authenticationLdapFilters) {
		this.authenticationLdapFilters = authenticationLdapFilters;
	}

}
