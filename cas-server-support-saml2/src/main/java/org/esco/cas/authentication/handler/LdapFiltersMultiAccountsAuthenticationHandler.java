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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.exception.AbstractCredentialsException;
import org.esco.cas.authentication.exception.EmptyCredentialsException;
import org.esco.cas.authentication.exception.NoAccountCredentialsException;
import org.esco.cas.authentication.handler.support.IMultiAccountFilterRetrieverHandler;
import org.esco.cas.authentication.principal.IMultiAccountCredential;
import org.esco.cas.authentication.principal.IResolvingCredentials;
import org.esco.cas.authentication.principal.Saml20MultiAccountCredentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.util.LdapUtils;
import org.opensaml.xml.util.Pair;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

/**
 * LDAP authentication handler managing multiples LDAP filters and multiple different attribute values.
 *
 * @author GIP RECIA 2019 - Julien Gribonvald.
 *
 */
public class LdapFiltersMultiAccountsAuthenticationHandler implements IMultiAccountFilterRetrieverHandler, InitializingBean {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(LdapFiltersMultiAccountsAuthenticationHandler.class);

	private String name;

	/** Ordered list of all LDAP filters to try for authenticate credentials. */
	private String authenticationAllValuesFilter;
	private String authenticationMergedAccountFilter;

	private LdapTemplate ldapTemplate;
	private String searchBase;
	private SearchControls searchControls;
	private String principalAttributeName;
	private boolean ignorePartialResultException = false;


	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (IMultiAccountCredential.class.isAssignableFrom(credentials.getClass()));
	}

	public Pair<List<String>, List<Map<String, List<String>>>> retrieveAccounts(final Credentials credentials){
		if (credentials != null) {
			IMultiAccountCredential mvCredentials = (IMultiAccountCredential) credentials;

			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(String.format(
						"Try to resolve users from SAML 2.0 Response with attributes: [%s] and with opaqueId [%s]",
						mvCredentials.getFederatedIds(), mvCredentials.getOpaqueId()));
			}

			if (!CollectionUtils.isEmpty(mvCredentials.getFederatedIds()) || StringUtils.hasText(mvCredentials.getOpaqueId())) {
				// construction du filtre avec l'ensemble des attributs du crédential transmis.
				StringBuilder mainFilter = new StringBuilder("(|");
				for (String cred : mvCredentials.getFederatedIds()) {
					if (StringUtils.hasText(cred)) {
						mainFilter.append(LdapUtils.getFilterWithValues(this.authenticationAllValuesFilter, cred));
					}
				}
				final String mergedCred = mvCredentials.getOpaqueId();
				if (StringUtils.hasText(mergedCred)) {
					mainFilter.append(LdapUtils.getFilterWithValues(this.authenticationMergedAccountFilter, mergedCred));
				}

				mainFilter.append(")");

				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(String.format(
							"Try to authenticate SAML 2.0 Response with LDAP filter: [%s]", mainFilter));
				}

				// Recherche du/des comptes si plusieurs retrouvés.
				final List<Map<String, List<String>>> accounts = this.searchInLdap(mainFilter.toString());
				final List<String> principals = this.getPrincipalIds(accounts);
				return new Pair<List<String>, List<Map<String, List<String>>>>(principals, accounts);
			}
		}
		return null;
	}

	protected final List<String> getPrincipalIds(final List<Map<String, List<String>>> accounts) {
		if (accounts.isEmpty()) {
			// No account bind to the LDAP query
			return null;
		}

		List<String> ids = new ArrayList<String>();

		for (Map<String, List<String>> account: accounts) {
			ids.addAll(account.get(this.getPrincipalAttributeName()));
		}


		return ids;
	}

	/**
	 * Serach in Ldap for attributes.
	 *
	 * @param filter the search filter
	 * @return the list of attributes
	 */
	protected final List<Map<String, List<String>>> searchInLdap(final String filter) {
		final List<Map<String, List<String>>> result = new ArrayList<Map<String, List<String>>>();

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(String.format("Starting LDAP search for filter [%s] ...", filter));
		}
		this.getLdapTemplate().search(this.getSearchBase(), filter, this.getSearchControls(), new AttributesMapper() {
			@Override
			public Object mapFromAttributes(final Attributes attributes) throws NamingException {
				if (attributes != null) {
					Map<String, List<String>> account = new HashMap<String, List<String>>();
					for (final NamingEnumeration<? extends Attribute> attributesEnum = attributes.getAll(); attributesEnum.hasMore(); ) {
						final Attribute attribute = attributesEnum.next();
						if (attribute.size() > 0) {
							final String attrName = attribute.getID();
							final List<String> values = this.getAttributeValues(attribute);
							account.put(attrName, values);
						}
					}
					result.add(account);
				}
				return null;
			}
			private List<String> getAttributeValues(Attribute attributeValue){
				List<String> values = new ArrayList<String>();
				try {
					for (final NamingEnumeration<?> attributesEnum = attributeValue.getAll(); attributesEnum.hasMore(); ) {
						final Object obj = attributesEnum.nextElement();
						if (obj instanceof String) {
							final String value = (String) obj;
							values.add(value);
						}
					}
				} catch (NamingException e){
					LOGGER.error("No enumeration values for " + attributeValue.toString());
				}

				return values;
			}
		});
		return result;
	}



		@Override
	public void afterPropertiesSet() throws Exception {
		Assert.hasText(this.name, "No bean name provided !");
		Assert.hasText(this.authenticationAllValuesFilter, "No authentication filter on all account values provided !");
		Assert.hasText(this.authenticationMergedAccountFilter, "No authentication filter on merged account provided !");

		Assert.isTrue(authenticationAllValuesFilter.contains("%u") || authenticationAllValuesFilter.contains("%U"), "authenticationAllValuesFilter filter must contain %u or %U");
		Assert.isTrue(authenticationMergedAccountFilter.contains("%u") || authenticationMergedAccountFilter.contains("%U"), "authenticationMergedAccountFilter filter must contain %u or %U");

		Assert.notNull(this.ldapTemplate, "No LdapTemplate provided !");
		Assert.hasText(this.searchBase, "No searchBase provided !");
		Assert.notNull(this.searchControls, "No searchControls provided !");
		Assert.notNull(this.principalAttributeName, "No LDAP principal attribute name configured !");
		this.ldapTemplate.setIgnorePartialResultException(this.ignorePartialResultException);
	}

	public String getName() {
		return name;
	}

	public void setName(final String name) {
		this.name = name;
	}

	public String getAuthenticationAllValuesFilter() {
		return authenticationAllValuesFilter;
	}

	public void setAuthenticationAllValuesFilter(final String authenticationAllValuesFilter) {
		this.authenticationAllValuesFilter = authenticationAllValuesFilter;
	}

	public String getAuthenticationMergedAccountFilter() {
		return authenticationMergedAccountFilter;
	}

	public void setAuthenticationMergedAccountFilter(final String authenticationMergedAccountFilter) {
		this.authenticationMergedAccountFilter = authenticationMergedAccountFilter;
	}

	public LdapTemplate getLdapTemplate() {
		return ldapTemplate;
	}

	public void setLdapTemplate(final LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	public String getSearchBase() {
		return searchBase;
	}

	public void setSearchBase(final String searchBase) {
		this.searchBase = searchBase;
	}

	public SearchControls getSearchControls() {
		return searchControls;
	}

	public void setSearchControls(final SearchControls searchControls) {
		this.searchControls = searchControls;
	}

	public String getPrincipalAttributeName() {
		return principalAttributeName;
	}

	public void setPrincipalAttributeName(final String principalAttributeName) {
		this.principalAttributeName = principalAttributeName;
	}

	public boolean isIgnorePartialResultException() {
		return ignorePartialResultException;
	}

	public void setIgnorePartialResultException(final boolean ignorePartialResultException) {
		this.ignorePartialResultException = ignorePartialResultException;
	}
}
