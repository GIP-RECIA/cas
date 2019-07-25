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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.exception.AbstractCredentialsException;
import org.esco.cas.authentication.exception.EmptyCredentialsException;
import org.esco.cas.authentication.exception.MultiAccountsCredentialsException;
import org.esco.cas.authentication.exception.NoAccountCredentialsException;
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

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

/**
 * LDAP authentication handler managing multiples LDAP filters and multiple different attribute values.
 *
 * @author GIP RECIA 2019 - Julien Gribonvald.
 *
 */
public class LdapFiltersMultiAccountsAuthenticationHandler extends AbstractLdapAuthentificationHandler implements InitializingBean {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(LdapFiltersMultiAccountsAuthenticationHandler.class);

	/** Ordered list of all LDAP filters to try for authenticate credentials. */
	private String authenticationAllValuesFilter;
	private String authenticationMergedAccountFilter;

	private String mergedCredentialPattern;
	private String accountsCredentialPattern;

	private int groupPatternOfMergedCredentialToExtract;
	private int groupPatternOfAccountsCredentialToExtract;

	private Pattern patternOfMergedCredential;
	private Pattern patternOfAccountsCredential;

	@Override
	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (MultiValuedAttributeCredentials.class.isAssignableFrom(credentials.getClass()));
	}

	@Override
	protected boolean doAuthentication(final Credentials credentials) throws AuthenticationException {
		boolean auth = false;

		if (credentials != null) {
			MultiValuedAttributeCredentials mvCredentials = (MultiValuedAttributeCredentials) credentials;

			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(String.format(
						"Try to authenticate SAML 2.0 Response with attributes: [%s]",
						mvCredentials.getAttributeValues()));
			}

			// Default is not authenticated
			this.updateAuthenticationStatus(mvCredentials, AuthenticationStatusEnum.NOT_AUTHENTICATED);

			try {
				mvCredentials = this.authenticateAttributeValuesInternal(mvCredentials);
			} catch(AbstractCredentialsException e) {
				this.updateAuthenticationStatus(mvCredentials, e.getStatusCode());
				throw e;
			}

			auth = AuthenticationStatusEnum.AUTHENTICATED.equals(mvCredentials.getAuthenticationStatus()) || AuthenticationStatusEnum.MULTIPLE_ACCOUNTS.equals(mvCredentials.getAuthenticationStatus());
			if (auth) {
				LOGGER.info(String.format(
						"[%s] Successfully authenticated SAML 2.0 Response with attributes: [%s]",
						this.getName(), mvCredentials.getAttributeValues()));

				if (AuthenticationStatusEnum.MULTIPLE_ACCOUNTS.equals(mvCredentials.getAuthenticationStatus())) {
					LOGGER.warn(String.format(
						"[%s] Multi Accounts Detected with attributes: [%s]",
						this.getName(), mvCredentials.getAttributeValues()));

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
	protected MultiValuedAttributeCredentials authenticateAttributeValuesInternal(final MultiValuedAttributeCredentials credentials) throws AuthenticationException {
		boolean authenticated = false;

		final List<String> attrValues = credentials.getAttributeValues();

		if (!CollectionUtils.isEmpty(attrValues)) {
			// construction du filtre avec l'ensemble des attributs du crédential transmis.
			StringBuilder mainFilter = new StringBuilder("(|");
			boolean haveCreds = false;
			for (String cred: this.extractCredentialsOfNotMergedAccount(credentials)) {
				if (StringUtils.hasText(cred)) {
					mainFilter.append(LdapUtils.getFilterWithValues(this.authenticationAllValuesFilter, cred));
					haveCreds = true;
				}
			}
			final String mergedCred = extractCredentialOfMergedAccount(credentials);
			if (StringUtils.hasText(mergedCred)) {
				mainFilter.append(LdapUtils.getFilterWithValues(this.authenticationMergedAccountFilter, mergedCred));
				haveCreds = true;
			}
			if (!haveCreds) {
				// No usable credentials was found
				this.updateAuthenticationStatus(credentials, AuthenticationStatusEnum.EMPTY_CREDENTIAL);
				throw new EmptyCredentialsException();
			}
			mainFilter.append(")");

			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(String.format(
						"Try to authenticate SAML 2.0 Response with LDAP filter: [%s]", mainFilter));
			}

			// Recherche du/des comptes si plusieurs retrouvés.
			final List<String> principalIds = this.searchAccounts(mainFilter.toString());

			// cas d'un seul compte.
			final String firstPrincipal = principalIds != null && !principalIds.isEmpty() ? principalIds.get(0) : null;
			authenticated = principalIds != null && principalIds.size() >= 1 && StringUtils.hasText(firstPrincipal) ;
			if (authenticated) {
				credentials.setAuthenticatedValue(firstPrincipal);
				this.updateAuthenticationStatus(credentials, AuthenticationStatusEnum.AUTHENTICATED);
				if (IResolvingCredentials.class.isAssignableFrom(credentials.getClass())) {
					IResolvingCredentials resolvingCreds = (IResolvingCredentials) credentials;
					resolvingCreds.setResolvedPrincipalId(firstPrincipal);

					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug(String.format(
								"Resolving credentials: [%s]", resolvingCreds.toString()));
					}
				}
			}
			if (principalIds.size() > 1) {
				// gestion du cas multi-account
				this.updateAuthenticationStatus(credentials, AuthenticationStatusEnum.MULTIPLE_ACCOUNTS);
				credentials.setResolvedPrincipalIds(principalIds);
			}

		} else {
			// Empty credentials
			this.updateAuthenticationStatus(credentials, AuthenticationStatusEnum.EMPTY_CREDENTIAL);
			throw new EmptyCredentialsException();
		}

		if (!authenticated) {
			// we cannoud found an account linked to the email address
			this.updateAuthenticationStatus(credentials, AuthenticationStatusEnum.NO_ACCOUNT);
			throw new NoAccountCredentialsException();
		}

		return credentials;
	}

	protected List<String> extractCredentialsOfNotMergedAccount(final MultiValuedAttributeCredentials credentials){
		List<String> ids = new ArrayList<String>();
		for (String cred: credentials.getAttributeValues()) {
			final Matcher matcher = this.patternOfAccountsCredential.matcher(cred);
			if (matcher.matches()){
				final String extract = matcher.group(this.groupPatternOfAccountsCredentialToExtract);
				if (StringUtils.hasText(extract)) {
					ids.add(extract);
				}
			}
		}
		return ids;
	}

	protected String extractCredentialOfMergedAccount(final MultiValuedAttributeCredentials credentials){
		for (String cred: credentials.getAttributeValues()) {
			final Matcher matcher = this.patternOfMergedCredential.matcher(cred);
			if (matcher.matches()){
				final String extract = matcher.group(this.groupPatternOfMergedCredentialToExtract);
				if (StringUtils.hasText(extract)) {
					return extract;
				}
			}
		}
		return null;
	}

	/**
	 * Search an account bind to the filled ldap filter.
	 *
	 * @param filledFilter the filled ldap filter
	 * @return the not null principal id if one was found corresponding to the filter
	 * @throws AuthenticationException in case of multiple accounts found
	 */
	protected final List<String> searchAccounts(final String filledFilter) throws AuthenticationException {

		List<Attributes> results = null;
		try {
			results = this.searchInLdap(filledFilter);
		} catch (Exception e) {
			// Catch exceptions to go further in authentication process
			LOGGER.error("Error during account authentication in LDAP !", e);
			return null;
		}

		if (results.isEmpty()) {
			// No account bind to the LDAP query
			LOGGER.info(String.format("Search for [%s] returned 0 results.", filledFilter));
			return null;
		}

		List<String> ids = new ArrayList<String>();
		try {
			for (Attributes attribute: results) {
				ids.add((String) attribute.get(this.getPrincipalAttributeName()).get());
			}
		} catch (NamingException e) {
			LOGGER.error("Unable to find principal attribute value in LDAP !");
		}

		return ids;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		Assert.hasText(this.authenticationAllValuesFilter, "No authentication filter on all account values provided !");
		Assert.hasText(this.authenticationMergedAccountFilter, "No authentication filter on merged account provided !");

		Assert.isTrue(authenticationAllValuesFilter.contains("%u") || authenticationAllValuesFilter.contains("%U"), "authenticationAllValuesFilter filter must contain %u or %U");
		Assert.isTrue(authenticationMergedAccountFilter.contains("%u") || authenticationMergedAccountFilter.contains("%U"), "authenticationMergedAccountFilter filter must contain %u or %U");

		Assert.hasText(this.accountsCredentialPattern, "No pattern provided for accountsCredentialPattern");
		Assert.hasText(this.mergedCredentialPattern, "No pattern provided for mergedCredentialPattern");

		Assert.isTrue(this.groupPatternOfAccountsCredentialToExtract > 0, "No group provided to extrat the groupPatternOfAccountsCredentialToExtract");
		Assert.isTrue(this.groupPatternOfMergedCredentialToExtract > 0, "No group provided to extrat the groupPatternOfMergedCredentialToExtract");

		this.patternOfAccountsCredential = Pattern.compile(this.accountsCredentialPattern);
		this.patternOfMergedCredential = Pattern.compile(this.mergedCredentialPattern);

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

	public String getMergedCredentialPattern() {
		return mergedCredentialPattern;
	}

	public void setMergedCredentialPattern(final String mergedCredentialPattern) {
		this.mergedCredentialPattern = mergedCredentialPattern;
	}

	public String getAccountsCredentialPattern() {
		return accountsCredentialPattern;
	}

	public void setAccountsCredentialPattern(final String accountsCredentialPattern) {
		this.accountsCredentialPattern = accountsCredentialPattern;
	}

	public int getGroupPatternOfMergedCredentialToExtract() {
		return groupPatternOfMergedCredentialToExtract;
	}

	public void setGroupPatternOfMergedCredentialToExtract(final int groupPatternOfMergedCredentialToExtract) {
		this.groupPatternOfMergedCredentialToExtract = groupPatternOfMergedCredentialToExtract;
	}

	public int getGroupPatternOfAccountsCredentialToExtract() {
		return groupPatternOfAccountsCredentialToExtract;
	}

	public void setGroupPatternOfAccountsCredentialToExtract(final int groupPatternOfAccountsCredentialToExtract) {
		this.groupPatternOfAccountsCredentialToExtract = groupPatternOfAccountsCredentialToExtract;
	}


}
