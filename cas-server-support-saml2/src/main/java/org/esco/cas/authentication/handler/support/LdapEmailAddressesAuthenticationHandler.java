/**
 * 
 */
package org.esco.cas.authentication.handler.support;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.handler.AbstractEmailAddressesSamlCredentialsException;
import org.esco.cas.authentication.handler.EmailAddressesAuthenticationStatusEnum;
import org.esco.cas.authentication.handler.EmptySamlCredentialsException;
import org.esco.cas.authentication.handler.MultiAccountsSamlCredentialsException;
import org.esco.cas.authentication.handler.MultiValuedSamlCredentialsException;
import org.esco.cas.authentication.handler.NoAccountSamlCredentialsException;
import org.esco.cas.authentication.principal.EmailAddressesCredentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.util.LdapUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * LDAP authentication handler for EmailAddressesCredentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class LdapEmailAddressesAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler implements InitializingBean {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(LdapEmailAddressesAuthenticationHandler.class);

	/** The default maximum number of results to return. */
	private static final int DEFAULT_MAX_NUMBER_OF_RESULTS = 1000;

	/** The default timeout. */
	private static final int DEFAULT_TIMEOUT = 1000;

	/** The scope. */
	@Min(0)
	@Max(2)
	private int scope = SearchControls.SUBTREE_SCOPE;

	/** The maximum number of results to return. */
	private int maxNumberResults = LdapEmailAddressesAuthenticationHandler.DEFAULT_MAX_NUMBER_OF_RESULTS;

	/** The amount of time to wait. */
	private int timeout = LdapEmailAddressesAuthenticationHandler.DEFAULT_TIMEOUT;

	/** LdapTemplate to execute ldap queries. */
	@NotNull
	private LdapTemplate ldapTemplate;

	/** Instance of ContextSource */
	@NotNull
	private ContextSource contextSource;

	/** The search base to find the user under. */
	private String searchBase;

	/** Whether the LdapTemplate should ignore partial results. */
	private boolean ignorePartialResultException = false;

	/** Ordered list of all LDAP filters to try for authenticate an email Address. */
	private List<String> authenticationLdapFilters;

	/** LDAP search controls. */
	private SearchControls searchControls;

	/** LDAP principal attribute name. */
	private String principalAttributeName;

	@Override
	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (credentials instanceof EmailAddressesCredentials);
	}

	@Override
	protected boolean doAuthentication(final Credentials credentials) throws AuthenticationException {
		boolean auth = false;

		if (credentials != null) {
			EmailAddressesCredentials emailCredentials = (EmailAddressesCredentials) credentials;

			if (LdapEmailAddressesAuthenticationHandler.LOGGER.isDebugEnabled()) {
				LdapEmailAddressesAuthenticationHandler.LOGGER.debug(String.format(
						"Try to authenticate SAML 2.0 Email Response with mail= [%s]",
						emailCredentials.getEmailAddresses()));
			}



			try {
				auth = this.authenticateEmailAddressInternal(emailCredentials);
			} catch(AbstractEmailAddressesSamlCredentialsException e) {
				emailCredentials.setAuthenticationStatus(e.getStatusCode());
				LdapEmailAddressesAuthenticationHandler.LOGGER.warn(
						String.format("Error while performing SAML via email authentication ! Email [%s] produced the following error code : [%s].",
								emailCredentials.getEmailAddresses(), e.getStatusCode()));
			}

			if (LdapEmailAddressesAuthenticationHandler.LOGGER.isInfoEnabled()) {
				if (auth) {
					emailCredentials.setAuthenticationStatus(EmailAddressesAuthenticationStatusEnum.AUTHENTICATED);
					LdapEmailAddressesAuthenticationHandler.LOGGER.info(String.format(
							"Successfully authenticated SAML 2.0 Email Response with mail= [%s]",
							emailCredentials.getEmailAddresses()));
				} else {
					LdapEmailAddressesAuthenticationHandler.LOGGER.info(String.format(
							"Unable to authenticate SAML 2.0 Email Response with mail= [%s]",
							emailCredentials.getEmailAddresses()));
					if (emailCredentials.getAuthenticationStatus() == null) {
						emailCredentials.setAuthenticationStatus(EmailAddressesAuthenticationStatusEnum.AUTHENTICATED);
					}
				}
			}

		}

		return auth;
	}

	/**
	 * Try to authenticate an EmailAddressesCredentials.
	 * Mutliple email values are rejected.
	 * Try a list of LDAP filters and stop on the first successful attempt.
	 * 
	 * @param credentials the EmailAddressesCredentials
	 * @return true if authenticated
	 * @throws AuthenticationException
	 */
	protected boolean authenticateEmailAddressInternal(final EmailAddressesCredentials credentials) throws AuthenticationException {
		boolean authenticated = false;

		List<String> emailAdresses = credentials.getEmailAddresses();

		if (CollectionUtils.isEmpty(emailAdresses)) {
			// Empty credentials are unsupported !
			throw new EmptySamlCredentialsException();
		}

		if (emailAdresses.size() > 1) {
			// Multi valued credentials are unsupported !
			throw new MultiValuedSamlCredentialsException();
		}

		String emailAddress = emailAdresses.iterator().next();
		Iterator<String> filterIterator = this.authenticationLdapFilters.iterator();

		while (!authenticated && filterIterator.hasNext()) {
			String currentFilter = filterIterator.next();
			String principalId = this.searchEmailAccount(currentFilter, emailAddress);
			credentials.setPrincipalId(principalId);
			authenticated = StringUtils.hasText(principalId);
		}

		if (authenticated) {
			credentials.setAuthenticatedEmailAddress(emailAddress);
		} else {
			// we cannoud found an account linked to the email address
			throw new NoAccountSamlCredentialsException();
		}

		return authenticated;
	}

	/**
	 * Search an account bind to the email address.
	 * 
	 * @param emailAddress the email address
	 * @return the not null principal id if one was found corresponding to the filter
	 * @throws AuthenticationException in case of multiple accounts found
	 */
	protected String searchEmailAccount(final String filter, final String emailAddress) throws AuthenticationException {
		final String filledFilter = LdapUtils.getFilterWithValues(filter, emailAddress);

		List<Attributes> results = null;
		try {
			results = this.searchInLdap(filledFilter);
		} catch (Exception e) {
			// Catch exceptions to go further in authentication process
			LdapEmailAddressesAuthenticationHandler.LOGGER.error("Error during email account authentication in LDAP !", e);
			return null;
		}

		if (results.isEmpty()) {
			// No account bind to email
			this.log.info(String.format("Search for [%s] returned 0 results.", filledFilter));
			return null;
		}
		if ((results.size() > 1)) {
			// Multiple accounts binds to email
			this.log.warn(String.format("Search for [%s] returned multiple results.", filledFilter));
			throw new MultiAccountsSamlCredentialsException();
		}

		Attributes uniqueResult = results.iterator().next();
		String principalId = null;
		try {
			principalId = (String) uniqueResult.get(this.principalAttributeName).get();
		} catch (NamingException e) {
			LdapEmailAddressesAuthenticationHandler.LOGGER.error("Unable to find principal attribute value in LDAP !");
		}

		return principalId;
	}

	/**
	 * Serach in Ldap for attributes.
	 * 
	 * @param filter the search filter
	 * @return the list of attributes
	 */
	protected List<Attributes> searchInLdap(final String filter) {
		final List<Attributes> result = new ArrayList<Attributes>();

		final SearchControls searchControls = this.getSearchControls();
		final String base = this.searchBase;

		if (LdapEmailAddressesAuthenticationHandler.LOGGER.isDebugEnabled()) {
			LdapEmailAddressesAuthenticationHandler.LOGGER.debug(String.format("Starting LDAP search for filter [%s] ...", filter));
		}

		this.getLdapTemplate().search(base, filter, searchControls, new AttributesMapper() {

			@Override
			public Object mapFromAttributes(final Attributes attrs) throws NamingException {
				if (attrs != null) {
					result.add(attrs);
				}
				return null;
			}
		});

		return result;
	}

	/**
	 * Retrieve Ldap search controls.
	 * 
	 * @return the Ldap search controls
	 */
	private SearchControls getSearchControls() {
		return this.searchControls;
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

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notEmpty(this.authenticationLdapFilters, "No authentication filter list provided !");
		for (String filter : this.authenticationLdapFilters) {
			Assert.isTrue(filter.contains("%u") || filter.contains("%U"), "filter must contain %u or %U");
		}

		if (this.ldapTemplate == null) {
			this.ldapTemplate = new LdapTemplate(this.contextSource);
		}
		this.ldapTemplate.setIgnorePartialResultException(this.ignorePartialResultException);

		final SearchControls constraints = new SearchControls();
		constraints.setSearchScope(this.scope);
		constraints.setTimeLimit(this.timeout);
		constraints.setCountLimit(this.maxNumberResults);
		constraints.setReturningAttributes(new String[]{this.principalAttributeName});
		this.searchControls = constraints;

		Assert.notNull(this.principalAttributeName, "No LDAP principal attribute name configured !");
	}

	/**
	 * Method to set the datasource and generate a JdbcTemplate.
	 * 
	 * @param contextSource the datasource to use.
	 */
	public final void setContextSource(final ContextSource contextSource) {
		this.contextSource = contextSource;
	}

	public final void setIgnorePartialResultException(final boolean ignorePartialResultException) {
		this.ignorePartialResultException = ignorePartialResultException;
	}

	/**
	 * Method to return the LdapTemplate
	 * 
	 * @return a fully created LdapTemplate.
	 */
	protected final LdapTemplate getLdapTemplate() {
		return this.ldapTemplate;
	}

	protected final ContextSource getContextSource() {
		return this.contextSource;
	}

	/**
	 * Available ONLY for subclasses that are doing special things with the ContextSource.
	 *
	 * @param ldapTemplate the LDAPTemplate to use.
	 */
	protected final void setLdapTemplate(final LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	public int getScope() {
		return this.scope;
	}

	public void setScope(final int scope) {
		this.scope = scope;
	}

	public int getMaxNumberResults() {
		return this.maxNumberResults;
	}

	public void setMaxNumberResults(final int maxNumberResults) {
		this.maxNumberResults = maxNumberResults;
	}

	public int getTimeout() {
		return this.timeout;
	}

	public void setTimeout(final int timeout) {
		this.timeout = timeout;
	}

	public String getSearchBase() {
		return this.searchBase;
	}

	public void setSearchBase(final String searchBase) {
		this.searchBase = searchBase;
	}

	public boolean isIgnorePartialResultException() {
		return this.ignorePartialResultException;
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

	public String getPrincipalAttributeName() {
		return this.principalAttributeName;
	}

	public void setPrincipalAttributeName(final String principalAttributeName) {
		this.principalAttributeName = principalAttributeName;
	}

}
