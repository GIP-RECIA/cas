package org.esco.cas.authentication.handler;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.exception.MultiAccountsSamlCredentialsException;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.util.Assert;

/**
 * Abstract class to build authentication handler based on LDAP.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public abstract class AbstractLdapAuthentificationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {	
	
	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(AbstractLdapAuthentificationHandler.class);
	
	/** The default maximum number of results to return. */
	private static final int DEFAULT_MAX_NUMBER_OF_RESULTS = 1000;

	/** The default timeout. */
	private static final int DEFAULT_TIMEOUT = 1000;
	
	/** The scope. */
	@Min(0)
	@Max(2)
	private int scope = SearchControls.SUBTREE_SCOPE;

	/** The maximum number of results to return. */
	private int maxNumberResults = AbstractLdapAuthentificationHandler.DEFAULT_MAX_NUMBER_OF_RESULTS;

	/** The amount of time to wait. */
	private int timeout = AbstractLdapAuthentificationHandler.DEFAULT_TIMEOUT;

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
	
	/** LDAP search controls. */
	private SearchControls searchControls;

	/** LDAP principal attribute name. */
	private String principalAttributeName;		

	/**
	 * Search an account bind to the filled ldap filter.
	 * 
	 * @param filledFilter the filled ldap filter
	 * @return the not null principal id if one was found corresponding to the filter
	 * @throws AuthenticationException in case of multiple accounts found
	 */
	protected final String searchAccount(final String filledFilter) throws AuthenticationException {		

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
		if ((results.size() > 1)) {
			// Multiple accounts binds to LDAP Query
			LOGGER.warn(String.format("Search for [%s] returned multiple results.", filledFilter));
			throw new MultiAccountsSamlCredentialsException();
		}

		Attributes uniqueResult = results.iterator().next();
		String principalId = null;
		try {
			principalId = (String) uniqueResult.get(this.getPrincipalAttributeName()).get();
		} catch (NamingException e) {
			LOGGER.error("Unable to find principal attribute value in LDAP !");
		}

		return principalId;
	}	
	
	/**
	 * Serach in Ldap for attributes.
	 * 
	 * @param filter the search filter
	 * @return the list of attributes
	 */
	protected final List<Attributes> searchInLdap(final String filter) {
		final List<Attributes> result = new ArrayList<Attributes>();

		final SearchControls searchControls = this.getSearchControls();
		final String base = this.getSearchBase();

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(String.format("Starting LDAP search for filter [%s] ...", filter));
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
	 * {@inheritDoc}
	 */	
	protected void afterPropertiesSet() throws Exception {
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
	 * Retrieve the subclass Ldap search controls.
	 * 
	 * @return the Ldap search controls
	 */
	protected final  SearchControls getSearchControls() {
		return this.searchControls;
	}
	
	/**
	 * Method to return the LdapTemplate
	 * 
	 * @return a fully created LdapTemplate.
	 */
	protected final LdapTemplate getLdapTemplate() {
		return this.ldapTemplate;
	}
	
	/**
	 * Available ONLY for subclasses that are doing special things with the ContextSource.
	 *
	 * @param ldapTemplate the LDAPTemplate to use.
	 */	
	protected final void setLdapTemplate(final LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	protected final ContextSource getContextSource() {
		return this.contextSource;
	}	

	/**
	 * Method to set the datasource and generate a JdbcTemplate.
	 * 
	 * @param contextSource the datasource to use.
	 */
	public final void setContextSource(final ContextSource contextSource) {
		this.contextSource = contextSource;
	}

	protected final int getScope() {
		return this.scope;
	}

	public final void setScope(final int scope) {
		this.scope = scope;
	}

	protected final int getMaxNumberResults() {
		return this.maxNumberResults;
	}

	public final void setMaxNumberResults(final int maxNumberResults) {
		this.maxNumberResults = maxNumberResults;
	}

	protected final int getTimeout() {
		return this.timeout;
	}

	public final void setTimeout(final int timeout) {
		this.timeout = timeout;
	}
	
	protected final String getSearchBase() {
		return this.searchBase;
	}

	public final void setSearchBase(final String searchBase) {
		this.searchBase = searchBase;
	}	
	
	/**
	 * Retrieve the subclass principalAttributeName.
	 * @return principalAttributeName.
	 */
	protected final String getPrincipalAttributeName() {
		return this.principalAttributeName;
	}

	public final void setPrincipalAttributeName(final String principalAttributeName) {
		this.principalAttributeName = principalAttributeName;
	}
	
	public final void setIgnorePartialResultException(final boolean ignorePartialResultException) {
		this.ignorePartialResultException = ignorePartialResultException;
	}

}
