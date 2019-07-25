/**
 * 
 */
package org.esco.cas.authentication.handler.support;

import org.esco.cas.authentication.exception.AbstractCredentialsException;
import org.esco.cas.authentication.exception.EmptyCredentialsException;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.esco.cas.authentication.principal.MultiValuedAttributeCredentials;
import org.esco.cas.authentication.principal.Saml20Credentials;
import org.esco.cas.authentication.principal.Saml20MultiAccountCredentials;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SAML 2.0 Credentials Handler which adapt SAML attribute values
 * for the LdapFiltersAuthenticationHandler.
 * 
 *  
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class FilteredMultiAccountSaml20CredentialsHandler implements ISaml20CredentialsAdaptors<ISaml20Credentials, Saml20MultiAccountCredentials>, InitializingBean {

	private String mergedCredentialPattern;
	private String accountsCredentialPattern;

	private int groupPatternOfMergedCredentialToExtract;
	private int groupPatternOfAccountsCredentialToExtract;

	private Pattern patternOfMergedCredential;
	private Pattern patternOfAccountsCredential;


	@Override
	public boolean support(ISaml20Credentials credential) {
		return Saml20MultiAccountCredentials.class.isAssignableFrom(credential.getClass());
	}

	@Override
	public boolean validate(ISaml20Credentials credentials) throws AbstractCredentialsException {
		final List<String> attributes = credentials.getAttributeValues();

		if (CollectionUtils.isEmpty(attributes)) {
			// Empty credentials are not supported !
			throw new EmptyCredentialsException();
		}

		return true;
	}

	@Override
	public Saml20MultiAccountCredentials adapt(ISaml20Credentials credentials) {
		((Saml20MultiAccountCredentials)credentials).setOpaqueId(extractCredentialOfMergedAccount(credentials));
		((Saml20MultiAccountCredentials)credentials).setFederatedIds(extractCredentialsOfNotMergedAccount(credentials));

		return (Saml20MultiAccountCredentials)credentials;
	}

	protected List<String> extractCredentialsOfNotMergedAccount(final ISaml20Credentials credentials){
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

	protected String extractCredentialOfMergedAccount(final ISaml20Credentials credentials){
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

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.hasText(this.accountsCredentialPattern, "No pattern provided for accountsCredentialPattern");
		Assert.hasText(this.mergedCredentialPattern, "No pattern provided for mergedCredentialPattern");

		Assert.isTrue(this.groupPatternOfAccountsCredentialToExtract > 0, "No group provided to extrat the groupPatternOfAccountsCredentialToExtract");
		Assert.isTrue(this.groupPatternOfMergedCredentialToExtract > 0, "No group provided to extrat the groupPatternOfMergedCredentialToExtract");

		this.patternOfAccountsCredential = Pattern.compile(this.accountsCredentialPattern);
		this.patternOfMergedCredential = Pattern.compile(this.mergedCredentialPattern);

	}

	public String getMergedCredentialPattern() {
		return mergedCredentialPattern;
	}

	public void setMergedCredentialPattern(String mergedCredentialPattern) {
		this.mergedCredentialPattern = mergedCredentialPattern;
	}

	public String getAccountsCredentialPattern() {
		return accountsCredentialPattern;
	}

	public void setAccountsCredentialPattern(String accountsCredentialPattern) {
		this.accountsCredentialPattern = accountsCredentialPattern;
	}

	public int getGroupPatternOfMergedCredentialToExtract() {
		return groupPatternOfMergedCredentialToExtract;
	}

	public void setGroupPatternOfMergedCredentialToExtract(int groupPatternOfMergedCredentialToExtract) {
		this.groupPatternOfMergedCredentialToExtract = groupPatternOfMergedCredentialToExtract;
	}

	public int getGroupPatternOfAccountsCredentialToExtract() {
		return groupPatternOfAccountsCredentialToExtract;
	}

	public void setGroupPatternOfAccountsCredentialToExtract(int groupPatternOfAccountsCredentialToExtract) {
		this.groupPatternOfAccountsCredentialToExtract = groupPatternOfAccountsCredentialToExtract;
	}
}
