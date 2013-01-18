/**
 * 
 */
package org.esco.cas.authentication.handler;

/**
 * Status of the SAML email adresse authentication.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public enum EmailAddressesAuthenticationStatusEnum {

	/** The SAML response returned nothing. */
	EMPTY_EMAIL_CREDENTIAL("error.authentication.saml.email.credentials.empty"),

	/** The SAML response returned more than one email. */
	NOT_UNIQUE_EMAIL_CREDENTIAL("error.authentication.saml.email.credentials.notUnique"),

	/** The SAML response returned an email bind to no account. */
	NO_ACCOUNT("error.authentication.saml.email.noAccount"),

	/** The SAML response returned an email bind to multiple accounts. */
	MULTIPLE_ACCOUNTS("error.authentication.saml.email.multipleAccounts"),

	/** Cannot authenticate the user for another reason. */
	NOT_AUTHENTICATED("error.authentication.saml.email.anotherReason"),

	/** The SAML response returned an email which could be authenticated. */
	AUTHENTICATED("success.authentication.saml.email");

	/** The status code. */
	private String statusCode;

	private EmailAddressesAuthenticationStatusEnum(final String statusCode) {
		this.statusCode = statusCode;
	}

	public String getStatusCode() {
		return this.statusCode;
	}

}
