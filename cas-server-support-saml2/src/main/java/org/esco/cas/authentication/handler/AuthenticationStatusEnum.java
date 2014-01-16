/**
 * 
 */
package org.esco.cas.authentication.handler;

/**
 * Status of the SAML vector authentication.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public enum AuthenticationStatusEnum {

	/** The SAML response returned nothing. */
	EMPTY_CREDENTIAL("error.authentication.saml.credentials.empty"),

	/** The SAML response returned more than one value in vector. */
	NOT_UNIQUE_CREDENTIAL("error.authentication.saml.credentials.notUnique"),

	/** The SAML response returned an identity vector bind to no account. */
	NO_ACCOUNT("error.authentication.saml.noAccount"),

	/** The SAML response returned an identity vector bind to multiple accounts. */
	MULTIPLE_ACCOUNTS("error.authentication.saml.multipleAccounts"),	

	/** Cannot authenticate the user for another reason. */
	NOT_AUTHENTICATED("error.authentication.saml.anotherReason"),

	/** The SAML response returned an identity vector which could be authenticated. */
	AUTHENTICATED("success.authentication.saml.authentificated");

	/** The status code. */
	private String statusCode;

	private AuthenticationStatusEnum(final String statusCode) {
		this.statusCode = statusCode;
	}

	public String getStatusCode() {
		return this.statusCode;
	}

}
