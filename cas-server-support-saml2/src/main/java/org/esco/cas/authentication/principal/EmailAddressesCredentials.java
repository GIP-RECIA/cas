/**
 * 
 */
package org.esco.cas.authentication.principal;

import java.util.List;

import org.esco.cas.authentication.handler.EmailAddressesAuthenticationStatusEnum;

/**
 * CAS Implementation for Email addresses credentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class EmailAddressesCredentials extends Saml20Credentials {

	/** SVUID. */
	private static final long serialVersionUID = 6280117516843013760L;

	/** Email addresses. */
	private List<String> emailAddresses;

	/** The one email address which is authenticated. */
	private String authenticatedEmailAddress;

	/** The authentication status. */
	private EmailAddressesAuthenticationStatusEnum authenticationStatus;

	@Override
	public String toString() {
		return "EmailAddressesCredentials [authenticatedEmailAddress=" + this.authenticatedEmailAddress + "]";
	}

	/**
	 * Default constructor.
	 * 
	 * @param email ordered list of email adresses
	 */
	public EmailAddressesCredentials(final List<String> email) {
		this.emailAddresses = email;
	}

	/**
	 * Email addresses.
	 * 
	 * @return Email addresses
	 */
	public List<String> getEmailAddresses() {
		return this.emailAddresses;
	}

	/**
	 * Email addresses.
	 * 
	 * @param addresses Email addresses
	 */
	public void setEmailAddresses(final List<String> addresses) {
		this.emailAddresses = addresses;
	}

	/**
	 * The one email address which is authenticated.
	 * 
	 * @return authenticated email address
	 */
	public String getAuthenticatedEmailAddress() {
		return this.authenticatedEmailAddress;
	}

	/**
	 * The one email address which is authenticated.
	 * 
	 * @param emailAddressAuthenticated the authenticated email address
	 */
	public void setAuthenticatedEmailAddress(final String authenticatedEmailAddress) {
		this.authenticatedEmailAddress = authenticatedEmailAddress;
	}

	/**
	 * The authentication status.
	 * 
	 * @return the authentication status
	 */
	public EmailAddressesAuthenticationStatusEnum getAuthenticationStatus() {
		return this.authenticationStatus;
	}

	/**
	 * The authentication status.
	 * 
	 * @param authenticationStatus the authentication status
	 */
	public void setAuthenticationStatus(final EmailAddressesAuthenticationStatusEnum authenticationStatus) {
		this.authenticationStatus = authenticationStatus;
	}

}
