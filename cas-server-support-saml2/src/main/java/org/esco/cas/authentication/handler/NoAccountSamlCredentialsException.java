
package org.esco.cas.authentication.handler;

import org.jasig.cas.authentication.handler.UnsupportedCredentialsException;

/**
 * Exception thrown when SAML authentication match multiple accounts.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public final class NoAccountSamlCredentialsException extends AbstractEmailAddressesSamlCredentialsException {

	/** Static instance of UnsupportedCredentialsException. */
	public static final UnsupportedCredentialsException ERROR = new UnsupportedCredentialsException();

	/** Unique ID for serializing. */
	private static final long serialVersionUID = 3977861752513837361L;

	/** The code description of this exception. */
	private static final EmailAddressesAuthenticationStatusEnum STATUS = EmailAddressesAuthenticationStatusEnum.NO_ACCOUNT;

	/**
	 * Default constructor that does not allow the chaining of exceptions and
	 * uses the default code as the error code for this exception.
	 */
	public NoAccountSamlCredentialsException() {
		super(NoAccountSamlCredentialsException.STATUS);
	}

	@Override
	public EmailAddressesAuthenticationStatusEnum getStatusCode() {
		return NoAccountSamlCredentialsException.STATUS;
	}
}