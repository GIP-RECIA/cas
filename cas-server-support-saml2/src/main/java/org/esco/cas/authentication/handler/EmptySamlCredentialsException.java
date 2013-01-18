
package org.esco.cas.authentication.handler;

import org.jasig.cas.authentication.handler.UnsupportedCredentialsException;

/**
 * Exception thrown when SAML credentials are empty.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public final class EmptySamlCredentialsException extends AbstractEmailAddressesSamlCredentialsException {

	/** Static instance of UnsupportedCredentialsException. */
	public static final UnsupportedCredentialsException ERROR = new UnsupportedCredentialsException();

	/** Unique ID for serializing. */
	private static final long serialVersionUID = 3977861752513837361L;

	/** The code description of this exception. */
	private static final EmailAddressesAuthenticationStatusEnum STATUS = EmailAddressesAuthenticationStatusEnum.EMPTY_EMAIL_CREDENTIAL;

	/**
	 * Default constructor that does not allow the chaining of exceptions and
	 * uses the default code as the error code for this exception.
	 */
	public EmptySamlCredentialsException() {
		super(EmptySamlCredentialsException.STATUS);
	}

	@Override
	public EmailAddressesAuthenticationStatusEnum getStatusCode() {
		return EmptySamlCredentialsException.STATUS;
	}
}
