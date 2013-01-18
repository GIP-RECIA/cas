
package org.esco.cas.authentication.handler;

import org.jasig.cas.authentication.handler.UnsupportedCredentialsException;

/**
 * Exception thrown when SAML multi valued credentials are unsupported.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public final class MultiValuedSamlCredentialsException extends AbstractEmailAddressesSamlCredentialsException {

	/** Static instance of UnsupportedCredentialsException. */
	public static final UnsupportedCredentialsException ERROR = new UnsupportedCredentialsException();

	/** Unique ID for serializing. */
	private static final long serialVersionUID = 3977861752513837361L;

	/** The code description of this exception. */
	private static final EmailAddressesAuthenticationStatusEnum STATUS = EmailAddressesAuthenticationStatusEnum.NOT_UNIQUE_EMAIL_CREDENTIAL;

	/**
	 * Default constructor that does not allow the chaining of exceptions and
	 * uses the default code as the error code for this exception.
	 */
	public MultiValuedSamlCredentialsException() {
		super(MultiValuedSamlCredentialsException.STATUS);
	}

	@Override
	public EmailAddressesAuthenticationStatusEnum getStatusCode() {
		return MultiValuedSamlCredentialsException.STATUS;
	}
}