/**
 * 
 */
package org.esco.cas.authentication.handler;

import org.jasig.cas.authentication.handler.AuthenticationException;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class AbstractEmailAddressesSamlCredentialsException extends AuthenticationException {

	/** SVUID. */
	private static final long serialVersionUID = 502324913010237437L;

	/**
	 * Constructor that allows for the chaining of exceptions. Defaults to the
	 * default code provided for this exception.
	 * 
	 * @param throwable the chained exception.
	 */
	protected AbstractEmailAddressesSamlCredentialsException(final EmailAddressesAuthenticationStatusEnum status) {
		super(status.getStatusCode());
	}

	/**
	 * Retrieve the Authentication status code.
	 * 
	 * @return the Authentication status code
	 */
	public abstract EmailAddressesAuthenticationStatusEnum getStatusCode();

}
