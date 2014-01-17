/**
 * 
 */
package org.esco.cas.authentication.exception;

import org.esco.cas.authentication.handler.AuthenticationStatusEnum;
import org.jasig.cas.authentication.handler.AuthenticationException;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * @param <T>
 *
 */
public abstract class AbstractCredentialsException extends AuthenticationException {

	/** SVUID. */
	private static final long serialVersionUID = 502324913010237437L;

	/**
	 * Constructor that allows for the chaining of exceptions. Defaults to the
	 * default code provided for this exception.
	 * 
	 * @param throwable the chained exception.
	 */
	protected AbstractCredentialsException(final AuthenticationStatusEnum status) {
		super(status.getStatusCode());
	}

	/**
	 * Retrieve the Authentication status code.
	 * 
	 * @return the Authentication status code
	 */
	public abstract AuthenticationStatusEnum getStatusCode();	

}
