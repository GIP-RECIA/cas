/**
 * 
 */
package org.esco.sso.security.saml.exception;

/**
 * A SAML processing problem.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlProcessingException extends Exception {

	/** SVUID. */
	private static final long serialVersionUID = 3445043904522046709L;

	public SamlProcessingException() {
		super();
	}

	public SamlProcessingException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public SamlProcessingException(final String message) {
		super(message);
	}

	public SamlProcessingException(final Throwable cause) {
		super(cause);
	}

}
