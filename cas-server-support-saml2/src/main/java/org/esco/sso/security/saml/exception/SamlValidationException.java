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
public class SamlValidationException extends Exception {

	/** SVUID. */
	private static final long serialVersionUID = 8901098007581401257L;

	public SamlValidationException() {
		super();
	}

	public SamlValidationException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public SamlValidationException(final String message) {
		super(message);
	}

	public SamlValidationException(final Throwable cause) {
		super(cause);
	}

}
