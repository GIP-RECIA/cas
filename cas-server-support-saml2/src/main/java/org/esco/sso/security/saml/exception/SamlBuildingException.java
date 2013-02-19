/**
 * 
 */
package org.esco.sso.security.saml.exception;

/**
 * A SAML building problem.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlBuildingException extends Exception {

	/** SVUID. */
	private static final long serialVersionUID = 3445043904522046709L;

	public SamlBuildingException() {
		super();
	}

	public SamlBuildingException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public SamlBuildingException(final String message) {
		super(message);
	}

	public SamlBuildingException(final Throwable cause) {
		super(cause);
	}

}
