/**
 * 
 */
package org.esco.sso.security.saml.exception;


/**
 * A SAML security problem. This problem should be considered as a potential attack !
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlSecurityException extends Exception {

	/** Svuid. */
	private static final long serialVersionUID = 8895835344122467592L;

	public SamlSecurityException(final String message) {
		super(message);
	}

	public SamlSecurityException(final String message, final Throwable cause) {
		super(message, cause);
	}

}
