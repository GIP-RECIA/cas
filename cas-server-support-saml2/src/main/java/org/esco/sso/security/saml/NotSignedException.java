/**
 * 
 */
package org.esco.sso.security.saml;

/**
 * Indicate an absence of signature.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class NotSignedException extends Exception {

	/** SVUID. */
	private static final long serialVersionUID = -6526199098196184344L;

	public NotSignedException() {
		super();
	}

	public NotSignedException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public NotSignedException(final String message) {
		super(message);
	}

	public NotSignedException(final Throwable cause) {
		super(cause);
	}

}
