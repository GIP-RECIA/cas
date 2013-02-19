/**
 * 
 */
package org.esco.sso.security.saml.exception;

/**
 * Error throwed if an unsuported SAML operation or feature is encountered.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class UnsupportedSamlOperation extends Exception {

	/** Svuid. */
	private static final long serialVersionUID = -5645234584904167672L;

	public UnsupportedSamlOperation() {
		super();
	}

	public UnsupportedSamlOperation(final String arg0) {
		super(arg0);
	}

	public UnsupportedSamlOperation(final Throwable arg0) {
		super(arg0);
	}

	public UnsupportedSamlOperation(final String arg0, final Throwable arg1) {
		super(arg0, arg1);
	}

}
