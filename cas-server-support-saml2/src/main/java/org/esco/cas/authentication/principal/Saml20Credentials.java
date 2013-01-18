/**
 * 
 */
package org.esco.cas.authentication.principal;

import org.esco.cas.impl.SamlAuthInfo;


/**
 * Abstract class for SAML 2.0 CAS Credentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class Saml20Credentials implements ISaml20Credentials {

	/** SVUID. */
	private static final long serialVersionUID = -4366282686714487731L;

	/** Authentication informations. */
	private transient SamlAuthInfo authenticationInformations;

	/** The principal Id corresponding to the authenticated principal. */
	private String principalId;

	public Saml20Credentials() {
		super();
		this.authenticationInformations = new SamlAuthInfo();
		this.authenticationInformations.setAuthCredentials(this);
	}

	@Override
	public SamlAuthInfo getAuthenticationInformations() {
		return this.authenticationInformations;
	}

	@Override
	public String getPrincipalId() {
		return this.principalId;
	}

	public void setPrincipalId(final String principalId) {
		this.principalId = principalId;
	}

}
