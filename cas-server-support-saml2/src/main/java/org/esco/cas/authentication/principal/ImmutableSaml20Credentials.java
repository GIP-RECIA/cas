/**
 * 
 */
package org.esco.cas.authentication.principal;

import java.util.List;

import org.esco.cas.impl.SamlAuthInfo;

/**
 * An immutable Saml Credentials class to give to the end user.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class ImmutableSaml20Credentials implements ISaml20Credentials {

	/** Svuid. */
	private static final long serialVersionUID = 2974189972018636584L;
	
	private final ISaml20Credentials samlCredentials;
	
	public ImmutableSaml20Credentials(final ISaml20Credentials samlCredentials) {
		super();
		this.samlCredentials = samlCredentials;
	}

	@Override
	public SamlAuthInfo getAuthenticationInformations() {
		return this.samlCredentials.getAuthenticationInformations();
	}

	@Override
	public String getAttributeFriendlyName() {
		return this.samlCredentials.getAttributeFriendlyName();
	}

	@Override
	public void setAttributeFriendlyName(String attributeFriendlyName) {
		throw new IllegalAccessError("This Saml20Credentials are immutables !");
	}

	@Override
	public void setAttributeValues(List<String> attributesList) {
		throw new IllegalAccessError("This Saml20Credentials are immutables !");
	}

	@Override
	public List<String> getAttributeValues() {
		return this.samlCredentials.getAttributeValues();
	}

}
