/**
 * 
 */
package org.esco.sso.security.saml;

import org.opensaml.common.xml.SAMLConstants;
import org.springframework.util.StringUtils;

/**
 * Supported Bindings.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public enum SamlBindingEnum {

	/** SAML 2.0 HTTP-POST binding. */
	SAML_20_HTTP_POST(SAMLConstants.SAML2_POST_BINDING_URI, "SAML 2.0 HTTP-POST binding"),

	/** SAML 2.0 HTTP-Redirect binding. */
	SAML_20_HTTP_REDIRECT(SAMLConstants.SAML2_REDIRECT_BINDING_URI, "SAML 2.0 HTTP-Redirect binding");

	/** Binding URI. */
	private String uri;

	/** Binding description. */
	private String description;

	private SamlBindingEnum(final String uri, final String description) {
		this.uri = uri;
		this.description = description;
	}

	/**
	 * Load the enum from a bidning URI.
	 * 
	 * @param uri the binding URI
	 * @return the matching enum
	 */
	public static SamlBindingEnum fromUri(final String uri) {
		SamlBindingEnum result = null;

		if (StringUtils.hasText(uri)) {
			for (SamlBindingEnum val : SamlBindingEnum.values()) {
				if (uri.equals(val.getUri())) {
					result =  val;
				}
			}
		}

		return result;
	}

	public String getUri() {
		return this.uri;
	}

	public String getDescription() {
		return this.description;
	}

}
