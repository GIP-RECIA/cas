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
	SAML_20_HTTP_POST(SAMLConstants.SAML2_POST_BINDING_URI, "SAML 2.0 HTTP-POST binding", "POST"),

	/** SAML 2.0 HTTP-Redirect binding. */
	SAML_20_HTTP_REDIRECT(SAMLConstants.SAML2_REDIRECT_BINDING_URI, "SAML 2.0 HTTP-Redirect binding", "GET");

	/** Binding URI. */
	private String samlUri;

	/** Binding description. */
	private String description;

	/** HTTP Method. */
	private String httpMethod;

	private SamlBindingEnum(final String samlUri, final String description, final String httpMethod) {
		this.samlUri = samlUri;
		this.description = description;
		this.httpMethod = httpMethod;
	}

	/**
	 * Load the enum from a bidning URI.
	 * 
	 * @param samlUri the binding URI
	 * @return the matching enum
	 */
	public static SamlBindingEnum fromSamlUri(final String samlUri) {
		SamlBindingEnum result = null;

		if (StringUtils.hasText(samlUri)) {
			for (SamlBindingEnum val : SamlBindingEnum.values()) {
				if (samlUri.equals(val.getUri())) {
					result =  val;
				}
			}
		}

		return result;
	}

	public String getUri() {
		return this.samlUri;
	}

	public String getDescription() {
		return this.description;
	}

	public String getHttpMethod() {
		return this.httpMethod;
	}

}
