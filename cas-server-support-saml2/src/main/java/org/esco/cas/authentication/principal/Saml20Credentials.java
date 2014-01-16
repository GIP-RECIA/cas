/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 
 */
package org.esco.cas.authentication.principal;

import org.esco.cas.authentication.handler.AuthenticationStatusEnum;
import org.esco.cas.impl.SamlAuthInfo;


/**
 * Abstract class for SAML 2.0 CAS Credentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class Saml20Credentials extends MultiValuedAttributeCredentials implements ISaml20Credentials, 
		IInformingCredentials {

	/** SVUID. */
	private static final long serialVersionUID = -4366282686714487731L;

	/** Authentication informations. */
	private SamlAuthInfo authenticationInformations;

	private String attributeFriendlyName;
	
	/** The authentication status. */
	private AuthenticationStatusEnum authenticationStatus;

	public Saml20Credentials() {
		super();
		this.authenticationInformations = new SamlAuthInfo();
	}

	@Override
	public String toString() {
		return "Saml20Credentials [friendlyName=" + this.attributeFriendlyName
				+ ", authenticationStatus=" + authenticationStatus + ", attributeValues=" + super.getAttributeValues() + ", authenticatedValue="
				+ super.getAuthenticatedValue() + ", resolvedPrincipalId=" + super.getResolvedPrincipalId() + "]";
	}

	@Override
	public SamlAuthInfo getAuthenticationInformations() {
		return this.authenticationInformations;
	}

	/**
	 * Getter of attributeFriendlyName.
	 *
	 * @return the attributeFriendlyName
	 */
	@Override
	public String getAttributeFriendlyName() {
		return attributeFriendlyName;
	}

	/**
	 * Setter of attributeFriendlyName.
	 *
	 * @param attributeFriendlyName the attributeFriendlyName to set
	 */
	@Override
	public void setAttributeFriendlyName(String attributeFriendlyName) {
		this.attributeFriendlyName = attributeFriendlyName;
	}

	/**
	 * The authentication status.
	 * 
	 * @return the authentication status
	 */
	public AuthenticationStatusEnum getAuthenticationStatus() {
		return this.authenticationStatus;
	}

	/**
	 * The authentication status.
	 * 
	 * @param authenticationStatus the authentication status
	 */
	public void setAuthenticationStatus(final AuthenticationStatusEnum authenticationStatus) {
		this.authenticationStatus = authenticationStatus;
	}

}
