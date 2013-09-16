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
	private SamlAuthInfo authenticationInformations;

	/** The principal Id corresponding to the authenticated principal. */
	private String principalId;

	public Saml20Credentials() {
		super();
		this.authenticationInformations = new SamlAuthInfo();
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
