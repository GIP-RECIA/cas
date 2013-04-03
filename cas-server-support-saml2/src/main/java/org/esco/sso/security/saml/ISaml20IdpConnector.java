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
package org.esco.sso.security.saml;

import javax.servlet.http.HttpServletRequest;

import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.saml.exception.SamlBuildingException;
import org.esco.sso.security.saml.om.IOutgoingSaml;

/**
 * SAML 2.0 IdP connector to ensure dialog with the IdP.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISaml20IdpConnector {

	/**
	 * Build a SAML 2.0 Authn request to ask an IdP for authentication.
	 * 
	 * @param request the HttpServletRequest origin of SAML 2.0 request
	 * @param binding the SAML 2.0 binding for the request
	 * @return the SAML 2.0 AuthnRequest
	 */
	IOutgoingSaml buildSaml20AuthnRequest(HttpServletRequest request,
			SamlBindingEnum binding) throws SamlBuildingException;

	/**
	 * Build a SAML 2.0 Single Logout Request.
	 * 
	 * @param request the HttpServletRequest origin of SAML 2.0 request
	 * @param binding the SAML 2.0 binding for the request
	 * @return the SAML 2.0 AuthnRequest
	 * @throws SamlBuildingException if unable to build the request
	 */
	IOutgoingSaml buildSaml20SingleLogoutRequest(HttpServletRequest request,
			SamlBindingEnum binding) throws SamlBuildingException;

	/**
	 * Build a SAML 2.0 Single Logout Response.
	 * 
	 * @param binding the SAML 2.0 binding for the request
	 * @param originRequestId the ID of the request origin of this response
	 * @param relayState the relayState associated with the original request
	 * @return the SAML 2.0 AuthnRequest
	 */
	IOutgoingSaml buildSaml20SingleLogoutResponse(SamlBindingEnum binding,
			String originRequestId, String relayState) throws SamlBuildingException;

	/**
	 * Register the SAML 2.0 SP processor.
	 * 
	 * @param saml20SpProcessor the SAML 2.0 SP processor
	 */
	void registerSaml20SpProcessor(ISaml20SpProcessor saml20SpProcessor);

	/**
	 * Retrieve the IdP configuration.
	 * 
	 * @return the IdP configuration
	 */
	IIdpConfig getIdpConfig();

}
