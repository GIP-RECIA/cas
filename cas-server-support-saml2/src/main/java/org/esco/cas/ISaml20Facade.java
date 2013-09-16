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
package org.esco.cas;

import javax.servlet.http.HttpServletRequest;

import org.esco.cas.authentication.principal.ISaml20Credentials;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISaml20Facade {

	/**
	 * Store SAML 2.0 Credentials for a TGT user.
	 * 
	 * @param tgtId the user's TGT Id
	 * @param credentials the user Credentials
	 */
	void storeAuthCredentialsInCache(String tgtId, ISaml20Credentials credentials);

	/**
	 * Retrieve SAML 2.0 credentials of a TGT user.
	 * 
	 * @param tgtId the user's TGT Id
	 * @return the user Credentials
	 */
	ISaml20Credentials retrieveAuthCredentialsFromCache(String tgtId);


	/**
	 * Remove SAML 2.0 Credentials of a TGT user.
	 * 
	 * @param tgtId the user's TGT Id
	 * @return the user Credentials
	 */
	ISaml20Credentials removeAuthenticationInfosFromCache(String tgtId);

	/**
	 * Find the CAS TGT Id corresponding to the SAML 2.0 Name ID.
	 * 
	 * @param nameId the user's SAML Name ID
	 * @return the CAS TGT Id
	 */
	String findTgtIdBySamlNameId(String nameId);

	/**
	 * Retrieve the CAS TGT Id from the cookie.
	 * 
	 * @param request the HTTP request
	 * @return the CAS TGT id
	 */
	String retrieveTgtIdFromCookie(HttpServletRequest request);

}
