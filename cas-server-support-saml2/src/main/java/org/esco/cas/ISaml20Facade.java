/**
 * 
 */
package org.esco.cas;

import javax.servlet.http.HttpServletRequest;

import org.esco.cas.impl.SamlAuthInfo;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISaml20Facade {

	/**
	 * Store SAML 2.0 Authentication infos for a TGT user.
	 * 
	 * @param tgtId the user's TGT Id
	 * @param authInfos the authentication informations
	 */
	void storeAuthenticationInfosInCache(String tgtId, SamlAuthInfo authInfos);

	/**
	 * Retrieve SAML 2.0 Authentication infos of a TGT user.
	 * 
	 * @param tgtId the user's TGT Id
	 * @return the authentication informations
	 */
	SamlAuthInfo retrieveAuthenticationInfosFromCache(String tgtId);


	/**
	 * Remove SAML 2.0 Authentication infos of a TGT user.
	 * 
	 * @param tgtId the user's TGT Id
	 * @return the authentication informations
	 */
	SamlAuthInfo removeAuthenticationInfosFromCache(String tgtId);

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
