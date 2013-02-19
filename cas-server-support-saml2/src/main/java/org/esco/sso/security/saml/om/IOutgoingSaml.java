/**
 * 
 */
package org.esco.sso.security.saml.om;

import java.util.Collection;
import java.util.Map.Entry;

/**
 * Interface representing datas which the SP want to send
 * outside (to an IdP).
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IOutgoingSaml extends ISamlData {

	/**
	 * Get the full SAML message encapsulated in HTTP-Redirect binding URL.
	 * 
	 * @return the HTTP-Redirect URL
	 */
	String getHttpRedirectBindingUrl();

	/**
	 * Get the HTTP-POST binding request parameters.
	 * 
	 * @return the HTTP request params
	 */
	Collection<Entry<String, String>> getHttpPostBindingParams();

}
