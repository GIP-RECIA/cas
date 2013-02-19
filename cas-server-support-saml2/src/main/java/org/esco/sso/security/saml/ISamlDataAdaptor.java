/**
 * 
 */
package org.esco.sso.security.saml;

import java.util.Collection;
import java.util.Map.Entry;

import org.esco.sso.security.saml.om.IOutgoingSaml;

/**
 * Adaptor which allow to configure the shape of SAML datas in HTTP requests.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISamlDataAdaptor {

	/**
	 * Build the HTTP-Redirect binding Request to send with GET method.
	 * 
	 * @return the HTTP-Redirect URL request
	 */
	String buildHttpRedirectBindingUrl(IOutgoingSaml outgoingData);

	/**
	 * Build the HTTP-POST binding params to send with POST method.
	 * 
	 * @return the HTTP-Post params request
	 */
	Collection<Entry<String, String>> buildHttpPostBindingParams(IOutgoingSaml outgoingData);
}
