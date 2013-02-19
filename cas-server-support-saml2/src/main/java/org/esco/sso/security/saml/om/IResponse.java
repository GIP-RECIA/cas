/**
 * 
 */
package org.esco.sso.security.saml.om;

import org.esco.sso.security.saml.query.IQuery;

/**
 * Base interface for SAML request issued in response to another SAML request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IResponse extends IQuery {

	/**
	 * Unique request ID.
	 * 
	 * @return Unique request ID
	 */
	String getInResponseToId();

	/**
	 * Get the original request which initiate this response.
	 * 
	 * @return originalRequest the initiating request
	 */
	IRequestWaitingForResponse getOriginalRequest();

}
