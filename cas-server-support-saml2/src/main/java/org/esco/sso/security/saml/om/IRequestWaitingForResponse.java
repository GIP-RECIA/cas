/**
 * 
 */
package org.esco.sso.security.saml.om;

import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.query.IQuery;

/**
 * Base interface for a SAML Request which need a SAML Response.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IRequestWaitingForResponse extends IQuery {

	/**
	 * The IdP connector which build this request.
	 * @return The IdP connector which build this request
	 */
	ISaml20IdpConnector getIdpConnectorBuilder();

}
