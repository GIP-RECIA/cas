/**
 * 
 */
package org.esco.sso.security.saml.query;

import org.esco.sso.security.saml.exception.SamlProcessingException;
import org.esco.sso.security.saml.exception.UnsupportedSamlOperation;
import org.esco.sso.security.saml.om.IIncomingSaml;

/**
 * IncomingQueryProcessor will fully process an incoming SAML request of a specific type.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface IQueryProcessor {

	/**
	 * Fully process the incoming SAML request.
	 * 
	 * @return the IIncomingSaml representation of the message
	 * @throws SamlProcessingException
	 * @throws UnsupportedSamlOperation
	 */
	IIncomingSaml processIncomingSamlMessage()
			throws SamlProcessingException, UnsupportedSamlOperation;

}
