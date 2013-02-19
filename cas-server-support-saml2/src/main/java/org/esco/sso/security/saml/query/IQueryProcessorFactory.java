/**
 * 
 */
package org.esco.sso.security.saml.query;

import javax.servlet.http.HttpServletRequest;

import org.esco.sso.security.saml.ISaml20SpProcessor;
import org.esco.sso.security.saml.exception.SamlProcessingException;
import org.esco.sso.security.saml.exception.UnsupportedSamlOperation;

/**
 * Query Processor Factory. (Abstract Factory pattern).
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface IQueryProcessorFactory {

	/**
	 * Build the QueryProcessor wich is able to process the incoming request.
	 * 
	 * @param spProcessor the SP Processor in charge
	 * @param request HTTP request containing SAML message
	 * @return the query processor
	 * @throws UnsupportedSamlOperation
	 * @throws SamlProcessingException
	 */
	IQueryProcessor buildQueryProcessor(ISaml20SpProcessor spProcessor, HttpServletRequest request)
			throws UnsupportedSamlOperation, SamlProcessingException;

}
