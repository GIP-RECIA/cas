/**
 * 
 */
package org.esco.sso.security.saml.query;

import java.io.Serializable;

/**
 * Base interface for any SAML query (request, reponse, ...).
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IQuery extends Serializable {

	/** The unique ID of the response. */
	String getId();

}
