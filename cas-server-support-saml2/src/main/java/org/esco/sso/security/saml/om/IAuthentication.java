/**
 * 
 */
package org.esco.sso.security.saml.om;

import java.util.List;
import java.util.Map;

import org.esco.sso.security.saml.exception.SamlSecurityException;
import org.joda.time.DateTime;

/**
 * Base interface representing an authentication from an IdP.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IAuthentication {

	/**
	 * Get the authentication instant.
	 * 
	 * @return The authentication instant.
	 */
	DateTime getAuthenticationInstant();

	/**
	 * Get the authenticated subject ID.
	 * 
	 * @return the authenticated subject ID
	 */
	String getSubjectId();

	/**
	 * Get the authenticated subject session ID on the IdP.
	 * 
	 * @return the session ID on the IdP
	 */
	String getSessionIndex();

	/**
	 * Add an authentication attribute.
	 * 
	 * @param name the name of the attribute
	 * @param values the values of the attribute
	 * @throws SamlSecurityException if multiple attribute with same name
	 */
	void addAttribute(String name, List<String> values) throws SamlSecurityException;

	/**
	 * Get on attribute values.
	 * 
	 * @param name the name of the attribute
	 * @return the values of the attribute
	 */
	List<String> getAttribute(String name);

	/**
	 * Get the map containing all attributes and their values.
	 * 
	 * @return the attributes map
	 */
	Map<String, List<String>> getAttributes();

}
