/**
 * 
 */
package org.esco.cas.authentication.principal;

import org.esco.cas.impl.SamlAuthInfo;
import org.jasig.cas.authentication.principal.Credentials;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISaml20Credentials extends Credentials {

	/**
	 * Retrieve the authentication informations.
	 * 
	 * @return the authentication informations
	 */
	SamlAuthInfo getAuthenticationInformations();

	/**
	 * Retrieve the principal Id.
	 * 
	 * @return the principal Id
	 */
	String getPrincipalId();

}
