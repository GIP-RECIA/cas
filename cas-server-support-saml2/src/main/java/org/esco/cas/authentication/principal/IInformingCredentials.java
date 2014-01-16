/**
 * 
 */
package org.esco.cas.authentication.principal;

import org.esco.cas.authentication.handler.AuthenticationStatusEnum;
import org.jasig.cas.authentication.principal.Credentials;

/**
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface IInformingCredentials extends Credentials {

	/**
	 * The authentication status.
	 * 
	 * @param authenticationStatus the authentication status
	 */
	void setAuthenticationStatus(AuthenticationStatusEnum authenticationStatus);

	/**
	 * The authentication status.
	 * 
	 * @return the authentication status
	 */
	AuthenticationStatusEnum getAuthenticationStatus();

}
