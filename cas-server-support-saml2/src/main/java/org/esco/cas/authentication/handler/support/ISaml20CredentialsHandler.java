/**
 * 
 */
package org.esco.cas.authentication.handler.support;

import org.esco.cas.authentication.exception.AbstractSamlCredentialsException;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.jasig.cas.authentication.principal.Credentials;

/**
 * SAML 2.0 Credentials Handler responsible for:
 * <ul>
 * <li>Validating supplied credentials.</li>
 * <li>Adapting supplied credentials which will be supplied to an AuthenticationHandler.</li>
 * </ul>
 *  
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface ISaml20CredentialsHandler<T extends ISaml20Credentials, V extends Credentials> {

	boolean validate(T credentials) throws AbstractSamlCredentialsException;
	
	V adapt(T credentials);
	
}
