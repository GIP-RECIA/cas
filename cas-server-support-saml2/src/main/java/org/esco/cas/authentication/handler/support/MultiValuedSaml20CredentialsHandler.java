/**
 * 
 */
package org.esco.cas.authentication.handler.support;

import java.util.List;

import org.esco.cas.authentication.exception.AbstractCredentialsException;
import org.esco.cas.authentication.exception.EmptyCredentialsException;
import org.esco.cas.authentication.principal.MultiValuedAttributeCredentials;
import org.esco.cas.authentication.principal.Saml20Credentials;
import org.springframework.util.CollectionUtils;

/**
 * SAML 2.0 Credentials Handler which verify the uniqueness of SAML attribute values 
 * and adapt it for the LdapFiltersAuthenticationHandler.
 * 
 *  
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class MultiValuedSaml20CredentialsHandler implements ISaml20CredentialsHandler<Saml20Credentials, MultiValuedAttributeCredentials> {

	@Override
	public boolean validate(Saml20Credentials credentials) throws AbstractCredentialsException {
		final List<String> attributes = credentials.getAttributeValues();

		if (CollectionUtils.isEmpty(attributes)) {
			// Empty credentials are not supported !
			throw new EmptyCredentialsException();
		}

		return true;
	}

	@Override
	public MultiValuedAttributeCredentials adapt(Saml20Credentials credentials) {
		return credentials;
	}

}
