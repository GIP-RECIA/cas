/**
 * 
 */
package org.esco.cas.authentication.handler.support;

import java.util.List;

import org.esco.cas.authentication.exception.AbstractCredentialsException;
import org.esco.cas.authentication.exception.EmptyCredentialsException;
import org.esco.cas.authentication.exception.MultiValuedCredentialsException;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.esco.cas.authentication.principal.MultiValuedAttributeCredentials;
import org.springframework.util.CollectionUtils;

/**
 * SAML 2.0 Credentials Handler which verify the uniqueness of SAML attribute values 
 * and adapt it for the LdapFiltersAuthenticationHandler.
 * 
 *  
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class MonoValuedSaml20CredentialsHandler implements ISaml20CredentialsHandler<ISaml20Credentials, MultiValuedAttributeCredentials> {

	@Override
	public boolean validate(ISaml20Credentials credentials) throws AbstractCredentialsException {
		final List<String> attributes = credentials.getAttributeValues();

		if (CollectionUtils.isEmpty(attributes)) {
			// Empty credentials are not supported !
			throw new EmptyCredentialsException();
		}

		if (attributes.size() > 1) {
			// Multi valued credentials are not supported !
			throw new MultiValuedCredentialsException();
		}
		
		return true;
	}

	@Override
	public MultiValuedAttributeCredentials adapt(ISaml20Credentials credentials) {
		final MultiValuedAttributeCredentials adapted = new MultiValuedAttributeCredentials();
		adapted.setAttributeValues(credentials.getAttributeValues());
		
		return adapted;
	}

}
