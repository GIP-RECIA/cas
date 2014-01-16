/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * 
 */
package org.esco.cas.authentication.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.handler.support.ISaml20CredentialsHandler;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Authentication handler which exploits ISaml20Credentials and delegate authentication 
 * to a backing authentication handler.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class SamlAttributesAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler implements InitializingBean {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(SamlAttributesAuthenticationHandler.class);

	/** The authentication handler which really handle the authentication. */
	private AuthenticationHandler backingHandler;

	private ISaml20CredentialsHandler<ISaml20Credentials, Credentials> samlCredsAdaptator;
	
	@Override
	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (ISaml20Credentials.class.isAssignableFrom(credentials.getClass()));
	}

	@Override
	protected boolean doAuthentication(final Credentials credentials) throws AuthenticationException {
		boolean auth = false;

		if (credentials != null) {
			final ISaml20Credentials samlCredentials = (ISaml20Credentials) credentials;

			final boolean validated = this.samlCredsAdaptator.validate(samlCredentials);
			
			if (validated) {
				final Credentials adaptedCreds = this.samlCredsAdaptator.adapt(samlCredentials);
				if (this.backingHandler.supports(adaptedCreds)) {
					auth = this.backingHandler.authenticate(adaptedCreds);
				} else {
					LOGGER.warn(String.format("Backing AuthenticationHandler of type: [%1$s] doesn't supports " +
							"SAML adapted Credentials of type: [%2$s] !", 
							this.backingHandler.getClass().getName(), adaptedCreds.getClass().getName()));
				}
			}
		}

		return auth;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.backingHandler, "No backing AuthenticationHandler supplied !");
		Assert.notNull(this.samlCredsAdaptator, "No ISamlCredentialsAdaptator supplied !");
	}

	/**
	 * Getter of backingHandler.
	 *
	 * @return the backingHandler
	 */
	public AuthenticationHandler getBackingHandler() {
		return backingHandler;
	}

	/**
	 * Setter of backingHandler.
	 *
	 * @param backingHandler the backingHandler to set
	 */
	public void setBackingHandler(AuthenticationHandler backingHandler) {
		this.backingHandler = backingHandler;
	}

	/**
	 * Getter of samlCredsAdaptator.
	 *
	 * @return the samlCredsAdaptator
	 */
	public ISaml20CredentialsHandler<ISaml20Credentials, Credentials> getSamlCredsAdaptator() {
		return samlCredsAdaptator;
	}

	/**
	 * Setter of samlCredsAdaptator.
	 *
	 * @param samlCredsAdaptator the samlCredsAdaptator to set
	 */
	public void setSamlCredsAdaptator(ISaml20CredentialsHandler<ISaml20Credentials, Credentials> samlCredsAdaptator) {
		this.samlCredsAdaptator = samlCredsAdaptator;
	}

}
