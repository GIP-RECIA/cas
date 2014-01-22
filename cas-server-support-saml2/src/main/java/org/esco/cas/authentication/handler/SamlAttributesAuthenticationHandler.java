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

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.exception.AuthenticationExceptionList;
import org.esco.cas.authentication.handler.support.ISaml20CredentialsHandler;
import org.esco.cas.authentication.principal.IInformingCredentials;
import org.esco.cas.authentication.principal.IResolvingCredentials;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.handler.NamedAuthenticationHandler;
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
	private List<AuthenticationHandler> backingHandlers;

	private ISaml20CredentialsHandler<ISaml20Credentials, Credentials> samlCredsAdaptator;
	
	@Override
	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (ISaml20Credentials.class.isAssignableFrom(credentials.getClass()));
	}

	@Override
	protected boolean doAuthentication(final Credentials credentials) throws AuthenticationException {
		boolean authenticated = false;

		if (credentials != null) {
			final ISaml20Credentials samlCredentials = (ISaml20Credentials) credentials;

			final boolean validated = this.samlCredsAdaptator.validate(samlCredentials);
			
			if (validated) {
				final StringBuilder sbErrorMsg = new StringBuilder(256);
				final AuthenticationExceptionList errorList = new AuthenticationExceptionList();
				
				for (AuthenticationHandler handler : this.backingHandlers) {
					final Credentials adaptedCreds = this.samlCredsAdaptator.adapt(samlCredentials);
					if (handler.supports(adaptedCreds)) {
						try {
							authenticated = handler.authenticate(adaptedCreds);
							
							if (authenticated) {
								if (IResolvingCredentials.class.isAssignableFrom(credentials.getClass())) {
									final IResolvingCredentials resolvingCreds = (IResolvingCredentials) adaptedCreds;
									samlCredentials.setResolvedPrincipalId(resolvingCreds.getResolvedPrincipalId());
								}
								if (IInformingCredentials.class.isAssignableFrom(credentials.getClass())) {
									final IInformingCredentials informingCreds = (IInformingCredentials) adaptedCreds;
									samlCredentials.setAuthenticationStatus(informingCreds.getAuthenticationStatus());
								}
								break;
							}
							
						} catch (AuthenticationException e) {
							// If error during authentication then keep it
							errorList.add(e);
						} finally {
							// If not authenticated add error message
							if (!authenticated) {
								sbErrorMsg.append(this.getHandlerName(handler));
								sbErrorMsg.append(" didn't authenticate credentials");
								if (IInformingCredentials.class.isAssignableFrom(credentials.getClass())) {
									final IInformingCredentials informingCreds = (IInformingCredentials) adaptedCreds;
									sbErrorMsg.append(" and returned code [");
									sbErrorMsg.append(informingCreds.getAuthenticationStatus());
									sbErrorMsg.append("]");
								}
								sbErrorMsg.append("\r\n");
							}
						}
					} else {
						LOGGER.warn(String.format("Backing AuthenticationHandler of type: [%1$s] doesn't supports " +
								"SAML adapted Credentials of type: [%2$s] !", 
								handler.getClass().getName(), adaptedCreds.getClass().getName()));
					}
				}
				
				if (!authenticated && !errorList.isEmpty()) {
					// Not authentified and Some errors were encountered during authentication process
					LOGGER.warn(
							String.format("Error while performing SAML authentication ! Attributes [%s] produced the following output : \r\n%s",
									samlCredentials.getAttributeValues(), sbErrorMsg.toString()));
					throw errorList;
				}
			}
		}

		return authenticated;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notEmpty(this.backingHandlers, "No backing AuthenticationHandler supplied !");
		Assert.notNull(this.samlCredsAdaptator, "No ISamlCredentialsAdaptator supplied !");
	}
	
	protected String getHandlerName(final AuthenticationHandler handler) {
		final String name;
		
		if (handler instanceof NamedAuthenticationHandler) {
			name = ((NamedAuthenticationHandler)handler).getName();
		} else {
			name = handler.getClass().getName();
		}
		
		return name;
	}

	/**
	 * Getter of backingHandlers.
	 *
	 * @return the backingHandlers
	 */
	public List<AuthenticationHandler> getBackingHandlers() {
		return backingHandlers;
	}

	/**
	 * Setter of backingHandlers.
	 *
	 * @param backingHandlers the backingHandlers to set
	 */
	public void setBackingHandlers(List<AuthenticationHandler> backingHandlers) {
		this.backingHandlers = backingHandlers;
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
