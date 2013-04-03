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
package org.esco.cas.authentication.principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Email addresses principal builder via LDAP.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class EmailAddressesCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(EmailAddressesCredentialsToPrincipalResolver.class);

	@Override
	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (credentials instanceof EmailAddressesCredentials);
	}

	@Override
	protected String extractPrincipalId(final Credentials credentials) {
		EmailAddressesCredentials emailCredentials = (EmailAddressesCredentials) credentials;

		String principalId = emailCredentials.getPrincipalId();
		Assert.isTrue(StringUtils.hasText(principalId), "The principal Id wasn't populate by the LdapEmailAddressAuthenticationHandler !");

		if (EmailAddressesCredentialsToPrincipalResolver.LOGGER.isDebugEnabled()) {
			EmailAddressesCredentialsToPrincipalResolver.LOGGER.debug(
					String.format("Resoving principal Id [%1$s].", principalId));
		}

		return principalId;
	}

}
