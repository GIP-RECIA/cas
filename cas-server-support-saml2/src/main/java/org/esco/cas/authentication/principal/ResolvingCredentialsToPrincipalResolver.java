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

/**
 * Principal Resolver for self resolved IResolvingCredentials.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class ResolvingCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(ResolvingCredentialsToPrincipalResolver.class);

	/** {@inheritDoc} */
	@Override
	public boolean supports(final Credentials credentials) {
		return (credentials != null) && (IResolvingCredentials.class.isAssignableFrom(credentials.getClass()));
	}

	/** {@inheritDoc} */
	@Override
	protected String extractPrincipalId(final Credentials credentials) {
		IResolvingCredentials resolvingCreds = (IResolvingCredentials) credentials;

		String principalId = resolvingCreds.getResolvedPrincipalId();
		Assert.hasText(principalId, String.format(
				"The principal Id wasn't populate in the IResolvingCredentials of type: [%1$s] !",
				resolvingCreds.getClass().getName()));

		if (ResolvingCredentialsToPrincipalResolver.LOGGER.isDebugEnabled()) {
			ResolvingCredentialsToPrincipalResolver.LOGGER.debug(
					String.format("Resolved principal Id: [%1$s].", principalId));
		}

		return principalId;
	}

}
