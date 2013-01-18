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
