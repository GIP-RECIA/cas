/**
 * 
 */
package org.esco.sso.security.saml.opensaml.query;

import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.exception.NotSignedException;
import org.esco.sso.security.saml.exception.SamlProcessingException;
import org.esco.sso.security.saml.exception.SamlSecurityException;
import org.esco.sso.security.saml.exception.SamlValidationException;
import org.esco.sso.security.saml.exception.UnsupportedSamlOperation;
import org.esco.sso.security.saml.query.impl.QuerySloRequest;
import org.esco.sso.security.saml.query.impl.QuerySloResponse;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutResponse;

/**
 * OpenSaml 2 implementation of QueryProcessor for incoming SLO Response.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public class SloResponseQueryProcessor extends BaseOpenSaml2QueryProcessor<QuerySloResponse, LogoutResponse> {

	@Override
	protected void checkSecurity() throws SamlSecurityException {
		final LogoutResponse sloResponse = this.getOpenSamlObject();
		final Issuer issuer = sloResponse.getIssuer();
		final ISaml20IdpConnector idpConnector = this.findIdpConnector(issuer);

		try {
			this.validateSignatureTrust(sloResponse, issuer, idpConnector);
		} catch (NotSignedException e) {
			throw new SamlSecurityException(
					"The SLO Response cannot be trusted, signature is missing !");
		}
	}

	@Override
	protected void validateConditions() throws SamlValidationException {
		// Nothing to validate
	}

	@Override
	protected void process() throws SamlProcessingException, SamlSecurityException, UnsupportedSamlOperation {
		// Nothing to process
	}

	@Override
	protected QuerySloResponse buildSamlQuery() throws SamlProcessingException, SamlSecurityException {
		final LogoutResponse sloResponse = this.getOpenSamlObject();

		final String inResponseToId = sloResponse.getInResponseTo();
		final QuerySloRequest originalRequest =
				this.checkResponseLegitimacy(inResponseToId, QuerySloRequest.class);

		QuerySloResponse query = new QuerySloResponse(sloResponse.getID());
		query.setInResponseToId(inResponseToId);
		query.setOriginalRequest(originalRequest);

		return query;
	}

}
