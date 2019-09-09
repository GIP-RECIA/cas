/**
 * 
 */
package org.esco.cas.web.flow;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.ISaml20Facade;
import org.esco.cas.authentication.handler.AuthenticationStatusEnum;
import org.esco.cas.authentication.handler.support.IMultiAccountFilterRetrieverHandler;
import org.esco.cas.authentication.handler.support.ISaml20CredentialsAdaptors;
import org.esco.cas.authentication.principal.IMultiAccountCredential;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.esco.cas.impl.SamlAuthInfo;
import org.esco.cas.multidomain.IStructureInformations;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IAuthentication;
import org.esco.sso.security.saml.om.IIncomingSaml;
import org.esco.sso.security.saml.query.IQuery;
import org.esco.sso.security.saml.query.impl.QueryAuthnResponse;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.flow.AbstractNonInteractiveCredentialsAction;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.WebUtils;
import org.opensaml.xml.util.Pair;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.webflow.execution.RequestContext;

/**
 * Retrieve email address authentication credentials from SAML response.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 * @author BULL - David BREYTON.
 *
 */
public class Saml20AuthenticationAction extends AbstractNonInteractiveCredentialsAction {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(Saml20AuthenticationAction.class);

	/** Saml response data flow scope key. */
	public static final String SAML_RESPONSE_DATA_FLOW_SCOPE_KEY = "samlResponseData";

	public static final String SAML_CREDENTIALS_FLOW_SCOPE_KEY = "samlCredentials";

	public static final String SAML_MULTIACCOUNT_CHOICE_FLOW_SCOPE_KEY = "samlMultiAccountChoice";

	public static final String SAML_MULTIACCOUNT_CHOICE_RESPONSE_DATA_FLOW_SCOPE_KEY = "chosen_id";

	/** Saml2 Facade. */
	private ISaml20Facade saml2Facade;

	private ISaml20CredentialsAdaptors<ISaml20Credentials, Credentials> samlCredsAdaptator;

	/** The LDAP MultiAccountRetriever. */
	private List<IMultiAccountFilterRetrieverHandler> multiAccountRetriever;

	private IStructureInformations structureInformations;

	@Override
	protected Credentials constructCredentialsFromRequest(final RequestContext context) {		
		Credentials credentials = null;
		try {

			// Only SAML Authn Responses need to be processed here !
			final QueryAuthnResponse authnResp = this.extractAuthnResponseFromContext(context);
			if (authnResp != null) {
				// The is a valid SAML Authn Response in the context

				// List of authentications
				final List<IAuthentication> authentications = authnResp.getSamlAuthentications();
				Assert.isTrue(authentications.size() == 1,
						"SAML Authn Response must contain 1 and only 1 authentication !");
				
				// Unique authentication
				final IAuthentication authentication = authentications.iterator().next();


				final ISaml20IdpConnector isSaml20IdpConnector = authnResp.getOriginalRequest().getIdpConnectorBuilder();
				final String friendlyName = isSaml20IdpConnector.getIdpConfig().getFriendlyName();
				Assert.notNull(friendlyName, "The friendlyName cannot be null here : the OpenSaml20IdpConnector must have a friendlyName ! ");
								
				// If a SAML response was found, the user is already authenticated via SAML
				List<String> vectorAttributeValues = authentication.getAttribute(friendlyName);

				final Class<? extends ISaml20Credentials> boundCredentialsType = isSaml20IdpConnector.getCredentialsType();
				Assert.notNull(boundCredentialsType, "The credential type cannot be null here : the OpenSaml20IdpConnector must have a credential type bound ! ");
				
				ISaml20Credentials saml20Credentials = boundCredentialsType.newInstance();
				saml20Credentials.setAttributeFriendlyName(friendlyName);
				saml20Credentials.setAttributeValues(vectorAttributeValues);
								
				final SamlAuthInfo authInfos = saml20Credentials.getAuthenticationInformations();
				String idpEntityId = authnResp.getOriginalRequest().getIdpConnectorBuilder()
						.getIdpConfig().getIdpEntityId();
				Assert.notNull(idpEntityId, "The IdP entity ID cannot be null here !");
				authInfos.setIdpEntityId(idpEntityId);
				authInfos.setIdpSubject(authentication.getSubjectId());
				authInfos.setSessionIndex(authentication.getSessionIndex());
				authInfos.setTargetUrl(WebUtils.getService(context));

				if (samlCredsAdaptator != null && samlCredsAdaptator.support(saml20Credentials) && samlCredsAdaptator.validate(saml20Credentials)) {
					saml20Credentials = (ISaml20Credentials)samlCredsAdaptator.adapt(saml20Credentials);
				}

				saml20Credentials = this.resolveMultiAccount(context, saml20Credentials);

				// selecting a default value to continue the process
				if (AuthenticationStatusEnum.MULTIPLE_ACCOUNTS.equals(saml20Credentials.getAuthenticationStatus())) {
					if (IMultiAccountCredential.class.isAssignableFrom(saml20Credentials.getClass())) {
						String defaultID = ((IMultiAccountCredential) saml20Credentials).getResolvedPrincipalIds().get(0);
						LOGGER.debug(
								String.format("Assigning default MultiAccount Authentication with credentials [%s] and default id [%s]!", credentials, defaultID));
						saml20Credentials.setResolvedPrincipalId(defaultID);
						saml20Credentials.setAuthenticationStatus(AuthenticationStatusEnum.AUTHENTICATED);
						LOGGER.info(String.format(
								"[%s] Successfully authenticated MultiAccount with default id: [%s]",
								this.getClass().getName(), defaultID));
					}
				}

				credentials = saml20Credentials;
				// Put identity vector credentials in flow scope
				context.getFlowScope().put(Saml20AuthenticationAction.SAML_CREDENTIALS_FLOW_SCOPE_KEY, saml20Credentials);
			} else {
				String chosenId = this.extractChosenAccountFromContext(context);
				if (chosenId != null) {
					String tgtId = WebUtils.getTicketGrantingTicketId(context);
					if (tgtId == null) {
						tgtId = this.extractTGTIDFromContext(context);
					}

					Assert.notNull(tgtId, "The TGT Id cannot be null here !");

					ISaml20Credentials saml20Credentials = this.saml2Facade.retrieveAuthCredentialsFromCache(tgtId);

					final WebApplicationService service = saml20Credentials.getAuthenticationInformations().getTarget();
					context.getFlowScope().put("service", service);

					if (IMultiAccountCredential.class.isAssignableFrom(saml20Credentials.getClass())) {
						LOGGER.debug(
								String.format("Entering on selecting a MultiAccount Authentication with credentials [%s] and chosen id [%s]!", saml20Credentials, chosenId));
						if (!((IMultiAccountCredential)saml20Credentials).getResolvedPrincipalIds().contains(chosenId)) {
							LOGGER.error(String.format("L'identifiant de multi account choisi [%s] ne fait pas parti de la liste des identifiants autorisés [%s]!",
									chosenId, ((IMultiAccountCredential)saml20Credentials).getResolvedPrincipalIds()));

						} else {
							saml20Credentials.setResolvedPrincipalId(chosenId);
							saml20Credentials.setAuthenticationStatus(AuthenticationStatusEnum.AUTHENTICATED);
							((IMultiAccountCredential) saml20Credentials).setUserChooseId(chosenId);
							LOGGER.info(String.format(
									"[%s] Successfully authenticated MultiAccount with chosen id: [%s]",
									this.getClass().getName(), chosenId));
							//this.onSuccess(context, credentials);
							credentials = saml20Credentials;
						}
					}
				}
			}
		} catch (Exception e) {
			Saml20AuthenticationAction.LOGGER.error("Unable to retrieve SAML response from context !", e);
		}

		return credentials;
	}

	/**
	 * Extract the QueryAuthnResponse from context if there is one !
	 * 
	 * @param context
	 * @return the QueryAuthnResponse or null
	 */
	protected QueryAuthnResponse extractAuthnResponseFromContext(final RequestContext context) {
		QueryAuthnResponse authnResp = null;

		// Retrieve the context corresponding SAML response
		HttpServletRequest request = WebUtils.getHttpServletRequest(context);
		Object object = request.getAttribute(Saml20AuthenticationAction.SAML_RESPONSE_DATA_FLOW_SCOPE_KEY);

		// Only SAML Authn Responses need to be processed here !
		if ((object != null) && (object instanceof IIncomingSaml)) {
			final IIncomingSaml incomingSaml = (IIncomingSaml) object;
			final IQuery samlQuery = incomingSaml.getSamlQuery();

			if (samlQuery instanceof QueryAuthnResponse) {
				// Our incoming SAML message is an Authn Response
				authnResp = (QueryAuthnResponse) samlQuery;
			}
		}

		return authnResp;
	}

	/**
	 * Extract the User id choice from context if there is one !
	 *
	 * @param context
	 * @return the QueryAuthnResponse or null
	 */
	protected String extractChosenAccountFromContext(final RequestContext context) {
		// Retrieve the context corresponding id response
		HttpServletRequest request = WebUtils.getHttpServletRequest(context);
		final String eventId = request.getParameter("_eventId");
		if (eventId != null && eventId.equals("performMultiAccountChoice"))
			return request.getParameter(Saml20AuthenticationAction.SAML_MULTIACCOUNT_CHOICE_RESPONSE_DATA_FLOW_SCOPE_KEY);

		return null;
	}

	protected String extractTGTIDFromContext(final RequestContext context) {
		// Retrieve the context corresponding id response
		HttpServletRequest request = WebUtils.getHttpServletRequest(context);
		final String eventId = request.getParameter("_eventId");
		if (eventId != null && eventId.equals("performMultiAccountChoice"))
			return request.getParameter("ticketGrantingTicketId");

		return null;
	}

	protected ISaml20Credentials resolveMultiAccount(RequestContext context, final ISaml20Credentials credentials) {
		if (IMultiAccountCredential.class.isAssignableFrom(credentials.getClass())) {
			LOGGER.debug(String.format("Entering on resolving a MultiAccount Authentication with credentials [%s]!", credentials));
			credentials.setAuthenticationStatus(AuthenticationStatusEnum.EMPTY_CREDENTIAL);
			if (!CollectionUtils.isEmpty(((IMultiAccountCredential)credentials).getFederatedIds())) {
				credentials.setAuthenticationStatus(AuthenticationStatusEnum.NO_ACCOUNT);
				for (IMultiAccountFilterRetrieverHandler accountHandler: this.multiAccountRetriever) {
					if (accountHandler.supports(credentials)) {
						Pair<List<String>, List<Map<String, List<String>>>> result = accountHandler.retrieveAccounts(credentials);
						final List<String> resolvedIds = result != null ? result.getFirst() : null;
						final List<Map<String, List<String>>> resolvedAccounts = result != null ? result.getSecond() : null;
						LOGGER.debug(String.format("MultiAccount credentials returned available account ids [%s] from [%s]!",resolvedIds, credentials.getAttributeValues()));
						if (!CollectionUtils.isEmpty(resolvedIds)) {
							((IMultiAccountCredential) credentials).setResolvedPrincipalIds(resolvedIds);
							if (resolvedIds.size() == 1) {
								credentials.setResolvedPrincipalId(resolvedIds.get(0));
								credentials.setAuthenticationStatus(AuthenticationStatusEnum.AUTHENTICATED);
								((IMultiAccountCredential) credentials).setUserChooseId(credentials.getResolvedPrincipalId());
								LOGGER.info(String.format(
										"[%s] Successfully authenticated SAML 2.0 Response with retrieved ids: [%s]",
										accountHandler.getName(), resolvedIds));
							} else {
								Assert.notEmpty(resolvedAccounts, "Multi accounts resolved is empty");
								credentials.setAuthenticationStatus(AuthenticationStatusEnum.MULTIPLE_ACCOUNTS);
								List<Map<String, List<String>>> conpletedAccounts = new ArrayList<Map<String, List<String>>>();
								for (Map<String, List<String>> account: resolvedAccounts) {
									conpletedAccounts.add(structureInformations.applyStructureName(account));
								}
								context.getFlowScope().put(SAML_MULTIACCOUNT_CHOICE_FLOW_SCOPE_KEY, conpletedAccounts);
								LOGGER.info(String.format(
										"[%s] Successfully authenticated SAML 2.0 Response with a Multi Account State and retrieved ids: [%s]",
										accountHandler.getClass().getSimpleName(), resolvedIds));
							}
						}
					}
				}
			}
		}
		return credentials;
	}

	/**
	 * After successful SAML authentication, register the credentials for later use.
	 */
	@Override
	protected void onSuccess(final RequestContext context, final Credentials credentials) {
		ISaml20Credentials samlCredentials = (ISaml20Credentials) credentials;
		String tgtId = WebUtils.getTicketGrantingTicketId(context);

		Assert.notNull(tgtId, "The TGT Id cannot be null here !");

		context.getFlowScope().put("ticketGrantingTicketId", tgtId);

		this.saml2Facade.storeAuthCredentialsInCache(tgtId , samlCredentials);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();

		//Assert.notNull(this.emailAttributeFriendlyName, "No email attribute friendly name provided !");
		Assert.notNull(this.saml2Facade, "SAML 2.0 Facade wasn't injected !");
		Assert.notNull(this.structureInformations, "Property structureInformations wasn't defined !");
	}

	public ISaml20Facade getSaml2Facade() {
		return this.saml2Facade;
	}

	public void setSaml2Facade(final ISaml20Facade saml2Facade) {
		this.saml2Facade = saml2Facade;
	}

	public ISaml20CredentialsAdaptors<ISaml20Credentials, Credentials> getSamlCredsAdaptator() {
		return samlCredsAdaptator;
	}

	public void setSamlCredsAdaptator(final ISaml20CredentialsAdaptors<ISaml20Credentials, Credentials> samlCredsAdaptator) {
		this.samlCredsAdaptator = samlCredsAdaptator;
	}

	public List<IMultiAccountFilterRetrieverHandler> getMultiAccountRetriever() {
		return multiAccountRetriever;
	}

	public void setMultiAccountRetriever(final List<IMultiAccountFilterRetrieverHandler> multiAccountRetriever) {
		this.multiAccountRetriever = multiAccountRetriever;
	}

	public IStructureInformations getStructureInformations() {
		return structureInformations;
	}

	public void setStructureInformations(final IStructureInformations structureInformations) {
		this.structureInformations = structureInformations;
	}
}
