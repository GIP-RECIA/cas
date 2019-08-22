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
package org.esco.cas.web.flow;

import org.esco.cas.ISaml20Facade;
import org.esco.cas.authentication.handler.AuthenticationStatusEnum;
import org.esco.cas.authentication.principal.IMultiAccountCredential;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.support.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.HttpServletRequest;

/**
 * Controller for the Multi Account Choice form. *
 */
public final class AccountChoiceAction extends AbstractAction {

	private static final Logger LOGGER = LoggerFactory.getLogger(AccountChoiceAction.class);

	private static final String ACCOUNT_ID = "_choice_id";

	/** Saml2 Facade. */
	private ISaml20Facade saml2Facade;

	protected Event doExecute(final RequestContext context) {
		LOGGER.debug("AccountChoiceAction !");

		HttpServletRequest request = WebUtils.getHttpServletRequest(context);

		final String id = request.getParameter(ACCOUNT_ID);

		ISaml20Credentials credentials = (ISaml20Credentials)context.getFlowScope().get(Saml20AuthenticationAction.SAML_CREDENTIALS_FLOW_SCOPE_KEY);

		if (IMultiAccountCredential.class.isAssignableFrom(credentials.getClass())) {
			LOGGER.debug(
					String.format("Entering on selecting a MultiAccount Authentication with credentials [%s] and chosen id [%s]!", credentials, id));
			if (!((IMultiAccountCredential)credentials).getResolvedPrincipalIds().contains(id)) return error(
					new IllegalStateException(
							String.format("L'identifiant de multi account choisi [%s] ne fait pas parti de la liste des identifiants autorisés [%s]!",
									id, ((IMultiAccountCredential)credentials).getResolvedPrincipalIds())));
			credentials.setResolvedPrincipalId(id);
			credentials.setAuthenticationStatus(AuthenticationStatusEnum.AUTHENTICATED);
			((IMultiAccountCredential) credentials).setUserChooseId(id);
			LOGGER.info(String.format(
					"[%s] Successfully authenticated MultiAccount with chosen id: [%s]",
					this.getClass().getName(), id));
			//this.onSuccess(context, credentials);
		}
		return success();
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		//Assert.notNull(this.emailAttributeFriendlyName, "No email attribute friendly name provided !");
		Assert.notNull(this.saml2Facade, "SAML 2.0 Facade wasn't injected !");
	}

	public ISaml20Facade getSaml2Facade() {
		return this.saml2Facade;
	}

	public void setSaml2Facade(final ISaml20Facade saml2Facade) {
		this.saml2Facade = saml2Facade;
	}

}
