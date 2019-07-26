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

import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.esco.sso.security.saml.util.SamlHelper;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.flow.AbstractNonInteractiveCredentialsAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.core.collection.MutableAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.naming.directory.Attributes;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Controller to initialize the wayf.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public final class AccountChoiceAction extends AbstractAction {

	private static final Logger LOGGER = LoggerFactory.getLogger(AccountChoiceAction.class);

	private static final String ACCOUNTS_PARAM = "accountsParam";

	@Override
	protected Event doExecute(final RequestContext context) throws Exception {
		final MutableAttributeMap viewScope = context.getViewScope();

		ISaml20Credentials credential = (ISaml20Credentials)context.getFlowScope().get(Saml20AuthenticationAction.SAML_CREDENTIALS_FLOW_SCOPE_KEY);
		LOGGER.debug("AccountChoiceAction !");

		return this.success();
	}
}
