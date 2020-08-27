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
package org.jasig.cas.web.view;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.MutableAuthentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SamlService;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.jasig.cas.validation.Assertion;
import org.jasig.cas.validation.ImmutableAssertionImpl;
import org.jasig.cas.web.view.OldSaml10SuccessResponseView;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=BlockJUnit4ClassRunner.class)
public class OldSaml10SuccessResponseViewTest {

	private OldSaml10SuccessResponseView responseView;

	private static final String MOCK_SERVICE_ID = "https://service.De.Test.eu/truc";

	private static final String PRINCIPAL_ID = "uid_de_test";

	private static final Map<String, Object> PRINCIPAL_ATTRS = new HashMap<String, Object>();

	private static final String ATTR1_KEY = "ATTR1_KEY";

	private static final String ATTR1_VAL = "ATTR1_VAL";

	private static final String ATTR2_KEY = "ATTR2_KEY";

	private static final List<String> ATTR2_VAL = new ArrayList<String>();

	private static final String ATTR21_VAL = "ATTR21_VAL";

	private static final String ATTR22_VAL = "ATTR22_VAL";

	private static final String CONST_PARAM_SERVICE = "TARGET";

	private static final String PRONOTE_SAML_REQUEST = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"> "
			+"<SOAP-ENV:Header/>  <SOAP-ENV:Body>    <samlp:Request xmlns:samlp=\"urn:oasis:names:tc:SAML:1.0:protocol\" MajorVersion=\"1\" MinorVersion=\"1\" "
			+"RequestID=\"{F4DBBA7E-C350-0D1B-7F3C-99A1BB50793F}\" IssueInstant=\"2012-08-30T15:32:31.444+02:00\"> "
			+"<samlp:AssertionArtifact>ST-19-aaeqGpxAJaLcuWccytYS-lycees.netocentre.fr</samlp:AssertionArtifact> </samlp:Request>  </SOAP-ENV:Body></SOAP-ENV:Envelope>";

	@BeforeClass
	public static void initClass() {
		// Init params
		OldSaml10SuccessResponseViewTest.PRINCIPAL_ATTRS.put(OldSaml10SuccessResponseViewTest.ATTR1_KEY, OldSaml10SuccessResponseViewTest.ATTR1_VAL);
		OldSaml10SuccessResponseViewTest.PRINCIPAL_ATTRS.put(OldSaml10SuccessResponseViewTest.ATTR2_KEY, OldSaml10SuccessResponseViewTest.ATTR2_VAL);

		// Init multi val param
		OldSaml10SuccessResponseViewTest.ATTR2_VAL.add(OldSaml10SuccessResponseViewTest.ATTR21_VAL);
		OldSaml10SuccessResponseViewTest.ATTR2_VAL.add(OldSaml10SuccessResponseViewTest.ATTR22_VAL);
	}

	@Before
	public void initTest() throws ConfigurationException {
		DefaultBootstrap.bootstrap();

		this.responseView = new OldSaml10SuccessResponseView();
		this.responseView.setIssuer("localhost");
	}

	@Test
	public void testBuildSaml10SuccessResponse() throws Throwable {
		Authentication authentication = this.buildAuthentication();
		Assertion assertion = this.buildAssertion(authentication, true);

		String xmlResponse = this.responseView.buildSaml10SuccessResponse(assertion, authentication, null,null);

		Assert.assertNotNull("The xml response cannot be null !", xmlResponse);

	}

	/**
	 * @return
	 */
	private Authentication buildAuthentication() {
		Principal principal = new SimplePrincipal(OldSaml10SuccessResponseViewTest.PRINCIPAL_ID, OldSaml10SuccessResponseViewTest.PRINCIPAL_ATTRS);
		Date date = new Date();
		Authentication auth = new MutableAuthentication(principal, date);

		return auth;
	}

	/**
	 * @return
	 */
	private Assertion buildAssertion(final Authentication authentication, final boolean fromNewLogin) {
		List<Authentication> principals = new ArrayList<Authentication>();
		principals.add(authentication);

		//final String requestBody = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp=\"urn:oasis:names:tc:SAML:1.0:protocol\" MajorVersion=\"1\" MinorVersion=\"1\" RequestID=\"_192.168.16.51.1024506224022\" IssueInstant=\"2002-06-19T17:03:44.022Z\"><samlp:AssertionArtifact>artifact</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>";
		final String requestBody = OldSaml10SuccessResponseViewTest.PRONOTE_SAML_REQUEST;

		Service service = this.buildSamlService(requestBody);

		Assertion assertion = new ImmutableAssertionImpl(principals, service, fromNewLogin);

		return assertion;
	}

	/**
	 * @return
	 */
	private SamlService buildSamlService(final String requestBody) {
		final MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContent(requestBody.getBytes());
		request.setParameter(OldSaml10SuccessResponseViewTest.CONST_PARAM_SERVICE, OldSaml10SuccessResponseViewTest.MOCK_SERVICE_ID);

		final SamlService samlService = SamlService.createServiceFrom(request, null);

		return samlService;
	}

}
