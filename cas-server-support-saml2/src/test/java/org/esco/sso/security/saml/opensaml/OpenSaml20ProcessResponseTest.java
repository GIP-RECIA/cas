/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import java.io.IOException;

import javax.annotation.Resource;

import org.apache.commons.io.FileUtils;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.SamlProcessingException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:openSaml20SpPrcoessorContext.xml")
public class OpenSaml20ProcessResponseTest {

	private static final String RESOURCE_BASE_PATH = "test";

	@Resource(name="saml20AuthnRequest")
	private ClassPathResource saml20AuthnRequest;

	@Resource(name="saml20Response")
	private ClassPathResource saml20Response;

	@Resource(name="saml20Assertion")
	private ClassPathResource saml20Assertion;

	@Autowired
	private OpenSaml20SpProcessor spProcessor;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test
	public void testDecodeResponse() {
		String response = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9kZW1vLWVudC5naXByZWNpYS5vcmcvY2FzL3NhbWwyIiBJRD0iXzgxZDgzZGRkNzc1NjhjMGE2NWUyODdmMTg0M2YxMTUyIiBJblJlc3BvbnNlVG89Il8yOGFjZTJmOGVlNzc3N2NiY2EzOTBiMmJlYWIyOTU2YTYyY2JiNjMxMjI3NWY2YTFhYjc0OTg2MDAzNWMxYWEwYTcxNWIwNjNiNjE4Y2NiZGYxYTAiIElzc3VlSW5zdGFudD0iMjAxMi0wNC0yNlQxNDoxMToyOS40NDJaIiBWZXJzaW9uPSIyLjAiPjxzYW1sMjpJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL2RlbW8tZW50LmdpcHJlY2lhLm9yZy9pZHAvc2hpYmJvbGV0aDwvc2FtbDI6SXNzdWVyPjxzYW1sMnA6U3RhdHVzPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpSZXNwb25kZXIiLz48c2FtbDJwOlN0YXR1c01lc3NhZ2U+Tm8gc2lnbmluZyBjcmVkZW50aWFsIGF2YWlsYWJsZTwvc2FtbDJwOlN0YXR1c01lc3NhZ2U+PC9zYW1sMnA6U3RhdHVzPjwvc2FtbDJwOlJlc3BvbnNlPg==";

		System.out.println(new String(Base64.decode(response)));
	}

	@Test
	public void testProcessSaml20Response() throws SamlProcessingException, IOException {
		MockHttpServletRequest request = this.BuildSamlMockRequest(this.readFile(this.saml20Response));

		this.spProcessor.processSaml20IncomingRequest(request, SamlBindingEnum.SAML_20_HTTP_POST);
	}

	private String readFile(final org.springframework.core.io.Resource resourceFile) throws IOException {
		return FileUtils.readFileToString(resourceFile.getFile());
	}

	private MockHttpServletRequest BuildSamlMockRequest(final String responseReq) {
		MockHttpServletRequest request = new MockHttpServletRequest(new MockServletContext(OpenSaml20ProcessResponseTest.RESOURCE_BASE_PATH));
		request.setMethod("POST");
		request.setParameter("SAMLRequest", Base64.encodeBytes(responseReq.getBytes()));
		return request;
	}


}
