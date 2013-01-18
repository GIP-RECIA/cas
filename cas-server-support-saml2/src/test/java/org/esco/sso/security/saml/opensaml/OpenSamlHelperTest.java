/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.springframework.util.Assert;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=BlockJUnit4ClassRunner.class)
public class OpenSamlHelperTest {

	private static final String REDIRECT_BIND_SAML_REQUEST = "fZJdT4MwFIav9VeQ3vM5ZFsDJNPFuGS6ZaAX3pjSnY0m0GJPMfPfC2zGeUMv 2zfP0/O2MbK6auiiNaXcwWcLaKxTXUmkw0FCWi2pYiiQSlYDUsNptnhe08Dx aKOVUVxVxFoggjZCyQclsa1BZ6C/BIfX3TohpTENUtfdQ61skMY5ikYDF8xR +uhmpSgKVYEpHUTl9vDA3W6ynFjL7jZCsp77R4GT0UyCcRi3la6ASbSNajU6 B+0OhGxDrNUyIR8Q+pyFwWw2DSd+NJ/dHaaTeRhFXsB5VMC8iyG2sJJomDQJ CTw/sL2p7U1yP6DhlPrRO7G2lynvhdwLeRyvpDiHkD7l+dY+j/EGGocRugBJ b2+GFff90sGvrxofp7Pfmkk6XipnGLtXhos1Pr/2SwdeLbeqEvzbelS6Zmbc 2++IvX0YorTvH0XnJG56tvz/QOkP";

	@Test
	public void decodeRedirectBindSamlRequest() throws Exception {
		String decodedRequest = OpenSamlHelper.httpRedirectDecode(OpenSamlHelperTest.REDIRECT_BIND_SAML_REQUEST);

		Assert.notNull(decodedRequest, "Decoded request is null !");

		System.out.println(decodedRequest);
	}

}
