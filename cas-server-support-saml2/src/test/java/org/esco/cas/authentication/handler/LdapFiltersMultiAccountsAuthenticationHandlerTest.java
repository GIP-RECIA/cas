package org.esco.cas.authentication.handler;

import org.esco.cas.authentication.handler.support.MultiValuedSaml20CredentialsHandler;
import org.esco.cas.authentication.principal.MultiValuedAttributeCredentials;
import org.esco.cas.authentication.principal.Saml20Credentials;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

@RunWith(value= BlockJUnit4ClassRunner.class)
public class LdapFiltersMultiAccountsAuthenticationHandlerTest {

    private static final String authenticationAllValuesFilter = "(&(|(ObjectClass=ENTEleve)(ObjectClass=ENTAuxPersRelEleve)) (ENTPersonJointure=AC-ORLEANS-TOURS$%u))";
    private static final String authenticationMergedAccountFilter = "(&(|(ObjectClass=ENTEleve)(ObjectClass=ENTAuxPersRelEleve)) (EduConnectJointure=%u))";

    private static final String mergedCredentialPattern = "\\{ECT-ENT\\}([a-z0-9]{12,})";
    private static final String accountsCredentialPattern = "\\{AAF\\}[0-9A-Z|]+\\|([0-9]+)";

    private static final int groupPatternOfMergedCredentialToExtract = 1;
    private static final int groupPatternOfAccountsCredentialToExtract = 1;

    private static LdapFiltersMultiAccountsAuthenticationHandler multiAccountFilter;

    private static MultiValuedAttributeCredentials credential;

    @BeforeClass
    public static void setUp() throws Exception {
        multiAccountFilter = new LdapFiltersMultiAccountsAuthenticationHandler();
        multiAccountFilter.setAuthenticationAllValuesFilter(authenticationAllValuesFilter);
        multiAccountFilter.setAuthenticationMergedAccountFilter(authenticationMergedAccountFilter);
        multiAccountFilter.setMergedCredentialPattern(mergedCredentialPattern);
        multiAccountFilter.setAccountsCredentialPattern(accountsCredentialPattern);
        multiAccountFilter.setGroupPatternOfAccountsCredentialToExtract(groupPatternOfAccountsCredentialToExtract);
        multiAccountFilter.setGroupPatternOfMergedCredentialToExtract(groupPatternOfMergedCredentialToExtract);

        multiAccountFilter.setPrincipalAttributeName("uid");

        multiAccountFilter.afterPropertiesSet();

        credential = new MultiValuedAttributeCredentials();
        ArrayList<String> credsVals = new ArrayList<String>();
        credsVals.add("{ECT-ENT}731cc7cddb3ef14bd245226a549335840a2b78ff62d6cb9b4e87ccf311888237d3ce0592906ead11451530bb9ea96339");
        credsVals.add("{ECT}f788997b067eb34d08595de6015b2ba7b8d74fb6753b640ffb33c94efcb89fe10b5016509344d6cc9b3ad4cc35449b6f");
        credsVals.add("{AAF}18|AC2D|1814477");
        credsVals.add("{AAF}36|AC2D|181");
        credential.setAttributeValues(credsVals);
    }

    @Test
    public void extractCredentialsOfNotMergedAccount() {
       List<String> ids = multiAccountFilter.extractCredentialsOfNotMergedAccount(credential);
       Assert.notEmpty(ids, "Pattern to extract account didn't provide an id");
       Assert.isTrue(ids.size() == 2);
       ArrayList<String> credsVals = new ArrayList<String>();
       credsVals.add("1814477");
       credsVals.add("181");
       Assert.isTrue(ids.equals(credsVals), "Pattern to extract accounts returned wrong values");
    }

    @Test
    public void extractCredentialOfMergedAccount() {
        String id = multiAccountFilter.extractCredentialOfMergedAccount(credential);
        Assert.hasText(id, "Pattern to extract merged account didn't provide an id");
        Assert.isTrue(id.equals("731cc7cddb3ef14bd245226a549335840a2b78ff62d6cb9b4e87ccf311888237d3ce0592906ead11451530bb9ea96339"), "Pattern to extract merged account returned wrong values");
    }
}