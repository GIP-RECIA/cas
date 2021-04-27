package org.esco.cas.multidomain.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.validation.constraints.NotNull;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.CasHelper;
import org.esco.cas.authentication.principal.MultiDomainWebApplicationService;
import org.esco.cas.helper.TicketHelper;
import org.esco.cas.multidomain.IMultiDomainFacade;
import org.esco.cas.multidomain.IStructureInformations;
import org.esco.cas.services.MultiDomainService;
import org.esco.ldap.LdapHelper;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.webflow.execution.RequestContextHolder;

public class MultiDomainFacade implements IMultiDomainFacade, IStructureInformations, InitializingBean {
    private static final Log LOGGER = LogFactory.getLog(MultiDomainFacade.class);


    private static final int DEFAULT_MAX_NUMBER_OF_RESULTS = 1000;


    private static final int DEFAULT_TIMEOUT = 30000;


    private static final int DEFAULT_SCOPE = 2;


    private int maxResultsNumber = 1000;


    private int timeout = 30000;


    private int scope = 2;


    private Map<String, Set<String>> uaiDomainNameMapping;

    private Map<String, String> uaiNameMapping;


    private LdapTemplate ldapTemplate;


    private String base;


    private String filter;


    private String structureUaiLdapField;


    private String structureDomainLdapField;

    private String structureNameLdapField;


    private String peopleDnLdapField;


    private String peopleUaiLdapField;


    private String peopleDomainsLdapField;


    @NotNull
    private ServicesManager servicesManager;


    private TicketRegistry ticketRegistry;


    private Map<String, String> alternateDomainNames;


    public MultiDomainWebApplicationService buildMultiDomainWebAppService(WebApplicationService service) {
        MultiDomainWebApplicationService mdWebAppService = null;

        MultiDomainService mdService = (MultiDomainService)CasHelper.findRegisteredService(this.servicesManager, service, MultiDomainService.class);
        if (mdService != null) {
            mdWebAppService = new MultiDomainWebApplicationService(service, mdService);
        }

        return mdWebAppService;
    }

    public void redirectServiceToAuthorizedDomain() {
        RequestContext context = RequestContextHolder.getRequestContext();
        Service service = WebUtils.getService(context);

        if ((service != null) && ((service instanceof MultiDomainWebApplicationService))) {
            LOGGER.debug("Check if the MultiDomainService need to be redirect...");

            MultiDomainWebApplicationService mdwaService = (MultiDomainWebApplicationService)service;
            MultiDomainService mdService = (MultiDomainService)CasHelper.findRegisteredService(this.servicesManager, service, MultiDomainService.class);
            if (mdService != null) {
                String currentServiceId = service.getId();
                String tgtId = WebUtils.getTicketGrantingTicketId(context);

                Set<String> serviceDomainNameToRedirect = findAuthorizedDomainToRedirect(tgtId, mdService);
                String currentDomain = CasHelper.extractDomainName(currentServiceId);
                if (!serviceDomainNameToRedirect.isEmpty() && !serviceDomainNameToRedirect.contains(currentDomain)) {
                    mdwaService.setDomainToRedirect((String)org.apache.commons.collections.CollectionUtils.get(serviceDomainNameToRedirect, 0));
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug(String.format("MultiDomainService [%s] is redirected to authorized domain name [%s].",
                                currentServiceId, serviceDomainNameToRedirect.toString()));
                    }
                }
            }
        }
    }

    public String getStructureName(final String uai){
        if (StringUtils.hasText(uai)) {
            return this.uaiNameMapping.get(uai);
        }
        return null;
    }

    public Map<String, List<String>> applyStructureName(final Map<String, List<String>> userInfos){
        if (userInfos != null && userInfos.containsKey(this.getPeopleUaiLdapField())) {
            Map<String, List<String>> user = userInfos;
            String structureName = this.getStructureName(userInfos.get(this.getPeopleUaiLdapField()).get(0));
            if (StringUtils.hasText(structureName)) {
                List<String> struct = new ArrayList<String>();
                struct.add(structureName);
                user.put("structureName", struct);
            }
            return user;
        }
        return null;
    }

    protected boolean checkServiceAuthorizations(String tgtId, String serviceUrl) {
        boolean authOk = false;

        String serviceDomainName = CasHelper.extractDomainName(serviceUrl);

        if (StringUtils.hasText(serviceDomainName)) {
            LoginInformations infos = loadLoginInformations(tgtId);

            if (infos != null) {
                authOk = infos.checkServiceDomainName(serviceDomainName);
            }
        }

        return authOk;
    }

    protected Set<String> findAuthorizedDomainToRedirect(String tgtId, MultiDomainService service) {
        LOGGER.debug("Searching for an authorized domain name to redirect...");
        Set<String> serviceDomainNameToRedirect = null;

        LoginInformations infos = loadLoginInformations(tgtId);
        Set<String> uaiDomainNames;
        if (infos != null) {
            String sessionUai = infos.getSessionUai();
            if (StringUtils.hasText(sessionUai)) {
                uaiDomainNames = (Set<String>)this.uaiDomainNameMapping.get(sessionUai);

                // For env test to override specific domains
                if (this.alternateDomainNames != null) {
                    Set<String> overridedDomains = new HashSet<String>();
                    for (String domain: uaiDomainNames) {
                        for (Map.Entry<String, String> entry : this.alternateDomainNames.entrySet()) {
                            if (entry.getValue().equals(domain)) {
                                overridedDomains.add(entry.getKey());
                                break;
                            }
                        }
                    }
                    if (!CollectionUtils.isEmpty(overridedDomains)) {
                        uaiDomainNames = overridedDomains;
                        LOGGER.debug(String.format("Found an alternate domain list to redirect (test env. feature): [%s]", uaiDomainNames.toString()));
                    }
                }

                final List<String> commonDomaines = (List<String>)org.apache.commons.collections.CollectionUtils.intersection(service.getMultiDomainConfig().getDomains(),uaiDomainNames);

                if (!CollectionUtils.isEmpty(commonDomaines)) {
                    serviceDomainNameToRedirect = new HashSet<String>(commonDomaines);
                    LOGGER.debug(String.format("Found a domain list to redirect: [%s]", serviceDomainNameToRedirect.toString()));
                } else {
                    LOGGER.error(String.format("No domain found to redirect from: [%s]", uaiDomainNames.toString()));
                }
            }
        }

        return serviceDomainNameToRedirect;
    }

    protected LoginInformations loadLoginInformations(String tgtId) {
        LoginInformations loginInfos = null;

        String userCurrentUai = null;
        String userDn = null;
        Collection<String> userAuthorizedDomains = null;

        TicketGrantingTicket tgt = TicketHelper.findRootTgt(this.ticketRegistry, tgtId);
        if (tgt != null) {
            List<String> userCurrentUaiValues = TicketHelper.findAttributeValuesInTgt(tgt, this.peopleUaiLdapField);
            if (!CollectionUtils.isEmpty(userCurrentUaiValues)) {
                userCurrentUai = (String)userCurrentUaiValues.iterator().next();
            }
            LOGGER.debug(String.format("User current UAI: [%s]", userCurrentUai));

            List<String> domainsValues = TicketHelper.findAttributeValuesInTgt(tgt, this.peopleDomainsLdapField);
            if (!CollectionUtils.isEmpty(domainsValues)) {
                userAuthorizedDomains = new HashSet();
                userAuthorizedDomains.addAll(domainsValues);
            }
            LOGGER.debug(String.format("User authorized Domains: [%s]", userAuthorizedDomains.toString()));

            List<String> userCurrentDnValues = TicketHelper.findAttributeValuesInTgt(tgt, this.peopleDnLdapField);
            if (!CollectionUtils.isEmpty(userCurrentDnValues)) {
                userDn = (String)userCurrentDnValues.iterator().next();
            }
            LOGGER.debug(String.format("User Dn: [%s]", new Object[] { userDn }));
        }

        if ((StringUtils.hasText(userDn)) && (StringUtils.hasText(userCurrentUai)) && (!CollectionUtils.isEmpty(userAuthorizedDomains))) {
            loginInfos = new LoginInformations();
            loginInfos.setAuthorizedDomains(userAuthorizedDomains);
            loginInfos.setDistinguishedName(userDn);
            loginInfos.setSessionUai(userCurrentUai);
        } else if (StringUtils.hasText(userDn)) {
            String authDomains = "null";
            if (userAuthorizedDomains != null) {
                authDomains = userAuthorizedDomains.toString();
            }

            LOGGER.warn(String.format("Unable to find all login informations in principal attributes ! dn: [%s] current UAI: [%s] authorized domains: [%s]",
                    new Object[] { userDn, userCurrentUai, authDomains }));
        }
        return loginInfos;
    }

    protected void loadUaiDomainNameMapping() {
        this.uaiDomainNameMapping = new HashMap<String, Set<String>>();
        this.uaiNameMapping = new HashMap<String, String>();

        String[] attributes = { this.structureUaiLdapField, this.structureDomainLdapField, this.structureNameLdapField };
        SearchControls searchControls = buildSearchControls();
        List<Attributes> attributesList = LdapHelper.ldapSearch(this.ldapTemplate, this.base, this.filter, attributes, searchControls);

        if (!CollectionUtils.isEmpty(attributesList)) {
            for (Attributes attrs : attributesList) {
                Attribute uaiAttr = attrs.get(this.structureUaiLdapField);
                Attribute domainAttr = attrs.get(this.structureDomainLdapField);
                Attribute nameAttr = attrs.get(this.structureNameLdapField);

                if ((uaiAttr != null) && (domainAttr != null) && nameAttr != null) {
                    try {
                        final String uai = (String)uaiAttr.get();

                        if (StringUtils.hasText(uai)) {

                            final String name = (String)nameAttr.get();

                            Set<String> domains = new HashSet<String>();
                            for (NamingEnumeration<String> ae = (NamingEnumeration<String>)domainAttr.getAll(); ae.hasMore();) {
                                final String val = (String) ae.next();
                                if (StringUtils.hasText(val)) {
                                    domains.add(val);
                                }
                            }

                            if (!CollectionUtils.isEmpty(domains)) {
                                this.uaiDomainNameMapping.put(uai, domains);
                            }
                            if (StringUtils.hasText(name)){
                                this.uaiNameMapping.put(uai, name);
                            }
                        }
                    } catch (Exception e) {
                        LOGGER.warn("Error while building UAI -> Domain name mapping !", e);
                    }
                }
            }
        }
    }

    protected SearchControls buildSearchControls() {
        SearchControls constraints = new SearchControls();
        constraints.setSearchScope(this.scope);
        constraints.setTimeLimit(this.timeout);
        constraints.setCountLimit(this.maxResultsNumber);

        return constraints;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.ldapTemplate, "LDAP template not injected !");
        Assert.notNull(this.base, "LDAP base not configured !");
        Assert.notNull(this.filter, "LDAP filter not configured !");
        Assert.notNull(this.structureUaiLdapField, "LDAP structure UAI field not configured !");
        Assert.notNull(this.structureDomainLdapField, "LDAP structure Domain name field not configured !");
        Assert.notNull(this.peopleUaiLdapField, "LDAP people UAI field not configured !");
        Assert.notNull(this.peopleDomainsLdapField, "LDAP people Domain name field not configured !");
        Assert.notNull(this.servicesManager, "Services manager not injected !");
        Assert.notNull(this.ticketRegistry, "Ticket registry not injected !");
        Assert.notNull(this.structureNameLdapField, "LDAP Structure Name fiels not configured !");

        loadUaiDomainNameMapping();

        Assert.notEmpty(this.uaiDomainNameMapping, "No UAI -> Domain name mapping found !");
        Assert.notEmpty(this.uaiNameMapping, "No UAI -> Name mapping found !");

        if (!CollectionUtils.isEmpty(this.alternateDomainNames)) {
            LOGGER.warn(String.format("Using an alternate domain names map. This feature is for test environment purpose only ! Map : [%s]", new Object[] { this.alternateDomainNames }));
        }
    }

    public int getMaxResultsNumber()
    {
        return this.maxResultsNumber;
    }

    public void setMaxResultsNumber(int maxResultsNumber) {
        this.maxResultsNumber = maxResultsNumber;
    }

    public int getTimeout() {
        return this.timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getScope() {
        return this.scope;
    }

    public void setScope(int scope) {
        this.scope = scope;
    }

    public LdapTemplate getLdapTemplate() {
        return this.ldapTemplate;
    }

    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public String getBase() {
        return this.base;
    }

    public void setBase(String base) {
        this.base = base;
    }

    public String getFilter() {
        return this.filter;
    }

    public void setFilter(String filter) {
        this.filter = filter;
    }

    public String getStructureUaiLdapField() {
        return this.structureUaiLdapField;
    }

    public void setStructureUaiLdapField(String structureUaiLdapField) {
        this.structureUaiLdapField = structureUaiLdapField;
    }

    public String getStructureDomainLdapField() {
        return this.structureDomainLdapField;
    }

    public void setStructureDomainLdapField(String structureDomainLdapField) {
        this.structureDomainLdapField = structureDomainLdapField;
    }

    public String getPeopleDnLdapField() {
        return this.peopleDnLdapField;
    }

    public void setPeopleDnLdapField(String peopleDnLdapField) {
        this.peopleDnLdapField = peopleDnLdapField;
    }

    public String getPeopleUaiLdapField() {
        return this.peopleUaiLdapField;
    }

    public void setPeopleUaiLdapField(String peopleUaiLdapField) {
        this.peopleUaiLdapField = peopleUaiLdapField;
    }

    public String getPeopleDomainsLdapField() {
        return this.peopleDomainsLdapField;
    }

    public void setPeopleDomainsLdapField(String peopleDomainsLdapField) {
        this.peopleDomainsLdapField = peopleDomainsLdapField;
    }

    public ServicesManager getServicesManager() {
        return this.servicesManager;
    }

    public void setServicesManager(ServicesManager servicesManager) {
        this.servicesManager = servicesManager;
    }

    public TicketRegistry getTicketRegistry() {
        return this.ticketRegistry;
    }

    public void setTicketRegistry(TicketRegistry ticketRegistry) {
        this.ticketRegistry = ticketRegistry;
    }

    public Map<String, String> getAlternateDomainNames() {
        return this.alternateDomainNames;
    }

    public void setAlternateDomainNames(Map<String, String> alternateDomainNames) {
        this.alternateDomainNames = alternateDomainNames;
    }

    public String getStructureNameLdapField() {
        return structureNameLdapField;
    }

    public void setStructureNameLdapField(String structureNameLdapField) {
        this.structureNameLdapField = structureNameLdapField;
    }
}
