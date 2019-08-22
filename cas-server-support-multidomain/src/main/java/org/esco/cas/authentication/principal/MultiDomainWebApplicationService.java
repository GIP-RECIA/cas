 package org.esco.cas.authentication.principal;
 
 import java.util.Map;
 import java.util.Set;
 import org.esco.cas.CasHelper;
 import org.esco.cas.multidomain.IMultiDomainConfig;
 import org.esco.cas.services.MultiDomainService;
 import org.jasig.cas.authentication.principal.Principal;
 import org.jasig.cas.authentication.principal.Response;
 import org.jasig.cas.authentication.principal.Response.ResponseType;
 import org.jasig.cas.authentication.principal.Service;
 import org.jasig.cas.authentication.principal.WebApplicationService;
 import org.springframework.util.Assert;
 import org.springframework.util.StringUtils;
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 public class MultiDomainWebApplicationService
   implements WebApplicationService
 {
   private static final long serialVersionUID = 2390711275062773675L;
   private WebApplicationService simpleService;
   private MultiDomainService multiDomainService;
   private String domainToRedirect;
   private String idDomainRedirected;
   
   public MultiDomainWebApplicationService(WebApplicationService service, MultiDomainService multiDomainService)
   {
     Assert.notNull(service, "No service provided !");
     Assert.notNull(multiDomainService, "No multi domain service provided");
     
     this.simpleService = service;
     this.multiDomainService = multiDomainService;
   }
   
   public void setPrincipal(Principal principal)
   {
     this.simpleService.setPrincipal(principal);
   }
   
   public boolean logOutOfService(String sessionIdentifier)
   {
     return this.simpleService.logOutOfService(sessionIdentifier);
   }
   
 
 
 
 
   public boolean matches(Service service)
   {
     String serviceDomain = null;
     
     if (service != null) {
       String serviceId = service.getId();
       if (StringUtils.hasText(serviceId)) {
         serviceDomain = CasHelper.extractDomainName(serviceId);
       }
     }
     
     Set<String> authorizedDomains = this.multiDomainService.getMultiDomainConfig().getDomains();
     
     return (serviceDomain != null) && (authorizedDomains.contains(serviceDomain));
   }
   
 
 
 
 
   public void setDomainToRedirect(String domainToRedirect)
   {
     this.domainToRedirect = domainToRedirect;
     
     if (StringUtils.hasText(domainToRedirect)) {
       this.idDomainRedirected = CasHelper.replaceUrlDomain(this.simpleService.getId(), domainToRedirect);
     }
   }
   
 
   public String getId()
   {
     String id = null;
     
     if (StringUtils.hasText(this.idDomainRedirected)) {
       id = this.idDomainRedirected;
     } else {
       id = this.simpleService.getId();
     }
     
     return id;
   }
   
   public Map<String, Object> getAttributes()
   {
     return this.simpleService.getAttributes();
   }
   
 
 
 
   public Response getResponse(String ticketId)
   {
     Response response = this.simpleService.getResponse(ticketId);
     
     if ((response != null) && (StringUtils.hasText(this.domainToRedirect)))
     {
       Response redirectedResponse = null;
       
       String responseUrl = response.getUrl().replaceAll("\\?.*$", "");
       String domainRedirectedUrl = CasHelper.replaceUrlDomain(responseUrl, this.domainToRedirect);
       if (Response.ResponseType.POST == response.getResponseType()) {
         redirectedResponse = Response.getPostResponse(domainRedirectedUrl, response.getAttributes());
       } else {
         redirectedResponse = Response.getRedirectResponse(domainRedirectedUrl, response.getAttributes());
       }
       
       if (redirectedResponse != null) {
         response = redirectedResponse;
       }
     }
     
     return response;
   }
   
   public String getArtifactId()
   {
     return this.simpleService.getArtifactId();
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/authentication/principal/MultiDomainWebApplicationService.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */