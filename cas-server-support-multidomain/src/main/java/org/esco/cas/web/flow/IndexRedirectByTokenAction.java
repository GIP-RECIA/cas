 package org.esco.cas.web.flow;
 
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
 import java.util.List;
 import java.util.Set;
 import javax.servlet.http.HttpServletRequest;
 import javax.validation.constraints.NotNull;
 import javax.validation.constraints.Size;
 import org.apache.commons.logging.Log;
 import org.apache.commons.logging.LogFactory;
 import org.esco.cas.CasHelper;
 import org.esco.cas.multidomain.IMultiDomainConfig;
 import org.esco.cas.services.IndexRedirectService;
 import org.esco.cas.services.MultiDomainService;
 import org.jasig.cas.authentication.principal.Service;
 import org.jasig.cas.services.ServicesManager;
 import org.jasig.cas.web.support.ArgumentExtractor;
 import org.jasig.cas.web.support.WebUtils;
 import org.springframework.util.Assert;
 import org.springframework.util.StringUtils;
 import org.springframework.webflow.action.AbstractAction;
 import org.springframework.webflow.core.collection.MutableAttributeMap;
 import org.springframework.webflow.execution.Event;
 import org.springframework.webflow.execution.RequestContext;
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 public class IndexRedirectByTokenAction
   extends AbstractAction
 {
   private static final Log LOGGER = LogFactory.getLog(IndexRedirectByTokenAction.class);
   
 
   public static final String REDIRECTION_NEEDED_EVENT_ID = "redirectionNeeded";
   
 
   public static final String URL_TO_REDIRECT_FLOW_SCOPE_PARAM_KEY = "urlToRedirect";
   
 
   private static final String INDEX_REDIRECT_TOKEN_PARAM_NAME = "token";
   
   @NotNull
   private ServicesManager servicesManager;
   
   @NotNull
   @Size(min=1)
   private List<ArgumentExtractor> argumentExtractors;
   
 
   protected void initAction()
     throws Exception
   {
     Assert.notNull(this.servicesManager, "Services manager was'nt injected !");
     Assert.notEmpty(this.argumentExtractors, "No argument extractors provided !");
   }
   
   protected Event doExecute(RequestContext context) throws Exception
   {
     HttpServletRequest request = WebUtils.getHttpServletRequest(context);
     
 
     String byPassRedirection = request.getParameter("bypassRedirect");
     
 
     Service service = WebUtils.getService(this.argumentExtractors, request);
     
     if ((!"ok".equals(byPassRedirection)) && (service != null))
     {
       IndexRedirectService redirectService = (IndexRedirectService)CasHelper.findRegisteredService(this.servicesManager, service, IndexRedirectService.class);
       if (redirectService != null) {
         String url = redirectService.getIndexRedirectUrl();
         
 
         if (MultiDomainService.class.isAssignableFrom(redirectService.getClass())) {
           MultiDomainService mdService = (MultiDomainService)redirectService;
           
 
           String referer = request.getHeader("Referer");
           if (StringUtils.hasText(referer)) {
             String refererDomainName = CasHelper.extractDomainName(referer);
             
             if (mdService.getMultiDomainConfig().getDomains().contains(refererDomainName))
             {
 
               url = CasHelper.replaceUrlDomain(url, refererDomainName);
               if (LOGGER.isDebugEnabled()) {
                 LOGGER.debug(String.format("MultiDomainService [%s] is redirected to index with referer domain name [%s].", new Object[] { Long.valueOf(mdService.getId()), refererDomainName }));
               }
             }
           }
         }
         
 
 
         if ((StringUtils.hasText(url)) && ((redirectService.isForceRedirection()) || (isRedirectionNeeded(request))))
         {
 
           if (LOGGER.isDebugEnabled()) {
             if (redirectService.isForceRedirection()) {
               LOGGER.debug(String.format("Redirection FORCED to url: [%s]", new Object[] { url }));
             }
             
             if (isRedirectionNeeded(request)) {
               LOGGER.debug(String.format("Redirection needed to url: [%s]", new Object[] { url }));
             }
           }
           
 
           context.getFlowScope().put("urlToRedirect", url);
           
           return new Event(this, "redirectionNeeded");
         }
         if (LOGGER.isDebugEnabled()) {
           LOGGER.debug("No redirection needed");
         }
       }
     }
     
 
 
     return no();
   }
   
 
 
 
 
 
 
 
   protected boolean isRedirectionNeeded(HttpServletRequest request)
   {
     Assert.notNull(request, "Request must not be null");
     
     String token = request.getParameter("token");
     
 
     Long currentPeriod = Long.valueOf((System.currentTimeMillis() + 14400000L) / 86400000L);
     
 
     return (!isTokenValid(token, currentPeriod)) && (!isTokenValid(token, Long.valueOf(currentPeriod.longValue() - 1L)));
   }
   
 
 
 
 
 
 
 
   protected boolean isTokenValid(String token, Long period)
   {
     String periodToken = null;
     
     if (StringUtils.hasText(token)) {
       try
       {
         MessageDigest md5Digester = MessageDigest.getInstance("MD5");
         byte[] hashedPeriod = md5Digester.digest(String.valueOf(period).getBytes());
         
         if ((hashedPeriod != null) && (hashedPeriod.length > 0)) {
           StringBuilder sb = new StringBuilder(32);
           for (byte b : hashedPeriod) {
             String hex = Integer.toHexString(b);
             if (hex.length() == 1) {
               sb.append("0");
               sb.append(hex);
             } else {
               sb.append(hex.substring(hex.length() - 2));
             }
           }
           periodToken = sb.toString();
         }
       }
       catch (NoSuchAlgorithmException e) {
         LOGGER.error("Error while attempting to hash token with MD5 !", e);
       }
     }
     
     boolean test = (periodToken != null) && (periodToken.equals(token));
     
     if (LOGGER.isDebugEnabled()) {
       if (test) {
         LOGGER.debug(String.format("Token [%1$s] is valid on period [%2$d]", new Object[] { token, period }));
       }
       else {
         LOGGER.debug(String.format("Token [%1$s] is not valid on period [%2$d]", new Object[] { token, period }));
       }
     }
     
 
 
 
     return test;
   }
   
   public ServicesManager getServicesManager() {
     return this.servicesManager;
   }
   
   public void setServicesManager(ServicesManager servicesManager) {
     this.servicesManager = servicesManager;
   }
   
   public List<ArgumentExtractor> getArgumentExtractors() {
     return this.argumentExtractors;
   }
   
   public void setArgumentExtractors(List<ArgumentExtractor> argumentExtractors) {
     this.argumentExtractors = argumentExtractors;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/web/flow/IndexRedirectByTokenAction.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */