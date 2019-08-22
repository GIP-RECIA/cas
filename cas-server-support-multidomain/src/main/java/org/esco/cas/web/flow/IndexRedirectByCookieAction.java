 package org.esco.cas.web.flow;
 
 import java.util.List;
 import javax.servlet.http.Cookie;
 import javax.servlet.http.HttpServletRequest;
 import javax.validation.constraints.NotNull;
 import javax.validation.constraints.Size;
 import org.apache.commons.logging.Log;
 import org.apache.commons.logging.LogFactory;
 import org.esco.cas.CasHelper;
 import org.esco.cas.services.IndexRedirectService;
 import org.jasig.cas.authentication.principal.Service;
 import org.jasig.cas.services.ServicesManager;
 import org.jasig.cas.web.support.ArgumentExtractor;
 import org.springframework.util.Assert;
 import org.springframework.util.StringUtils;
 import org.springframework.webflow.action.AbstractAction;
 import org.springframework.webflow.core.collection.MutableAttributeMap;
 import org.springframework.webflow.execution.Event;
 import org.springframework.webflow.execution.RequestContext;
 
 
 
 
 
 
 
 
 
 
 
 
 public class IndexRedirectByCookieAction
   extends AbstractAction
 {
   private static final Log LOGGER = LogFactory.getLog(IndexRedirectByCookieAction.class);
   
 
   public static final String REDIRECTION_NEEDED_EVENT_ID = "redirectionNeeded";
   
 
   public static final String URL_TO_REDIRECT_FLOW_SCOPE_PARAM_KEY = "urlToRedirect";
   
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
     HttpServletRequest request = org.jasig.cas.web.support.WebUtils.getHttpServletRequest(context);
     
     Service service = org.jasig.cas.web.support.WebUtils.getService(this.argumentExtractors, request);
     
     if (service != null)
     {
       IndexRedirectService redirectService = (IndexRedirectService)CasHelper.findRegisteredService(this.servicesManager, service, IndexRedirectService.class);
       if (redirectService != null) {
         String url = redirectService.getIndexRedirectUrl();
         
         if ((StringUtils.hasText(url)) && ((redirectService.isForceRedirection()) || (isRedirectionNeeded(request, redirectService.getIndexCookieName()))))
         {
 
           if (LOGGER.isDebugEnabled()) {
             LOGGER.debug(String.format("Redirection needed to url: [%s]", new Object[] { url }));
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
   
 
 
 
 
 
 
 
   private boolean isRedirectionNeeded(HttpServletRequest request, String indexCookieName)
   {
     Assert.notNull(request, "Request must not be null");
     
     Cookie indexCookie = null;
     
     if (StringUtils.hasText(indexCookieName)) {
       indexCookie = org.springframework.web.util.WebUtils.getCookie(request, indexCookieName);
     }
     
     return (StringUtils.hasText(indexCookieName)) && (indexCookie == null);
   }
   
   public ServicesManager getServicesManager()
   {
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


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/web/flow/IndexRedirectByCookieAction.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */