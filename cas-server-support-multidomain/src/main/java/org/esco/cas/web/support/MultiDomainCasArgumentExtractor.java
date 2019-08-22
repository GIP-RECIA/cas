 package org.esco.cas.web.support;
 
 import javax.servlet.http.HttpServletRequest;
 import org.apache.commons.logging.Log;
 import org.apache.commons.logging.LogFactory;
 import org.esco.cas.multidomain.IMultiDomainFacade;
 import org.jasig.cas.authentication.principal.SimpleWebApplicationServiceImpl;
 import org.jasig.cas.authentication.principal.WebApplicationService;
 import org.jasig.cas.web.support.AbstractSingleSignOutEnabledArgumentExtractor;
 import org.springframework.beans.factory.InitializingBean;
 import org.springframework.util.Assert;
 
 
 
 
 
 
 
 
 
 
 
 
 public class MultiDomainCasArgumentExtractor
   extends AbstractSingleSignOutEnabledArgumentExtractor
   implements InitializingBean
 {
   private static final Log LOGGER = LogFactory.getLog(MultiDomainCasArgumentExtractor.class);
   
   private IMultiDomainFacade multiDomainFacade;
   
 
   protected WebApplicationService extractServiceInternal(HttpServletRequest request)
   {
     WebApplicationService service = SimpleWebApplicationServiceImpl.createServiceFrom(request, getHttpClientIfSingleSignOutEnabled());
     
     if (service != null) {
       service = this.multiDomainFacade.buildMultiDomainWebAppService(service);
     }
     
     return service;
   }
   
   public void afterPropertiesSet() throws Exception
   {
     Assert.notNull(this.multiDomainFacade, "MultiDomainFacade wasn't injected !");
   }
   
   public IMultiDomainFacade getMultiDomainFacade()
   {
     return this.multiDomainFacade;
   }
   
   public void setMultiDomainFacade(IMultiDomainFacade multiDomainFacade) {
     this.multiDomainFacade = multiDomainFacade;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/web/support/MultiDomainCasArgumentExtractor.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */