 package org.esco.cas.web.flow;
 
 import javax.servlet.http.HttpServletRequest;
 import javax.validation.constraints.NotNull;
 import org.apache.commons.logging.Log;
 import org.apache.commons.logging.LogFactory;
 import org.esco.cas.CasHelper;
 import org.esco.cas.services.MultiDomainService;
 import org.jasig.cas.authentication.principal.WebApplicationService;
 import org.jasig.cas.services.ServicesManager;
 import org.jasig.cas.web.support.WebUtils;
 import org.springframework.util.StringUtils;
 import org.springframework.webflow.action.AbstractAction;
 import org.springframework.webflow.core.collection.MutableAttributeMap;
 import org.springframework.webflow.execution.Event;
 import org.springframework.webflow.execution.RequestContext;
 
 
 
 
 
 
 
 
 
 
 
 public class InitMultiDomainAction
   extends AbstractAction
 {
   private static final Log LOGGER = LogFactory.getLog(InitMultiDomainAction.class);
   
 
   public static final String CURRENT_DOMAIN_NAME_FLOW_SCOPE_PARAM_KEY = "currentDomainName";
   
   @NotNull
   private ServicesManager servicesManager;
   
   private String casCommonDomainName;
   
 
   protected Event doExecute(RequestContext context)
     throws Exception
   {
     storeCurrentMultiDomainName(context);
     
     return success();
   }
   
 
 
 
 
 
 
 
 
   protected void storeCurrentMultiDomainName(RequestContext context)
   {
     String currentDomainName = null;
     
 
     WebApplicationService service = WebUtils.getService(context);
     if (service != null) {
       MultiDomainService mdService = (MultiDomainService)CasHelper.findRegisteredService(this.servicesManager, service, MultiDomainService.class);
       
 
       if (mdService != null) {
         String mdServiceId = mdService.getServiceId();
         currentDomainName = CasHelper.extractDomainName(mdServiceId);
       }
     }
     
 
     if (!StringUtils.hasText(currentDomainName)) {
       currentDomainName = CasHelper.getServiceDomainName();
     }
     
 
     if ((!StringUtils.hasText(currentDomainName)) || (currentDomainName.equals(this.casCommonDomainName))) {
       HttpServletRequest request = CasHelper.retrieveCurrentRequest();
       if (request != null) {
         currentDomainName = request.getServerName();
       }
     }
     
     context.getFlowScope().put("currentDomainName", currentDomainName);
     
 
     LOGGER.debug(String.format("Current domain name is: [%s]", new Object[] { currentDomainName }));
   }
   
   public ServicesManager getServicesManager() {
     return this.servicesManager;
   }
   
   public void setServicesManager(ServicesManager servicesManager) {
     this.servicesManager = servicesManager;
   }
   
   public String getCasCommonDomainName() {
     return this.casCommonDomainName;
   }
   
   public void setCasCommonDomainName(String casCommonDomainName) {
     this.casCommonDomainName = casCommonDomainName;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/web/flow/InitMultiDomainAction.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */