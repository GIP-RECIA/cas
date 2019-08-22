 package org.esco.cas;
 
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 import javax.servlet.http.HttpServletRequest;
 import org.apache.commons.logging.Log;
 import org.apache.commons.logging.LogFactory;
 import org.jasig.cas.authentication.principal.Service;
 import org.jasig.cas.services.RegisteredService;
 import org.jasig.cas.services.ServicesManager;
 import org.springframework.util.StringUtils;
 import org.springframework.web.context.request.ServletRequestAttributes;
 import org.springframework.webflow.core.collection.MutableAttributeMap;
 import org.springframework.webflow.execution.RequestContext;
 
 
 public class CasHelper {
   private static final Log LOGGER = LogFactory.getLog(CasHelper.class);
   
 
   public static final String SERVICE_HTTP_PARAM_KEY = "service";
   
 
   public static final String SEPARATOR = "://";
   
 
   public static final String PROTOCOL_AND_DOMAIN_REGEX = "([^/]+://[^/]+)";
   
   public static final String DOMAIN_REGEX = "://([^/]+)";
   
   public static final Pattern PROTOCOL_PATTERN = Pattern.compile("([^/]+)://");
   
 
   public static final Pattern DOMAIN_PATTERN = Pattern.compile("://([^/]+)");
   
 
   public static final Pattern PATH_PATTERN = Pattern.compile("[^/]+://[^/]+(/.*)");
   
 
   public static final Pattern PROTOCOL_AND_DOMAIN_PATTERN = Pattern.compile("([^/]+://[^/]+)");

 
   public static String replaceUrlDomain(String url, String newDomain)
   {
     String result = "";
     
     if ((StringUtils.hasText(url)) && (StringUtils.hasText(newDomain))) {
       result = url.replaceFirst("://([^/]+)", String.format("://%s", new Object[] { newDomain }));
     }
     
     return result;
   }
   
 
 
 
 
 
   public static String extractServiceDomain(HttpServletRequest request)
   {
     String domainName = null;
     
     if (request != null) {
       String service = request.getParameter("service");
       if (StringUtils.hasText(service)) {
         domainName = extractDomainName(service);
       }
     }
     
     return domainName;
   }
   
   public static String extractDomainName(String url) {
     String domainName = null;
     
     if (StringUtils.hasText(url)) {
       Matcher domainMatcher = DOMAIN_PATTERN.matcher(url);
       if (domainMatcher.find()) {
         domainName = domainMatcher.group(1);
       }
     }
     
     return domainName;
   }
   
 
 
 
 
 
 
   public static <T> T findRegisteredService(ServicesManager servicesManager, Service service, Class<T> clazz)
   {
     T regServcie = null;
     
     if ((servicesManager != null) && (service != null))
     {
       RegisteredService regService = servicesManager.findServiceBy(service);
       
       if ((regService != null) && (clazz != null) && (clazz.isAssignableFrom(regService.getClass()))) {
         if (LOGGER.isDebugEnabled()) {
           LOGGER.debug(String.format("The service is a [%s]", new Object[] { clazz.getName() }));
         }
         regServcie = (T) regService;
       }
     }
     
     return regServcie;
   }
   
   public static String getServiceDomainName() {
     String serviceDomain = null;
     
 
     RequestContext context = org.springframework.webflow.execution.RequestContextHolder.getRequestContext();
     if (context != null) {
       Service service = (Service)context.getFlowScope().get("service");
       if (service != null) {
         String serviceId = service.getId();
         if (StringUtils.hasText(serviceId)) {
           serviceDomain = extractDomainName(serviceId);
         }
       }
     }
     
 
     if (!StringUtils.hasText(serviceDomain)) {
       HttpServletRequest request = retrieveCurrentRequest();
       if (request != null) {
         serviceDomain = extractServiceDomain(request);
       }
     }
     
     return serviceDomain;
   }
   
 
 
 
 
   public static HttpServletRequest retrieveCurrentRequest()
   {
     HttpServletRequest request = null;
     
     ServletRequestAttributes attributes = (ServletRequestAttributes)org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
     if (attributes != null) {
       request = attributes.getRequest();
     }
     
     return request;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/CasHelper.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */