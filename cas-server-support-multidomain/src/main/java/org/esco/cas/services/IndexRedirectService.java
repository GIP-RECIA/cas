 package org.esco.cas.services;
 
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 import org.apache.commons.logging.Log;
 import org.apache.commons.logging.LogFactory;
 import org.jasig.cas.authentication.principal.Service;
 import org.jasig.cas.services.RegisteredServiceImpl;
 import org.springframework.beans.factory.InitializingBean;
 import org.springframework.util.Assert;
 import org.springframework.util.StringUtils;
 
 
 
 
 
 
 
 
 
 
 
 
 public class IndexRedirectService
   extends RegisteredServiceImpl
   implements InitializingBean
 {
   private static final long serialVersionUID = -3601483389214507542L;
   private static final Log LOGGER = LogFactory.getLog(IndexRedirectService.class);
   
 
 
 
   private String indexRedirectUrl;
   
 
 
 
   private String indexCookieName;
   
 
 
 
   private boolean forceRedirection = true;
   
 
   public boolean matches(Service service)
   {
     if (service != null) {
       Pattern p = Pattern.compile(getServiceId(), 2);
       Matcher m = p.matcher(service.getId());
       boolean result = m.find();
       LOGGER.debug("Is service matching between " + getServiceId() + " and " + service.getId() + " returned " + result);
       if (result) {
         return true;
       }
     }
     return false;
   }
   
   public void afterPropertiesSet() throws Exception
   {
     Assert.isTrue((!StringUtils.hasText(this.indexRedirectUrl)) || (StringUtils.hasText(this.indexCookieName)), "Index redirection config need a URL and a cookie name !");
   }
   
 
 
 
 
 
 
   public String getIndexRedirectUrl()
   {
     return this.indexRedirectUrl;
   }
   
 
 
 
 
 
   public void setIndexRedirectUrl(String indexRedirectUrl)
   {
     this.indexRedirectUrl = indexRedirectUrl;
   }
   
 
 
 
 
   public String getIndexCookieName()
   {
     return this.indexCookieName;
   }
   
 
 
 
 
   public void setIndexCookieName(String indexCookieName)
   {
     this.indexCookieName = indexCookieName;
   }
   
 
 
 
 
 
   public boolean isForceRedirection()
   {
     return this.forceRedirection;
   }
   
 
 
 
 
 
   public void setForceRedirection(boolean forceRedirection)
   {
     this.forceRedirection = forceRedirection;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/services/IndexRedirectService.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */