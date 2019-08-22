 package org.esco.cas.web.support;
 
 import java.util.List;
 import javax.servlet.http.HttpServletRequest;
 import org.jasig.cas.authentication.principal.WebApplicationService;
 import org.jasig.cas.web.support.ArgumentExtractor;
 import org.springframework.beans.factory.InitializingBean;
 import org.springframework.util.Assert;
 
 
 
 
 
 
 
 
 
 
 
 
 public class MultipleArgumentExtractorWrapper
   implements ArgumentExtractor, InitializingBean
 {
   private List<ArgumentExtractor> argumentExtractors;
   
   public WebApplicationService extractService(HttpServletRequest request)
   {
     for (ArgumentExtractor extractor : this.argumentExtractors) {
       WebApplicationService service = extractor.extractService(request);
       if (service != null) {
         return service;
       }
     }
     
     return null;
   }
   
   public void afterPropertiesSet() throws Exception
   {
     Assert.notEmpty(this.argumentExtractors, "No argument extractors provided !");
   }
   
   public List<ArgumentExtractor> getArgumentExtractors() {
     return this.argumentExtractors;
   }
   
   public void setArgumentExtractors(List<ArgumentExtractor> argumentExtractors) {
     this.argumentExtractors = argumentExtractors;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/web/support/MultipleArgumentExtractorWrapper.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */