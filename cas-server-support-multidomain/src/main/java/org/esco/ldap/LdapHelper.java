 package org.esco.ldap;
 
 import java.util.List;
 import javax.naming.NamingException;
 import javax.naming.directory.Attributes;
 import javax.naming.directory.SearchControls;
 import org.apache.commons.logging.Log;
 import org.apache.commons.logging.LogFactory;
 import org.springframework.ldap.core.AttributesMapper;
 import org.springframework.ldap.core.LdapTemplate;
 
 
 
 
 
 
 
 
 
 
 
 
 
 public abstract class LdapHelper
 {
   private static final Log LOGGER = LogFactory.getLog(LdapHelper.class);
   
 
 
 
 
 
 
   public static List<Attributes> ldapSearch(LdapTemplate template, String base, String filter, String[] attributes, SearchControls searchControls)
   {
     searchControls.setReturningAttributes(attributes);
     
     AttributesMapper mapper = new AttributesMapper()
     {
       public Object mapFromAttributes(Attributes attrs) throws NamingException
       {
         return attrs;
       }
       
     };
     List<Attributes> result = template.search(base, filter, searchControls, mapper);
     
     if ((LOGGER.isDebugEnabled()) && (result != null)) {
       LOGGER.debug(String.format("Search for base: [%s] filter: [%s] returned %s result(s).", new Object[] { base, filter, Integer.valueOf(result.size()) }));
     }
     
     return result;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/ldap/LdapHelper.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */