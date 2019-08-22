 package org.esco.cas.web.flow;
 
 import org.esco.cas.multidomain.IMultiDomainFacade;
 import org.springframework.webflow.action.AbstractAction;
 import org.springframework.webflow.execution.Event;
 import org.springframework.webflow.execution.RequestContext;
 
 
 
 
 
 
 
 
 
 public class GenerateMultiDomainServiceTicketAction
   extends AbstractAction
 {
   AbstractAction generateServiceTicketAction;
   IMultiDomainFacade mdFacade;
   
   protected Event doExecute(RequestContext context)
     throws Exception
   {
     Event defaultResult = this.generateServiceTicketAction.execute(context);
     
     this.mdFacade.redirectServiceToAuthorizedDomain();
     
     return defaultResult;
   }
   
   public AbstractAction getGenerateServiceTicketAction() {
     return this.generateServiceTicketAction;
   }
   
   public void setGenerateServiceTicketAction(AbstractAction generateServiceTicketAction) {
     this.generateServiceTicketAction = generateServiceTicketAction;
   }
   
   public IMultiDomainFacade getMultiDomainFacade() {
     return this.mdFacade;
   }
   
   public void setMultiDomainFacade(IMultiDomainFacade mdFacade) {
     this.mdFacade = mdFacade;
   }
 }


/* Location:              /home/jgribonvald/Téléchargements/cas-server-support-multidomain-1.1.2.jar!/org/esco/cas/web/flow/GenerateMultiDomainServiceTicketAction.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       0.7.1
 */