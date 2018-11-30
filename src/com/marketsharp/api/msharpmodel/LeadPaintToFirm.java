/**
 * Copyright 2005-2010 Noelios Technologies.
 * 
 * The contents of this file are subject to the terms of one of the following
 * open source licenses: LGPL 3.0 or LGPL 2.1 or CDDL 1.0 or EPL 1.0 (the
 * "Licenses"). You can select the license that you prefer but you may not use
 * this file except in compliance with one of these Licenses.
 * 
 * You can obtain a copy of the LGPL 3.0 license at
 * http://www.opensource.org/licenses/lgpl-3.0.html
 * 
 * You can obtain a copy of the LGPL 2.1 license at
 * http://www.opensource.org/licenses/lgpl-2.1.php
 * 
 * You can obtain a copy of the CDDL 1.0 license at
 * http://www.opensource.org/licenses/cddl1.php
 * 
 * You can obtain a copy of the EPL 1.0 license at
 * http://www.opensource.org/licenses/eclipse-1.0.php
 * 
 * See the Licenses for the specific language governing permissions and
 * limitations under the Licenses.
 * 
 * Alternatively, you can obtain a royalty free commercial license with less
 * limitations, transferable or non-transferable, directly at
 * http://www.noelios.com/products/restlet-engine
 * 
 * Restlet is a registered trademark of Noelios Technologies.
 */

package msharpmodel;


import msharpmodel.LeadPaint;
import msharpmodel.LeadPaintFirm;

/**
* Generated by the generator tool for the OData extension for the Restlet framework.<br>
*
* @see <a href="http://localhost:57241/WcfDataService.svc/$metadata">Metadata of the target OData service</a>
*
*/
public class LeadPaintToFirm {

    private String firmId;
    private String id;
    private String leadPaintId;
    private LeadPaint leadPaint;
    private LeadPaintFirm leadPaintFirm;

    /**
     * Constructor without parameter.
     * 
     */
    public LeadPaintToFirm() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param id
     *            The identifiant value of the entity.
     */
    public LeadPaintToFirm(String id) {
        this();
        this.id = id;
    }

   /**
    * Returns the value of the "firmId" attribute.
    *
    * @return The value of the "firmId" attribute.
    */
   public String getFirmId() {
      return firmId;
   }
   /**
    * Returns the value of the "id" attribute.
    *
    * @return The value of the "id" attribute.
    */
   public String getId() {
      return id;
   }
   /**
    * Returns the value of the "leadPaintId" attribute.
    *
    * @return The value of the "leadPaintId" attribute.
    */
   public String getLeadPaintId() {
      return leadPaintId;
   }
   /**
    * Returns the value of the "leadPaint" attribute.
    *
    * @return The value of the "leadPaint" attribute.
    */
   public LeadPaint getLeadPaint() {
      return leadPaint;
   }
   
   /**
    * Returns the value of the "leadPaintFirm" attribute.
    *
    * @return The value of the "leadPaintFirm" attribute.
    */
   public LeadPaintFirm getLeadPaintFirm() {
      return leadPaintFirm;
   }
   
   /**
    * Sets the value of the "firmId" attribute.
    *
    * @param firmId
    *     The value of the "firmId" attribute.
    */
   public void setFirmId(String firmId) {
      this.firmId = firmId;
   }
   /**
    * Sets the value of the "id" attribute.
    *
    * @param id
    *     The value of the "id" attribute.
    */
   public void setId(String id) {
      this.id = id;
   }
   /**
    * Sets the value of the "leadPaintId" attribute.
    *
    * @param leadPaintId
    *     The value of the "leadPaintId" attribute.
    */
   public void setLeadPaintId(String leadPaintId) {
      this.leadPaintId = leadPaintId;
   }
   /**
    * Sets the value of the "leadPaint" attribute.
    *
    * @param leadPaint"
    *     The value of the "leadPaint" attribute.
    */
   public void setLeadPaint(LeadPaint leadPaint) {
      this.leadPaint = leadPaint;
   }

   /**
    * Sets the value of the "leadPaintFirm" attribute.
    *
    * @param leadPaintFirm"
    *     The value of the "leadPaintFirm" attribute.
    */
   public void setLeadPaintFirm(LeadPaintFirm leadPaintFirm) {
      this.leadPaintFirm = leadPaintFirm;
   }

}