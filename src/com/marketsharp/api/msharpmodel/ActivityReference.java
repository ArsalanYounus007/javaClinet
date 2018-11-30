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


import java.util.Date;
import java.util.List;
import msharpmodel.Activity;
import msharpmodel.Company;

/**
* Generated by the generator tool for the OData extension for the Restlet framework.<br>
*
* @see <a href="http://localhost:57241/WcfDataService.svc/$metadata">Metadata of the target OData service</a>
*
*/
public class ActivityReference {

    private boolean appointmentRequired;
    private String companyId;
    private String createdBy;
    private Date createdDateUtc;
    private int id;
    private boolean inquiryRequired;
    private boolean isActive;
    private String lastUpdateBy;
    private Date lastUpdateUtc;
    private String name;
    private List<Activity> activity;
    private Company company;

    /**
     * Constructor without parameter.
     * 
     */
    public ActivityReference() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param id
     *            The identifiant value of the entity.
     */
    public ActivityReference(int id) {
        this();
        this.id = id;
    }

   /**
    * Returns the value of the "appointmentRequired" attribute.
    *
    * @return The value of the "appointmentRequired" attribute.
    */
   public boolean getAppointmentRequired() {
      return appointmentRequired;
   }
   /**
    * Returns the value of the "companyId" attribute.
    *
    * @return The value of the "companyId" attribute.
    */
   public String getCompanyId() {
      return companyId;
   }
   /**
    * Returns the value of the "createdBy" attribute.
    *
    * @return The value of the "createdBy" attribute.
    */
   public String getCreatedBy() {
      return createdBy;
   }
   /**
    * Returns the value of the "createdDateUtc" attribute.
    *
    * @return The value of the "createdDateUtc" attribute.
    */
   public Date getCreatedDateUtc() {
      return createdDateUtc;
   }
   /**
    * Returns the value of the "id" attribute.
    *
    * @return The value of the "id" attribute.
    */
   public int getId() {
      return id;
   }
   /**
    * Returns the value of the "inquiryRequired" attribute.
    *
    * @return The value of the "inquiryRequired" attribute.
    */
   public boolean getInquiryRequired() {
      return inquiryRequired;
   }
   /**
    * Returns the value of the "isActive" attribute.
    *
    * @return The value of the "isActive" attribute.
    */
   public boolean getIsActive() {
      return isActive;
   }
   /**
    * Returns the value of the "lastUpdateBy" attribute.
    *
    * @return The value of the "lastUpdateBy" attribute.
    */
   public String getLastUpdateBy() {
      return lastUpdateBy;
   }
   /**
    * Returns the value of the "lastUpdateUtc" attribute.
    *
    * @return The value of the "lastUpdateUtc" attribute.
    */
   public Date getLastUpdateUtc() {
      return lastUpdateUtc;
   }
   /**
    * Returns the value of the "name" attribute.
    *
    * @return The value of the "name" attribute.
    */
   public String getName() {
      return name;
   }
   /**
    * Returns the value of the "activity" attribute.
    *
    * @return The value of the "activity" attribute.
    */
   public List<Activity> getActivity() {
      return activity;
   }
   
   /**
    * Returns the value of the "company" attribute.
    *
    * @return The value of the "company" attribute.
    */
   public Company getCompany() {
      return company;
   }
   
   /**
    * Sets the value of the "appointmentRequired" attribute.
    *
    * @param appointmentRequired
    *     The value of the "appointmentRequired" attribute.
    */
   public void setAppointmentRequired(boolean appointmentRequired) {
      this.appointmentRequired = appointmentRequired;
   }
   /**
    * Sets the value of the "companyId" attribute.
    *
    * @param companyId
    *     The value of the "companyId" attribute.
    */
   public void setCompanyId(String companyId) {
      this.companyId = companyId;
   }
   /**
    * Sets the value of the "createdBy" attribute.
    *
    * @param createdBy
    *     The value of the "createdBy" attribute.
    */
   public void setCreatedBy(String createdBy) {
      this.createdBy = createdBy;
   }
   /**
    * Sets the value of the "createdDateUtc" attribute.
    *
    * @param createdDateUtc
    *     The value of the "createdDateUtc" attribute.
    */
   public void setCreatedDateUtc(Date createdDateUtc) {
      this.createdDateUtc = createdDateUtc;
   }
   /**
    * Sets the value of the "id" attribute.
    *
    * @param id
    *     The value of the "id" attribute.
    */
   public void setId(int id) {
      this.id = id;
   }
   /**
    * Sets the value of the "inquiryRequired" attribute.
    *
    * @param inquiryRequired
    *     The value of the "inquiryRequired" attribute.
    */
   public void setInquiryRequired(boolean inquiryRequired) {
      this.inquiryRequired = inquiryRequired;
   }
   /**
    * Sets the value of the "isActive" attribute.
    *
    * @param isActive
    *     The value of the "isActive" attribute.
    */
   public void setIsActive(boolean isActive) {
      this.isActive = isActive;
   }
   /**
    * Sets the value of the "lastUpdateBy" attribute.
    *
    * @param lastUpdateBy
    *     The value of the "lastUpdateBy" attribute.
    */
   public void setLastUpdateBy(String lastUpdateBy) {
      this.lastUpdateBy = lastUpdateBy;
   }
   /**
    * Sets the value of the "lastUpdateUtc" attribute.
    *
    * @param lastUpdateUtc
    *     The value of the "lastUpdateUtc" attribute.
    */
   public void setLastUpdateUtc(Date lastUpdateUtc) {
      this.lastUpdateUtc = lastUpdateUtc;
   }
   /**
    * Sets the value of the "name" attribute.
    *
    * @param name
    *     The value of the "name" attribute.
    */
   public void setName(String name) {
      this.name = name;
   }
   /**
    * Sets the value of the "activity" attribute.
    *
    * @param activity"
    *     The value of the "activity" attribute.
    */
   public void setActivity(List<Activity> activity) {
      this.activity = activity;
   }

   /**
    * Sets the value of the "company" attribute.
    *
    * @param company"
    *     The value of the "company" attribute.
    */
   public void setCompany(Company company) {
      this.company = company;
   }

}