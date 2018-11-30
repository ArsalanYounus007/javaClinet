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
import msharpmodel.Appointment;
import msharpmodel.Contact;
import msharpmodel.Contract;
import msharpmodel.JobProduct;
import msharpmodel.LeadPaint;
import msharpmodel.Survey;

/**
* Generated by the generator tool for the OData extension for the Restlet framework.<br>
*
* @see <a href="http://localhost:57241/WcfDataService.svc/$metadata">Metadata of the target OData service</a>
*
*/
public class Job {

    private String addressLin2;
    private String addressLine1;
    private String appointmentId;
    private String city;
    private Date completedDate;
    private String contactId;
    private Date createdDate;
    private String description;
    private boolean exportedToGuildQuality;
    private String id;
    private String inquiryId;
    private boolean isActive;
    private Date lastUpdate;
    private String name;
    private String note;
    private String number;
    private Date saleDate;
    private String site;
    private Date startDate;
    private String state;
    private String status;
    private String structureValueCode;
    private String type;
    private String zip;
    private Appointment appointment;
    private Contact contact;
    private List<Contract> contract;
    private List<JobProduct> jobProduct;
    private List<LeadPaint> leadPaint;
    private List<Survey> survey;

    /**
     * Constructor without parameter.
     * 
     */
    public Job() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param id
     *            The identifiant value of the entity.
     */
    public Job(String id) {
        this();
        this.id = id;
    }

   /**
    * Returns the value of the "addressLin2" attribute.
    *
    * @return The value of the "addressLin2" attribute.
    */
   public String getAddressLin2() {
      return addressLin2;
   }
   /**
    * Returns the value of the "addressLine1" attribute.
    *
    * @return The value of the "addressLine1" attribute.
    */
   public String getAddressLine1() {
      return addressLine1;
   }
   /**
    * Returns the value of the "appointmentId" attribute.
    *
    * @return The value of the "appointmentId" attribute.
    */
   public String getAppointmentId() {
      return appointmentId;
   }
   /**
    * Returns the value of the "city" attribute.
    *
    * @return The value of the "city" attribute.
    */
   public String getCity() {
      return city;
   }
   /**
    * Returns the value of the "completedDate" attribute.
    *
    * @return The value of the "completedDate" attribute.
    */
   public Date getCompletedDate() {
      return completedDate;
   }
   /**
    * Returns the value of the "contactId" attribute.
    *
    * @return The value of the "contactId" attribute.
    */
   public String getContactId() {
      return contactId;
   }
   /**
    * Returns the value of the "createdDate" attribute.
    *
    * @return The value of the "createdDate" attribute.
    */
   public Date getCreatedDate() {
      return createdDate;
   }
   /**
    * Returns the value of the "description" attribute.
    *
    * @return The value of the "description" attribute.
    */
   public String getDescription() {
      return description;
   }
   /**
    * Returns the value of the "exportedToGuildQuality" attribute.
    *
    * @return The value of the "exportedToGuildQuality" attribute.
    */
   public boolean getExportedToGuildQuality() {
      return exportedToGuildQuality;
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
    * Returns the value of the "inquiryId" attribute.
    *
    * @return The value of the "inquiryId" attribute.
    */
   public String getInquiryId() {
      return inquiryId;
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
    * Returns the value of the "lastUpdate" attribute.
    *
    * @return The value of the "lastUpdate" attribute.
    */
   public Date getLastUpdate() {
      return lastUpdate;
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
    * Returns the value of the "note" attribute.
    *
    * @return The value of the "note" attribute.
    */
   public String getNote() {
      return note;
   }
   /**
    * Returns the value of the "number" attribute.
    *
    * @return The value of the "number" attribute.
    */
   public String getNumber() {
      return number;
   }
   /**
    * Returns the value of the "saleDate" attribute.
    *
    * @return The value of the "saleDate" attribute.
    */
   public Date getSaleDate() {
      return saleDate;
   }
   /**
    * Returns the value of the "site" attribute.
    *
    * @return The value of the "site" attribute.
    */
   public String getSite() {
      return site;
   }
   /**
    * Returns the value of the "startDate" attribute.
    *
    * @return The value of the "startDate" attribute.
    */
   public Date getStartDate() {
      return startDate;
   }
   /**
    * Returns the value of the "state" attribute.
    *
    * @return The value of the "state" attribute.
    */
   public String getState() {
      return state;
   }
   /**
    * Returns the value of the "status" attribute.
    *
    * @return The value of the "status" attribute.
    */
   public String getStatus() {
      return status;
   }
   /**
    * Returns the value of the "structureValueCode" attribute.
    *
    * @return The value of the "structureValueCode" attribute.
    */
   public String getStructureValueCode() {
      return structureValueCode;
   }
   /**
    * Returns the value of the "type" attribute.
    *
    * @return The value of the "type" attribute.
    */
   public String getType() {
      return type;
   }
   /**
    * Returns the value of the "zip" attribute.
    *
    * @return The value of the "zip" attribute.
    */
   public String getZip() {
      return zip;
   }
   /**
    * Returns the value of the "appointment" attribute.
    *
    * @return The value of the "appointment" attribute.
    */
   public Appointment getAppointment() {
      return appointment;
   }
   
   /**
    * Returns the value of the "contact" attribute.
    *
    * @return The value of the "contact" attribute.
    */
   public Contact getContact() {
      return contact;
   }
   
   /**
    * Returns the value of the "contract" attribute.
    *
    * @return The value of the "contract" attribute.
    */
   public List<Contract> getContract() {
      return contract;
   }
   
   /**
    * Returns the value of the "jobProduct" attribute.
    *
    * @return The value of the "jobProduct" attribute.
    */
   public List<JobProduct> getJobProduct() {
      return jobProduct;
   }
   
   /**
    * Returns the value of the "leadPaint" attribute.
    *
    * @return The value of the "leadPaint" attribute.
    */
   public List<LeadPaint> getLeadPaint() {
      return leadPaint;
   }
   
   /**
    * Returns the value of the "survey" attribute.
    *
    * @return The value of the "survey" attribute.
    */
   public List<Survey> getSurvey() {
      return survey;
   }
   
   /**
    * Sets the value of the "addressLin2" attribute.
    *
    * @param addressLin2
    *     The value of the "addressLin2" attribute.
    */
   public void setAddressLin2(String addressLin2) {
      this.addressLin2 = addressLin2;
   }
   /**
    * Sets the value of the "addressLine1" attribute.
    *
    * @param addressLine1
    *     The value of the "addressLine1" attribute.
    */
   public void setAddressLine1(String addressLine1) {
      this.addressLine1 = addressLine1;
   }
   /**
    * Sets the value of the "appointmentId" attribute.
    *
    * @param appointmentId
    *     The value of the "appointmentId" attribute.
    */
   public void setAppointmentId(String appointmentId) {
      this.appointmentId = appointmentId;
   }
   /**
    * Sets the value of the "city" attribute.
    *
    * @param city
    *     The value of the "city" attribute.
    */
   public void setCity(String city) {
      this.city = city;
   }
   /**
    * Sets the value of the "completedDate" attribute.
    *
    * @param completedDate
    *     The value of the "completedDate" attribute.
    */
   public void setCompletedDate(Date completedDate) {
      this.completedDate = completedDate;
   }
   /**
    * Sets the value of the "contactId" attribute.
    *
    * @param contactId
    *     The value of the "contactId" attribute.
    */
   public void setContactId(String contactId) {
      this.contactId = contactId;
   }
   /**
    * Sets the value of the "createdDate" attribute.
    *
    * @param createdDate
    *     The value of the "createdDate" attribute.
    */
   public void setCreatedDate(Date createdDate) {
      this.createdDate = createdDate;
   }
   /**
    * Sets the value of the "description" attribute.
    *
    * @param description
    *     The value of the "description" attribute.
    */
   public void setDescription(String description) {
      this.description = description;
   }
   /**
    * Sets the value of the "exportedToGuildQuality" attribute.
    *
    * @param exportedToGuildQuality
    *     The value of the "exportedToGuildQuality" attribute.
    */
   public void setExportedToGuildQuality(boolean exportedToGuildQuality) {
      this.exportedToGuildQuality = exportedToGuildQuality;
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
    * Sets the value of the "inquiryId" attribute.
    *
    * @param inquiryId
    *     The value of the "inquiryId" attribute.
    */
   public void setInquiryId(String inquiryId) {
      this.inquiryId = inquiryId;
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
    * Sets the value of the "lastUpdate" attribute.
    *
    * @param lastUpdate
    *     The value of the "lastUpdate" attribute.
    */
   public void setLastUpdate(Date lastUpdate) {
      this.lastUpdate = lastUpdate;
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
    * Sets the value of the "note" attribute.
    *
    * @param note
    *     The value of the "note" attribute.
    */
   public void setNote(String note) {
      this.note = note;
   }
   /**
    * Sets the value of the "number" attribute.
    *
    * @param number
    *     The value of the "number" attribute.
    */
   public void setNumber(String number) {
      this.number = number;
   }
   /**
    * Sets the value of the "saleDate" attribute.
    *
    * @param saleDate
    *     The value of the "saleDate" attribute.
    */
   public void setSaleDate(Date saleDate) {
      this.saleDate = saleDate;
   }
   /**
    * Sets the value of the "site" attribute.
    *
    * @param site
    *     The value of the "site" attribute.
    */
   public void setSite(String site) {
      this.site = site;
   }
   /**
    * Sets the value of the "startDate" attribute.
    *
    * @param startDate
    *     The value of the "startDate" attribute.
    */
   public void setStartDate(Date startDate) {
      this.startDate = startDate;
   }
   /**
    * Sets the value of the "state" attribute.
    *
    * @param state
    *     The value of the "state" attribute.
    */
   public void setState(String state) {
      this.state = state;
   }
   /**
    * Sets the value of the "status" attribute.
    *
    * @param status
    *     The value of the "status" attribute.
    */
   public void setStatus(String status) {
      this.status = status;
   }
   /**
    * Sets the value of the "structureValueCode" attribute.
    *
    * @param structureValueCode
    *     The value of the "structureValueCode" attribute.
    */
   public void setStructureValueCode(String structureValueCode) {
      this.structureValueCode = structureValueCode;
   }
   /**
    * Sets the value of the "type" attribute.
    *
    * @param type
    *     The value of the "type" attribute.
    */
   public void setType(String type) {
      this.type = type;
   }
   /**
    * Sets the value of the "zip" attribute.
    *
    * @param zip
    *     The value of the "zip" attribute.
    */
   public void setZip(String zip) {
      this.zip = zip;
   }
   /**
    * Sets the value of the "appointment" attribute.
    *
    * @param appointment"
    *     The value of the "appointment" attribute.
    */
   public void setAppointment(Appointment appointment) {
      this.appointment = appointment;
   }

   /**
    * Sets the value of the "contact" attribute.
    *
    * @param contact"
    *     The value of the "contact" attribute.
    */
   public void setContact(Contact contact) {
      this.contact = contact;
   }

   /**
    * Sets the value of the "contract" attribute.
    *
    * @param contract"
    *     The value of the "contract" attribute.
    */
   public void setContract(List<Contract> contract) {
      this.contract = contract;
   }

   /**
    * Sets the value of the "jobProduct" attribute.
    *
    * @param jobProduct"
    *     The value of the "jobProduct" attribute.
    */
   public void setJobProduct(List<JobProduct> jobProduct) {
      this.jobProduct = jobProduct;
   }

   /**
    * Sets the value of the "leadPaint" attribute.
    *
    * @param leadPaint"
    *     The value of the "leadPaint" attribute.
    */
   public void setLeadPaint(List<LeadPaint> leadPaint) {
      this.leadPaint = leadPaint;
   }

   /**
    * Sets the value of the "survey" attribute.
    *
    * @param survey"
    *     The value of the "survey" attribute.
    */
   public void setSurvey(List<Survey> survey) {
      this.survey = survey;
   }

}