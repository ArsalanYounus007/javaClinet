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
import msharpmodel.AppointmentResult;
import msharpmodel.Employee;
import msharpmodel.Inquiry;
import msharpmodel.Job;
import msharpmodel.Proposal;

/**
* Generated by the generator tool for the OData extension for the Restlet framework.<br>
*
* @see <a href="http://localhost:57241/WcfDataService.svc/$metadata">Metadata of the target OData service</a>
*
*/
public class Appointment {

    private Date appointmentDate;
    private String createdBy;
    private Date createdDate;
    private String id;
    private String inquiryId;
    private boolean isActive;
    private Date issuedDate;
    private Date lastUpdate;
    private String lastUpdateBy;
    private String note;
    private String resultId;
    private String resultReason;
    private String salesperson1id;
    private String salesperson2id;
    private String setById;
    private Date setDate;
    private String subject;
    private String type;
    private List<Activity> activity;
    private AppointmentResult appointmentResult;
    private Inquiry inquiry;
    private List<Job> job;
    private List<Proposal> proposal;
    private Employee salesperson1;
    private Employee salesperson2;
    private Employee setBy;

    /**
     * Constructor without parameter.
     * 
     */
    public Appointment() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param id
     *            The identifiant value of the entity.
     */
    public Appointment(String id) {
        this();
        this.id = id;
    }

   /**
    * Returns the value of the "appointmentDate" attribute.
    *
    * @return The value of the "appointmentDate" attribute.
    */
   public Date getAppointmentDate() {
      return appointmentDate;
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
    * Returns the value of the "createdDate" attribute.
    *
    * @return The value of the "createdDate" attribute.
    */
   public Date getCreatedDate() {
      return createdDate;
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
    * Returns the value of the "issuedDate" attribute.
    *
    * @return The value of the "issuedDate" attribute.
    */
   public Date getIssuedDate() {
      return issuedDate;
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
    * Returns the value of the "lastUpdateBy" attribute.
    *
    * @return The value of the "lastUpdateBy" attribute.
    */
   public String getLastUpdateBy() {
      return lastUpdateBy;
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
    * Returns the value of the "resultId" attribute.
    *
    * @return The value of the "resultId" attribute.
    */
   public String getResultId() {
      return resultId;
   }
   /**
    * Returns the value of the "resultReason" attribute.
    *
    * @return The value of the "resultReason" attribute.
    */
   public String getResultReason() {
      return resultReason;
   }
   /**
    * Returns the value of the "salesperson1id" attribute.
    *
    * @return The value of the "salesperson1id" attribute.
    */
   public String getSalesperson1id() {
      return salesperson1id;
   }
   /**
    * Returns the value of the "salesperson2id" attribute.
    *
    * @return The value of the "salesperson2id" attribute.
    */
   public String getSalesperson2id() {
      return salesperson2id;
   }
   /**
    * Returns the value of the "setById" attribute.
    *
    * @return The value of the "setById" attribute.
    */
   public String getSetById() {
      return setById;
   }
   /**
    * Returns the value of the "setDate" attribute.
    *
    * @return The value of the "setDate" attribute.
    */
   public Date getSetDate() {
      return setDate;
   }
   /**
    * Returns the value of the "subject" attribute.
    *
    * @return The value of the "subject" attribute.
    */
   public String getSubject() {
      return subject;
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
    * Returns the value of the "activity" attribute.
    *
    * @return The value of the "activity" attribute.
    */
   public List<Activity> getActivity() {
      return activity;
   }
   
   /**
    * Returns the value of the "appointmentResult" attribute.
    *
    * @return The value of the "appointmentResult" attribute.
    */
   public AppointmentResult getAppointmentResult() {
      return appointmentResult;
   }
   
   /**
    * Returns the value of the "inquiry" attribute.
    *
    * @return The value of the "inquiry" attribute.
    */
   public Inquiry getInquiry() {
      return inquiry;
   }
   
   /**
    * Returns the value of the "job" attribute.
    *
    * @return The value of the "job" attribute.
    */
   public List<Job> getJob() {
      return job;
   }
   
   /**
    * Returns the value of the "proposal" attribute.
    *
    * @return The value of the "proposal" attribute.
    */
   public List<Proposal> getProposal() {
      return proposal;
   }
   
   /**
    * Returns the value of the "salesperson1" attribute.
    *
    * @return The value of the "salesperson1" attribute.
    */
   public Employee getSalesperson1() {
      return salesperson1;
   }
   
   /**
    * Returns the value of the "salesperson2" attribute.
    *
    * @return The value of the "salesperson2" attribute.
    */
   public Employee getSalesperson2() {
      return salesperson2;
   }
   
   /**
    * Returns the value of the "setBy" attribute.
    *
    * @return The value of the "setBy" attribute.
    */
   public Employee getSetBy() {
      return setBy;
   }
   
   /**
    * Sets the value of the "appointmentDate" attribute.
    *
    * @param appointmentDate
    *     The value of the "appointmentDate" attribute.
    */
   public void setAppointmentDate(Date appointmentDate) {
      this.appointmentDate = appointmentDate;
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
    * Sets the value of the "createdDate" attribute.
    *
    * @param createdDate
    *     The value of the "createdDate" attribute.
    */
   public void setCreatedDate(Date createdDate) {
      this.createdDate = createdDate;
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
    * Sets the value of the "issuedDate" attribute.
    *
    * @param issuedDate
    *     The value of the "issuedDate" attribute.
    */
   public void setIssuedDate(Date issuedDate) {
      this.issuedDate = issuedDate;
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
    * Sets the value of the "lastUpdateBy" attribute.
    *
    * @param lastUpdateBy
    *     The value of the "lastUpdateBy" attribute.
    */
   public void setLastUpdateBy(String lastUpdateBy) {
      this.lastUpdateBy = lastUpdateBy;
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
    * Sets the value of the "resultId" attribute.
    *
    * @param resultId
    *     The value of the "resultId" attribute.
    */
   public void setResultId(String resultId) {
      this.resultId = resultId;
   }
   /**
    * Sets the value of the "resultReason" attribute.
    *
    * @param resultReason
    *     The value of the "resultReason" attribute.
    */
   public void setResultReason(String resultReason) {
      this.resultReason = resultReason;
   }
   /**
    * Sets the value of the "salesperson1id" attribute.
    *
    * @param salesperson1id
    *     The value of the "salesperson1id" attribute.
    */
   public void setSalesperson1id(String salesperson1id) {
      this.salesperson1id = salesperson1id;
   }
   /**
    * Sets the value of the "salesperson2id" attribute.
    *
    * @param salesperson2id
    *     The value of the "salesperson2id" attribute.
    */
   public void setSalesperson2id(String salesperson2id) {
      this.salesperson2id = salesperson2id;
   }
   /**
    * Sets the value of the "setById" attribute.
    *
    * @param setById
    *     The value of the "setById" attribute.
    */
   public void setSetById(String setById) {
      this.setById = setById;
   }
   /**
    * Sets the value of the "setDate" attribute.
    *
    * @param setDate
    *     The value of the "setDate" attribute.
    */
   public void setSetDate(Date setDate) {
      this.setDate = setDate;
   }
   /**
    * Sets the value of the "subject" attribute.
    *
    * @param subject
    *     The value of the "subject" attribute.
    */
   public void setSubject(String subject) {
      this.subject = subject;
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
    * Sets the value of the "activity" attribute.
    *
    * @param activity"
    *     The value of the "activity" attribute.
    */
   public void setActivity(List<Activity> activity) {
      this.activity = activity;
   }

   /**
    * Sets the value of the "appointmentResult" attribute.
    *
    * @param appointmentResult"
    *     The value of the "appointmentResult" attribute.
    */
   public void setAppointmentResult(AppointmentResult appointmentResult) {
      this.appointmentResult = appointmentResult;
   }

   /**
    * Sets the value of the "inquiry" attribute.
    *
    * @param inquiry"
    *     The value of the "inquiry" attribute.
    */
   public void setInquiry(Inquiry inquiry) {
      this.inquiry = inquiry;
   }

   /**
    * Sets the value of the "job" attribute.
    *
    * @param job"
    *     The value of the "job" attribute.
    */
   public void setJob(List<Job> job) {
      this.job = job;
   }

   /**
    * Sets the value of the "proposal" attribute.
    *
    * @param proposal"
    *     The value of the "proposal" attribute.
    */
   public void setProposal(List<Proposal> proposal) {
      this.proposal = proposal;
   }

   /**
    * Sets the value of the "salesperson1" attribute.
    *
    * @param salesperson1"
    *     The value of the "salesperson1" attribute.
    */
   public void setSalesperson1(Employee salesperson1) {
      this.salesperson1 = salesperson1;
   }

   /**
    * Sets the value of the "salesperson2" attribute.
    *
    * @param salesperson2"
    *     The value of the "salesperson2" attribute.
    */
   public void setSalesperson2(Employee salesperson2) {
      this.salesperson2 = salesperson2;
   }

   /**
    * Sets the value of the "setBy" attribute.
    *
    * @param setBy"
    *     The value of the "setBy" attribute.
    */
   public void setSetBy(Employee setBy) {
      this.setBy = setBy;
   }

}