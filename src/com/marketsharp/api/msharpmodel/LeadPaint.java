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


import java.util.List;
import msharpmodel.Company;
import msharpmodel.Inquiry;
import msharpmodel.Job;
import msharpmodel.LeadPaintAttachment;
import msharpmodel.LeadPaintToFirm;
import msharpmodel.LeadPaintToRenovator;
import msharpmodel.LeadPaintToWorker;

/**
* Generated by the generator tool for the OData extension for the Restlet framework.<br>
*
* @see <a href="http://localhost:57241/WcfDataService.svc/$metadata">Metadata of the target OData service</a>
*
*/
public class LeadPaint {

    private int childOccupied;
    private String companyId;
    private int hasLeadPaint;
    private int housingType;
    private String id;
    private String inquiryId;
    private boolean isActive;
    private String jobId;
    private int pre1978;
    private String yearBuilt;
    private Company company;
    private Inquiry inquiry;
    private Job job;
    private List<LeadPaintAttachment> leadPaintAttachment;
    private List<LeadPaintToFirm> leadPaintToFirm;
    private List<LeadPaintToRenovator> leadPaintToRenovator;
    private List<LeadPaintToWorker> leadPaintToWorker;

    /**
     * Constructor without parameter.
     * 
     */
    public LeadPaint() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param id
     *            The identifiant value of the entity.
     */
    public LeadPaint(String id) {
        this();
        this.id = id;
    }

   /**
    * Returns the value of the "childOccupied" attribute.
    *
    * @return The value of the "childOccupied" attribute.
    */
   public int getChildOccupied() {
      return childOccupied;
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
    * Returns the value of the "hasLeadPaint" attribute.
    *
    * @return The value of the "hasLeadPaint" attribute.
    */
   public int getHasLeadPaint() {
      return hasLeadPaint;
   }
   /**
    * Returns the value of the "housingType" attribute.
    *
    * @return The value of the "housingType" attribute.
    */
   public int getHousingType() {
      return housingType;
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
    * Returns the value of the "jobId" attribute.
    *
    * @return The value of the "jobId" attribute.
    */
   public String getJobId() {
      return jobId;
   }
   /**
    * Returns the value of the "pre1978" attribute.
    *
    * @return The value of the "pre1978" attribute.
    */
   public int getPre1978() {
      return pre1978;
   }
   /**
    * Returns the value of the "yearBuilt" attribute.
    *
    * @return The value of the "yearBuilt" attribute.
    */
   public String getYearBuilt() {
      return yearBuilt;
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
   public Job getJob() {
      return job;
   }
   
   /**
    * Returns the value of the "leadPaintAttachment" attribute.
    *
    * @return The value of the "leadPaintAttachment" attribute.
    */
   public List<LeadPaintAttachment> getLeadPaintAttachment() {
      return leadPaintAttachment;
   }
   
   /**
    * Returns the value of the "leadPaintToFirm" attribute.
    *
    * @return The value of the "leadPaintToFirm" attribute.
    */
   public List<LeadPaintToFirm> getLeadPaintToFirm() {
      return leadPaintToFirm;
   }
   
   /**
    * Returns the value of the "leadPaintToRenovator" attribute.
    *
    * @return The value of the "leadPaintToRenovator" attribute.
    */
   public List<LeadPaintToRenovator> getLeadPaintToRenovator() {
      return leadPaintToRenovator;
   }
   
   /**
    * Returns the value of the "leadPaintToWorker" attribute.
    *
    * @return The value of the "leadPaintToWorker" attribute.
    */
   public List<LeadPaintToWorker> getLeadPaintToWorker() {
      return leadPaintToWorker;
   }
   
   /**
    * Sets the value of the "childOccupied" attribute.
    *
    * @param childOccupied
    *     The value of the "childOccupied" attribute.
    */
   public void setChildOccupied(int childOccupied) {
      this.childOccupied = childOccupied;
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
    * Sets the value of the "hasLeadPaint" attribute.
    *
    * @param hasLeadPaint
    *     The value of the "hasLeadPaint" attribute.
    */
   public void setHasLeadPaint(int hasLeadPaint) {
      this.hasLeadPaint = hasLeadPaint;
   }
   /**
    * Sets the value of the "housingType" attribute.
    *
    * @param housingType
    *     The value of the "housingType" attribute.
    */
   public void setHousingType(int housingType) {
      this.housingType = housingType;
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
    * Sets the value of the "jobId" attribute.
    *
    * @param jobId
    *     The value of the "jobId" attribute.
    */
   public void setJobId(String jobId) {
      this.jobId = jobId;
   }
   /**
    * Sets the value of the "pre1978" attribute.
    *
    * @param pre1978
    *     The value of the "pre1978" attribute.
    */
   public void setPre1978(int pre1978) {
      this.pre1978 = pre1978;
   }
   /**
    * Sets the value of the "yearBuilt" attribute.
    *
    * @param yearBuilt
    *     The value of the "yearBuilt" attribute.
    */
   public void setYearBuilt(String yearBuilt) {
      this.yearBuilt = yearBuilt;
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
   public void setJob(Job job) {
      this.job = job;
   }

   /**
    * Sets the value of the "leadPaintAttachment" attribute.
    *
    * @param leadPaintAttachment"
    *     The value of the "leadPaintAttachment" attribute.
    */
   public void setLeadPaintAttachment(List<LeadPaintAttachment> leadPaintAttachment) {
      this.leadPaintAttachment = leadPaintAttachment;
   }

   /**
    * Sets the value of the "leadPaintToFirm" attribute.
    *
    * @param leadPaintToFirm"
    *     The value of the "leadPaintToFirm" attribute.
    */
   public void setLeadPaintToFirm(List<LeadPaintToFirm> leadPaintToFirm) {
      this.leadPaintToFirm = leadPaintToFirm;
   }

   /**
    * Sets the value of the "leadPaintToRenovator" attribute.
    *
    * @param leadPaintToRenovator"
    *     The value of the "leadPaintToRenovator" attribute.
    */
   public void setLeadPaintToRenovator(List<LeadPaintToRenovator> leadPaintToRenovator) {
      this.leadPaintToRenovator = leadPaintToRenovator;
   }

   /**
    * Sets the value of the "leadPaintToWorker" attribute.
    *
    * @param leadPaintToWorker"
    *     The value of the "leadPaintToWorker" attribute.
    */
   public void setLeadPaintToWorker(List<LeadPaintToWorker> leadPaintToWorker) {
      this.leadPaintToWorker = leadPaintToWorker;
   }

}