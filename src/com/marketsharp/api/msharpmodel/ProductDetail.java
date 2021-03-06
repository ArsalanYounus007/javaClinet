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
import msharpmodel.FutureInterest;
import msharpmodel.JobProductDetail;
import msharpmodel.ProductInterest;
import msharpmodel.ProductType;

/**
* Generated by the generator tool for the OData extension for the Restlet framework.<br>
*
* @see <a href="http://localhost:57241/WcfDataService.svc/$metadata">Metadata of the target OData service</a>
*
*/
public class ProductDetail {

    private String companyId;
    private String id;
    private boolean isActive;
    private String name;
    private String productTypeId;
    private Company company;
    private List<FutureInterest> futureInterest;
    private List<JobProductDetail> jobProductDetail;
    private List<ProductInterest> productInterest;
    private ProductType productType;

    /**
     * Constructor without parameter.
     * 
     */
    public ProductDetail() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param id
     *            The identifiant value of the entity.
     */
    public ProductDetail(String id) {
        this();
        this.id = id;
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
    * Returns the value of the "id" attribute.
    *
    * @return The value of the "id" attribute.
    */
   public String getId() {
      return id;
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
    * Returns the value of the "name" attribute.
    *
    * @return The value of the "name" attribute.
    */
   public String getName() {
      return name;
   }
   /**
    * Returns the value of the "productTypeId" attribute.
    *
    * @return The value of the "productTypeId" attribute.
    */
   public String getProductTypeId() {
      return productTypeId;
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
    * Returns the value of the "futureInterest" attribute.
    *
    * @return The value of the "futureInterest" attribute.
    */
   public List<FutureInterest> getFutureInterest() {
      return futureInterest;
   }
   
   /**
    * Returns the value of the "jobProductDetail" attribute.
    *
    * @return The value of the "jobProductDetail" attribute.
    */
   public List<JobProductDetail> getJobProductDetail() {
      return jobProductDetail;
   }
   
   /**
    * Returns the value of the "productInterest" attribute.
    *
    * @return The value of the "productInterest" attribute.
    */
   public List<ProductInterest> getProductInterest() {
      return productInterest;
   }
   
   /**
    * Returns the value of the "productType" attribute.
    *
    * @return The value of the "productType" attribute.
    */
   public ProductType getProductType() {
      return productType;
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
    * Sets the value of the "id" attribute.
    *
    * @param id
    *     The value of the "id" attribute.
    */
   public void setId(String id) {
      this.id = id;
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
    * Sets the value of the "name" attribute.
    *
    * @param name
    *     The value of the "name" attribute.
    */
   public void setName(String name) {
      this.name = name;
   }
   /**
    * Sets the value of the "productTypeId" attribute.
    *
    * @param productTypeId
    *     The value of the "productTypeId" attribute.
    */
   public void setProductTypeId(String productTypeId) {
      this.productTypeId = productTypeId;
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
    * Sets the value of the "futureInterest" attribute.
    *
    * @param futureInterest"
    *     The value of the "futureInterest" attribute.
    */
   public void setFutureInterest(List<FutureInterest> futureInterest) {
      this.futureInterest = futureInterest;
   }

   /**
    * Sets the value of the "jobProductDetail" attribute.
    *
    * @param jobProductDetail"
    *     The value of the "jobProductDetail" attribute.
    */
   public void setJobProductDetail(List<JobProductDetail> jobProductDetail) {
      this.jobProductDetail = jobProductDetail;
   }

   /**
    * Sets the value of the "productInterest" attribute.
    *
    * @param productInterest"
    *     The value of the "productInterest" attribute.
    */
   public void setProductInterest(List<ProductInterest> productInterest) {
      this.productInterest = productInterest;
   }

   /**
    * Sets the value of the "productType" attribute.
    *
    * @param productType"
    *     The value of the "productType" attribute.
    */
   public void setProductType(ProductType productType) {
      this.productType = productType;
   }

}