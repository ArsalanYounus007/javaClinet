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


import msharpmodel.Contact;

/**
* Generated by the generator tool for the OData extension for the Restlet framework.<br>
*
* @see <a href="http://localhost:57241/WcfDataService.svc/$metadata">Metadata of the target OData service</a>
*
*/
public class AdditionalContact {

    private String cellPhone;
    private String city;
    private String contactId;
    private String email1;
    private String email2;
    private String firstName;
    private String homePhone;
    private String id;
    private boolean isActive;
    private String lastName;
    private String line1;
    private String line2;
    private String note;
    private String relationship;
    private String state;
    private String title;
    private String workPhone;
    private String zip;
    private Contact contact;

    /**
     * Constructor without parameter.
     * 
     */
    public AdditionalContact() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param id
     *            The identifiant value of the entity.
     */
    public AdditionalContact(String id) {
        this();
        this.id = id;
    }

   /**
    * Returns the value of the "cellPhone" attribute.
    *
    * @return The value of the "cellPhone" attribute.
    */
   public String getCellPhone() {
      return cellPhone;
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
    * Returns the value of the "contactId" attribute.
    *
    * @return The value of the "contactId" attribute.
    */
   public String getContactId() {
      return contactId;
   }
   /**
    * Returns the value of the "email1" attribute.
    *
    * @return The value of the "email1" attribute.
    */
   public String getEmail1() {
      return email1;
   }
   /**
    * Returns the value of the "email2" attribute.
    *
    * @return The value of the "email2" attribute.
    */
   public String getEmail2() {
      return email2;
   }
   /**
    * Returns the value of the "firstName" attribute.
    *
    * @return The value of the "firstName" attribute.
    */
   public String getFirstName() {
      return firstName;
   }
   /**
    * Returns the value of the "homePhone" attribute.
    *
    * @return The value of the "homePhone" attribute.
    */
   public String getHomePhone() {
      return homePhone;
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
    * Returns the value of the "lastName" attribute.
    *
    * @return The value of the "lastName" attribute.
    */
   public String getLastName() {
      return lastName;
   }
   /**
    * Returns the value of the "line1" attribute.
    *
    * @return The value of the "line1" attribute.
    */
   public String getLine1() {
      return line1;
   }
   /**
    * Returns the value of the "line2" attribute.
    *
    * @return The value of the "line2" attribute.
    */
   public String getLine2() {
      return line2;
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
    * Returns the value of the "relationship" attribute.
    *
    * @return The value of the "relationship" attribute.
    */
   public String getRelationship() {
      return relationship;
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
    * Returns the value of the "title" attribute.
    *
    * @return The value of the "title" attribute.
    */
   public String getTitle() {
      return title;
   }
   /**
    * Returns the value of the "workPhone" attribute.
    *
    * @return The value of the "workPhone" attribute.
    */
   public String getWorkPhone() {
      return workPhone;
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
    * Returns the value of the "contact" attribute.
    *
    * @return The value of the "contact" attribute.
    */
   public Contact getContact() {
      return contact;
   }
   
   /**
    * Sets the value of the "cellPhone" attribute.
    *
    * @param cellPhone
    *     The value of the "cellPhone" attribute.
    */
   public void setCellPhone(String cellPhone) {
      this.cellPhone = cellPhone;
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
    * Sets the value of the "contactId" attribute.
    *
    * @param contactId
    *     The value of the "contactId" attribute.
    */
   public void setContactId(String contactId) {
      this.contactId = contactId;
   }
   /**
    * Sets the value of the "email1" attribute.
    *
    * @param email1
    *     The value of the "email1" attribute.
    */
   public void setEmail1(String email1) {
      this.email1 = email1;
   }
   /**
    * Sets the value of the "email2" attribute.
    *
    * @param email2
    *     The value of the "email2" attribute.
    */
   public void setEmail2(String email2) {
      this.email2 = email2;
   }
   /**
    * Sets the value of the "firstName" attribute.
    *
    * @param firstName
    *     The value of the "firstName" attribute.
    */
   public void setFirstName(String firstName) {
      this.firstName = firstName;
   }
   /**
    * Sets the value of the "homePhone" attribute.
    *
    * @param homePhone
    *     The value of the "homePhone" attribute.
    */
   public void setHomePhone(String homePhone) {
      this.homePhone = homePhone;
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
    * Sets the value of the "lastName" attribute.
    *
    * @param lastName
    *     The value of the "lastName" attribute.
    */
   public void setLastName(String lastName) {
      this.lastName = lastName;
   }
   /**
    * Sets the value of the "line1" attribute.
    *
    * @param line1
    *     The value of the "line1" attribute.
    */
   public void setLine1(String line1) {
      this.line1 = line1;
   }
   /**
    * Sets the value of the "line2" attribute.
    *
    * @param line2
    *     The value of the "line2" attribute.
    */
   public void setLine2(String line2) {
      this.line2 = line2;
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
    * Sets the value of the "relationship" attribute.
    *
    * @param relationship
    *     The value of the "relationship" attribute.
    */
   public void setRelationship(String relationship) {
      this.relationship = relationship;
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
    * Sets the value of the "title" attribute.
    *
    * @param title
    *     The value of the "title" attribute.
    */
   public void setTitle(String title) {
      this.title = title;
   }
   /**
    * Sets the value of the "workPhone" attribute.
    *
    * @param workPhone
    *     The value of the "workPhone" attribute.
    */
   public void setWorkPhone(String workPhone) {
      this.workPhone = workPhone;
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
    * Sets the value of the "contact" attribute.
    *
    * @param contact"
    *     The value of the "contact" attribute.
    */
   public void setContact(Contact contact) {
      this.contact = contact;
   }

}