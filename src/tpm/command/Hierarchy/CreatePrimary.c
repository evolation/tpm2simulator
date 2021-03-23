/******************************************************************************************************************/
/*                                                                                                                */
/*                                                                                                                */
/*  Licenses and Notices                                                                                          */
/*     Copyright Licenses:                                                                                        */
/*     Trusted     Computing    Group   (TCG)     grants    to   the  user  of   the  source  code        in     this  specification   (the                                                                                            */
/*     "Source Code") a worldwide, irrevocable, nonexclusive, royalty free, copyright license to reproduce,       */
/*     create   derivative      works,  distribute,     display  and  perform     the     Source     Code        and   derivative  works                                                                                               */
/*     thereof, and to grant others the rights granted herein.                                                    */
/*     The TCG grants to the user of the other parts of the specification (other than the Source Code) the        */
/*     rights  to  reproduce,   distribute,       display,  and  perform     the  specification      solely      for   the  purpose     of                                                                                             */
/*     developing products based on such documents.                                                               */
/*     Source Code Distribution Conditions:                                                                       */
/*     Redistributions of Source Code must retain the above copyright licenses, this list of conditions and       */
/*     the following disclaimers.                                                                                 */
/*     Redistributions in binary form must reproduce the above copyright licenses, this list of conditions and    */
/*     the following disclaimers in the documentation and/or other materials provided with the distribution.      */
/*     Disclaimers:                                                                                               */
/*     THE     COPYRIGHT        LICENSES          SET   FORTH         ABOVE      DO   NOT  REPRESENT                   ANY  FORM       OF                                                                                              */
/*     LICENSE     OR  WAIVER,          EXPRESS         OR       IMPLIED,    BY      ESTOPPEL        OR          OTHERWISE,        WITH                                                                                                */
/*     RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES) THAT                                 */
/*     MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE. Contact TCG                                 */
/*     Administration (admin@trustedcomputinggroup.org) for information on specification licensing rights         */
/*     available through TCG membership agreements.                                                               */
/*     THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                               */
/*     WHATSOEVER,              INCLUDING    ANY        WARRANTY      OF     MERCHANTABILITY                  OR       FITNESS     FOR  A                                                                                              */
/*     PARTICULAR         PURPOSE,           ACCURACY,           COMPLETENESS,             OR        NONINFRINGEMENT                   OF                                                                                              */
/*     INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF ANY                                 */
/*     PROPOSAL, SPECIFICATION OR SAMPLE.                                                                         */
/*     Without     limitation,  TCG     and  its  members        and  licensors  disclaim  all       liability,  including  liability   for                                                                                            */
/*     infringement of any proprietary rights, relating to use of information in this specification and to the    */
/*     implementation     of    this    specification,  and      TCG  disclaims      all  liability  for  cost    of   procurement      of                                                                                             */
/*     substitute goods or services, lost profits, loss of use, loss of data or any incidental, consequential,    */
/*     direct, indirect, or special damages, whether under contract, tort, warranty or otherwise, arising in any  */
/*     way out of use or reliance upon this specification or any information herein.                              */
/*     Any marks and brands contained herein are the property of their respective owners.                         */
/*                                                                                                                */
/******************************************************************************************************************/

#include "Tpm.h"
#include "CreatePrimary_fp.h"
#ifdef TPM_CC_CreatePrimary                 // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES sensitiveDataOrigin is CLEAR when 'sensitive.data' is an Empty
// Buffer, or is SET when 'sensitive.data' is not empty; fixedTPM,
// fixedParent, or encryptedDuplication attributes are inconsistent
// between themselves or with those of the parent object; inconsistent
// restricted, decrypt and sign attributes; attempt to inject sensitive data
// for an asymmetric key; attempt to create a symmetric cipher key that
// is not a decryption key
// TPM_RC_KDF incorrect KDF specified for decrypting keyed hash object
// TPM_RC_KEY a provided symmetric key value is not allowed
// TPM_RC_OBJECT_MEMORY there is no free slot for the object
// TPM_RC_SCHEME inconsistent attributes decrypt, sign, restricted and key's scheme ID;
// or hash algorithm is inconsistent with the scheme ID for keyed hash
// object
// TPM_RC_SIZE size of public authorization policy or sensitive authorization value
// does not match digest size of the name algorithm; or sensitive data
// size for the keyed hash object is larger than is allowed for the
// scheme
// TPM_RC_SYMMETRIC a storage key with no symmetric algorithm specified; or non-storage
// key with symmetric algorithm different from TPM_ALG_NULL
// TPM_RC_TYPE unknown object type

TPM_RC
TPM2_CreatePrimary(
    CreatePrimary_In *in,                 // IN: input parameter list
    CreatePrimary_Out *out                 // OUT: output parameter list
)
{
// Local variables
    TPM_RC result = TPM_RC_SUCCESS;
    TPMT_PUBLIC *publicArea;
    DRBG_STATE rand;
    OBJECT *newObject;
    TPM2B_NAME name;
// Input Validation
    // Will need a place to put the result
    newObject = FindEmptyObjectSlot(&out->objectHandle);
    if(newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    // Get the address of the public area in the new object
    // (this is just to save typing)
    publicArea = &newObject->publicArea;
    *publicArea = in->inPublic.publicArea;
    // Check attributes in input public area. CreateChecks() checks the things that
    // are unique to creation and then validates the attributes and values that are
    // common to create and load.
    result = CreateChecks(NULL, publicArea);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_CreatePrimary_inPublic);
    // Validate the sensitive area values
    if(!AdjustAuthSize(&in->inSensitive.sensitive.userAuth,
                       publicArea->nameAlg))
        return TPM_RCS_SIZE + RC_CreatePrimary_inSensitive;
// Command output
    // Compute the name using out->name as a scratch area (this is not the value
    // that ultimately will be returned, then instantiate the state that will be
    // used as a random number generator during the object creation.
    // The caller does not know the seed values so the actual name does not have
    // to be over the input, it can be over the unmarshaled structure.
    DRBG_InstantiateSeeded(&rand,
                           &HierarchyGetPrimarySeed(in->primaryHandle)->b,
                           PRIMARY_OBJECT_CREATION,
                           (TPM2B *)PublicMarshalAndComputeName(publicArea, &name),
                           &in->inSensitive.sensitive.data.b);
    newObject->attributes.primary = SET;
    if(in->primaryHandle == TPM_RH_ENDORSEMENT)
        newObject->attributes.epsHierarchy = SET;
    // Create the primary object.
    result = CryptCreateObject(newObject, &in->inSensitive.sensitive,
                               (RAND_STATE *)&rand);
    if(result != TPM_RC_SUCCESS)
        return result;
    // Set the publicArea and name from the computed values
    out->outPublic.publicArea = newObject->publicArea;
    out->name = newObject->name;
    // Fill in creation data
    FillInCreationData(in->primaryHandle, publicArea->nameAlg,
                       &in->creationPCR, &in->outsideInfo, &out->creationData,
                       &out->creationHash);
    // Compute creation ticket
    TicketComputeCreation(EntityGetHierarchy(in->primaryHandle), &out->name,
                          &out->creationHash, &out->creationTicket);
    // Set the remaining attributes for a loaded object
    ObjectSetLoadedAttributes(newObject, in->primaryHandle);
    return result;
}
#endif // CC_CreatePrimary
