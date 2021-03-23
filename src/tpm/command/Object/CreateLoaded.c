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
#include "CreateLoaded_fp.h"
#ifdef TPM_CC_CreateLoaded              // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES sensitiveDataOrigin is CLEAR when 'sensitive.data' is an Empty
// Buffer, or is SET when 'sensitive.data' is not empty; fixedTPM,
// fixedParent, or encryptedDuplication attributes are inconsistent
// between themselves or with those of the parent object; inconsistent
// restricted, decrypt and sign attributes; attempt to inject sensitive data
// for an asymmetric key; attempt to create a symmetric cipher key that
// is not a decryption key
// TPM_RC_KDF incorrect KDF specified for decrypting keyed hash object
// TPM_RC_KEY the value of a provided symmetric key is not allowed
// TPM_RC_OBJECT_MEMORY there is no free slot for the object
// TPM_RC_SCHEME inconsistent attributes decrypt, sign, restricted and key's scheme ID;
// or hash algorithm is inconsistent with the scheme ID for keyed hash
// object
// TPM_RC_SIZE size of public authorization policy or sensitive authorization value
// does not match digest size of the name algorithm sensitive data size
// for the keyed hash object is larger than is allowed for the scheme
// TPM_RC_SYMMETRIC a storage key with no symmetric algorithm specified; or non-storage
// key with symmetric algorithm different from TPM_ALG_NULL
// TPM_RC_TYPE cannot create the object of the indicated type (usually only occurs if
// trying to derive an RSA key).

TPM_RC
TPM2_CreateLoaded(
    CreateLoaded_In *in,                  // IN: input parameter list
    CreateLoaded_Out *out                  // OUT: output parameter list
)
{
// Local variables
    TPM_RC result = TPM_RC_SUCCESS;
    // These are the values used in object creation
    OBJECT *parent = HandleToObject(in->parentHandle);
    OBJECT *newObject;
    BOOL derivation;
    TPMT_PUBLIC *publicArea;
    RAND_STATE randState;
    RAND_STATE *rand = &randState;
// Input Validation
    // How the public area is unmarshaled is determined by the parent, so
    // see if parent is a derivation parent
    derivation = (parent != NULL && parent->attributes.derivation);
    // If the parent is an object, then make sure that it is either a parent or
    // derivation parent
    if(parent != NULL && !parent->attributes.isParent && !derivation)
        return TPM_RCS_TYPE + RC_CreateLoaded_parentHandle;
    // Get a spot in which to create the newObject
    newObject = FindEmptyObjectSlot(&out->objectHandle);
    if(newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    // Do this to save typing
    publicArea = &newObject->publicArea;
// Unmarshal the template into the object space. TPM2_Create() and
// TPM2_CreatePrimary() have the publicArea unmarshaled by CommandDispatcher.
// This command is different because of an unfortunate property of the
// unique field of an ECC key. It is a structure rather than a single TPM2B. If
// if had been a TPM2B, then the label and context could be within a TPM2B and
// unmarshaled like other public areas. Since it is not, this command needs its
// on template that is a TPM2B that is unmarshaled as a BYTE array with a
// its own unmarshal function.
    result = UnmarshalToPublic(publicArea, &in->inPublic, derivation);
    if(result != TPM_RC_SUCCESS)
        return result + RC_CreateLoaded_inPublic;
// Validate that the authorization size is appropriate
    if(!AdjustAuthSize(&in->inSensitive.sensitive.userAuth, publicArea->nameAlg))
        return TPM_RCS_SIZE + RC_CreateLoaded_inSensitive;
// Command output
    if(derivation)
    {
        TPMT_KEYEDHASH_SCHEME *scheme;
        scheme = &parent->publicArea.parameters.keyedHashDetail.scheme;
        // SP800-108 is the only KDF supported by this implementation and there is
        // no default hash algorithm.
        pAssert(scheme->details.xor.hashAlg != TPM_ALG_NULL
                && scheme->details.xor.kdf == TPM_ALG_KDF1_SP800_108);
        // Don't derive RSA keys
        if(publicArea->type == ALG_RSA_VALUE)
            return TPM_RCS_TYPE + RC_CreateLoaded_inPublic;
        // sensitiveDataOrigin has to be CLEAR in a derived object. Since this
        // is specific to a derived object, it is checked here.
        if(publicArea->objectAttributes.sensitiveDataOrigin)
            return TPM_RCS_ATTRIBUTES;
        // Check the reset of the attributes
        result = PublicAttributesValidation(parent, publicArea);
        if(result != TPM_RC_SUCCESS)
            return RcSafeAddToResult(result, RC_CreateLoaded_inPublic);
        // Process the template and sensitive areas to get the actual 'label' and
        // 'context' values to be used for this derivation.
        result = SetLabelAndContext(publicArea, &in->inSensitive.sensitive.data);
        if(result != TPM_RC_SUCCESS)
            return result;
        // Set up the KDF for object generation
        DRBG_InstantiateSeededKdf((KDF_STATE *)rand,
                                  scheme->details.xor.hashAlg,
                                  scheme->details.xor.kdf,
                                  &parent->sensitive.seedValue.b,
                                  &publicArea->unique.derive.label.b,
                                  &publicArea->unique.derive.context.b);
        // Clear the sensitive size so that the creation functions will not try
        // to use this value.
        in->inSensitive.sensitive.data.t.size = 0;
    }
    else
    {
        // Check attributes in input public area. CreateChecks() checks the things
        // that are unique to creation and then validates the attributes and values
        // that are common to create and load.
        result = CreateChecks(parent, publicArea);
        if(result != TPM_RC_SUCCESS)
            return RcSafeAddToResult(result, RC_CreateLoaded_inPublic);
        // Creating a primary object
        if(parent == NULL)
        {
            TPM2B_NAME name;
            newObject->attributes.primary = SET;
            if(in->parentHandle == TPM_RH_ENDORSEMENT)
                newObject->attributes.epsHierarchy = SET;
            // If so, use the primary seed and the digest of the template
            // to seed the DRBG
	    DRBG_InstantiateSeeded((DRBG_STATE *)rand,
                         &HierarchyGetPrimarySeed(in->parentHandle)->b,
                         PRIMARY_OBJECT_CREATION,
                         (TPM2B *)PublicMarshalAndComputeName(publicArea, &name),
                         &in->inSensitive.sensitive.data.b);
        }
        else
            // This is an ordinary object so use the normal random number generator
            rand = NULL;
    }
// Internal data update
    // Create the object
    result = CryptCreateObject(newObject, &in->inSensitive.sensitive, rand);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if this is not a Primary key and not a derived key, then return the sensitive
    // area
    if(parent != NULL && !derivation)
        // Prepare output private data from sensitive
        SensitiveToPrivate(&newObject->sensitive, &newObject->name.b,
                           parent, newObject->publicArea.nameAlg,
                           &out->outPrivate);
    else
        out->outPrivate.t.size = 0;
    // Set the remaining return values
    out->outPublic.publicArea = newObject->publicArea;
    out->name = newObject->name;
    // Set the remaining attributes for a loaded object
    ObjectSetLoadedAttributes(newObject, in->parentHandle);
    return result;
}
#endif // CC_CreatePrimary
