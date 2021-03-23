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
#include "Load_fp.h"
#ifdef TPM_CC_Load        // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ASYMMETRIC storage key with different asymmetric type than parent
// TPM_RC_ATTRIBUTES inPulblic attributes are not allowed with selected parent
// TPM_RC_BINDING inPrivate and inPublic are not cryptographically bound
// TPM_RC_HASH incorrect hash selection for signing key or the nameAlg for 'inPubic is
// not valid
// TPM_RC_INTEGRITY HMAC on inPrivate was not valid
// TPM_RC_KDF KDF selection not allowed
// TPM_RC_KEY the size of the object's unique field is not consistent with the indicated
// size in the object's parameters
// TPM_RC_OBJECT_MEMORY no available object slot
// TPM_RC_SCHEME the signing scheme is not valid for the key
// TPM_RC_SENSITIVE the inPrivate did not unmarshal correctly
// TPM_RC_SIZE inPrivate missing, or authPolicy size for inPublic or is not valid
// TPM_RC_SYMMETRIC symmetric algorithm not provided when required
// TPM_RC_TYPE parentHandle is not a storage key, or the object to load is a storage
// key but its parameters do not match the parameters of the parent.
// TPM_RC_VALUE decryption failure

TPM_RC
TPM2_Load(
    Load_In *in,                     // IN: input parameter list
    Load_Out *out                     // OUT: output parameter list
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE sensitive;
    OBJECT *parentObject;
    OBJECT *newObject;
// Input Validation
    // Don't get invested in loading if there is no place to put it.
    newObject = FindEmptyObjectSlot(&out->objectHandle);
    if(newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    if(in->inPrivate.t.size == 0)
        return TPM_RCS_SIZE + RC_Load_inPrivate;
    parentObject = HandleToObject(in->parentHandle);
    pAssert(parentObject != NULL);
    // Is the object that is being used as the parent actually a parent.
    if(!ObjectIsParent(parentObject))
        return TPM_RCS_TYPE + RC_Load_parentHandle;
    // Compute the name of object. If there isn't one, it is because the nameAlg is
    // not valid.
    PublicMarshalAndComputeName(&in->inPublic.publicArea, &out->name);
    if(out->name.t.size == 0)
        return TPM_RCS_HASH + RC_Load_inPublic;
    // Retrieve sensitive data.
    result = PrivateToSensitive(&in->inPrivate.b, &out->name.b, parentObject,
                                in->inPublic.publicArea.nameAlg,
                                &sensitive);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_Load_inPrivate);
// Internal Data Update
    // Load and validate object
    result = ObjectLoad(newObject, parentObject,
                        &in->inPublic.publicArea, &sensitive,
                        RC_Load_inPublic, RC_Load_inPrivate,
                        &out->name);
    if(result == TPM_RC_SUCCESS)
    {
        // Set the common OBJECT attributes for a loaded object.
        ObjectSetLoadedAttributes(newObject, in->parentHandle);
    }
    return result;
}
#endif // CC_Load
