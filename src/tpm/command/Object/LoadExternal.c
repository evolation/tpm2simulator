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
#include "LoadExternal_fp.h"
#ifdef TPM_CC_LoadExternal              // Conditional expansion of this file
#include "Object_spt_fp.h"

// M e
// TPM_RC_ATTRIBUTES 'fixedParent", fixedTPM, and restricted must be CLEAR if sensitive
// portion of an object is loaded
// TPM_RC_BINDING the inPublic and inPrivate structures are not cryptographically bound
// TPM_RC_HASH incorrect hash selection for signing key
// TPM_RC_HIERARCHY hierarchy is turned off, or only NULL hierarchy is allowed when
// loading public and private parts of an object
// TPM_RC_KDF incorrect KDF selection for decrypting keyedHash object
// TPM_RC_KEY the size of the object's unique field is not consistent with the indicated
// size in the object's parameters
// TPM_RC_OBJECT_MEMORY if there is no free slot for an object
// TPM_RC_ECC_POINT for a public-only ECC key, the ECC point is not on the curve
// TPM_RC_SCHEME the signing scheme is not valid for the key
// TPM_RC_SIZE authPolicy is not zero and is not the size of a digest produced by the
// object's nameAlg TPM_RH_NULL hierarchy
// TPM_RC_SYMMETRIC symmetric algorithm not provided when required
// TPM_RC_TYPE inPublic and inPrivate are not the same type

TPM_RC
TPM2_LoadExternal(
    LoadExternal_In *in,                     // IN: input parameter list
    LoadExternal_Out *out                     // OUT: output parameter list
)
{
    TPM_RC result;
    OBJECT *object;
    TPMT_SENSITIVE *sensitive = NULL;
// Input Validation
    // Don't get invested in loading if there is no place to put it.
    object = FindEmptyObjectSlot(&out->objectHandle);
    if(object == NULL)
        return TPM_RC_OBJECT_MEMORY;
    // If the hierarchy to be associated with this object is turned off, the object
    // cannot be loaded.
    if(!HierarchyIsEnabled(in->hierarchy))
        return TPM_RCS_HIERARCHY + RC_LoadExternal_hierarchy;
    // For loading an object with both public and sensitive
    if(in->inPrivate.size != 0)
    {
        // An external object with a sensitive area can only be loaded in the
        // NULL hierarchy
        if(in->hierarchy != TPM_RH_NULL)
            return TPM_RCS_HIERARCHY + RC_LoadExternal_hierarchy;
        // An external object with a sensitive area must have fixedTPM == CLEAR
        // fixedParent == CLEAR so that it does not appear to be a key created by
        // this TPM.
        if(in->inPublic.publicArea.objectAttributes.fixedTPM != CLEAR
                || in->inPublic.publicArea.objectAttributes.fixedParent != CLEAR
                || in->inPublic.publicArea.objectAttributes.restricted != CLEAR)
            return TPM_RCS_ATTRIBUTES + RC_LoadExternal_inPublic;
        // Have sensitive point to something other than NULL so that object
        // initialization will load the sensitive part too
        sensitive = &in->inPrivate.sensitiveArea;
    }
    // Need the name to initialize the object structure
    PublicMarshalAndComputeName(&in->inPublic.publicArea, &out->name);
    // Load and validate key
    result = ObjectLoad(object, NULL,
                        &in->inPublic.publicArea, sensitive,
                        RC_LoadExternal_inPublic, RC_LoadExternal_inPrivate,
                        &out->name);
    if(result == TPM_RC_SUCCESS)
    {
        object->attributes.external = SET;
        // Set the common OBJECT attributes for a loaded object.
        ObjectSetLoadedAttributes(object, in->hierarchy);
    }
    return result;
}
#endif // CC_LoadExternal
