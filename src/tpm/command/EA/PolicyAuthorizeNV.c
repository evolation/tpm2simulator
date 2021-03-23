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
//#include "PolicyAuthorizeNV_fp.h"
#ifdef TPM_CC_PolicyAuthorizeNV                     // Conditional expansion of this file
#include "PolicyAuthorizeNV_fp.h"
#include "Policy_spt_fp.h"

// M e
// TPM_RC_HASH hash algorithm in keyName is not supported or is not the same as the
// hash algorithm of the policy session
// TPM_RC_SIZE keyName is not the correct size for its hash algorithm
// TPM_RC_VALUE the current policyDigest of policySession does not match
// approvedPolicy; or checkTicket doesn't match the provided values

TPM_RC
TPM2_PolicyAuthorizeNV(
    PolicyAuthorizeNV_In *in
)
{
    SESSION *session;
    TPM_RC result;
    NV_REF locator;
    NV_INDEX *nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPM2B_NAME name;
    TPMT_HA policyInNv;
    BYTE nvTemp[sizeof(TPMT_HA)];
    BYTE *buffer = nvTemp;
    INT32 size;
// Input Validation
    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    // Skip checks if this is a trial policy
    if(!session->attributes.isTrialPolicy)
    {
        // Check the authorizations for reading
        // Common read access checks. NvReadAccessChecks() returns
        // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
        // error may be returned at this point
        result = NvReadAccessChecks(in->authHandle, in->nvIndex,
                                    nvIndex->publicArea.attributes);
        if(result != TPM_RC_SUCCESS)
            return result;
        // Read the contents of the index into a temp buffer
        size = MIN(nvIndex->publicArea.dataSize, sizeof(TPMT_HA));
        NvGetIndexData(nvIndex, locator, 0, (UINT16)size, nvTemp);
        // Unmarshal the contents of the buffer into the internal format of a
        // TPMT_HA so that the hash and digest elements can be accessed from the
        // structure rather than the byte array that is in the Index (written by
        // user of the Index).
        result = TPMT_HA_Unmarshal(&policyInNv, &buffer, &size, FALSE);
        if(result != TPM_RC_SUCCESS)
            return result;
        // Verify that the hash is the same
        if(policyInNv.hashAlg != session->authHashAlg)
            return TPM_RC_HASH;
        // See if the contents of the digest in the Index matches the value
        // in the policy
        if(!MemoryEqual(&policyInNv.digest, &session->u2.policyDigest.t.buffer,
                        session->u2.policyDigest.t.size))
            return TPM_RC_VALUE;
    }
// Internal Data Update
    // Set policyDigest to zero digest
    PolicyDigestClear(session);
    // Update policyDigest
    PolicyContextUpdate(TPM_CC_PolicyAuthorizeNV, EntityGetName(in->nvIndex, &name),
                        NULL, NULL, 0, session);
    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyAuthorize
