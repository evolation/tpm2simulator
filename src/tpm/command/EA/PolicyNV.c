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
#include "PolicyNV_fp.h"
#ifdef TPM_CC_PolicyNV             // Conditional expansion of this file
#include "Policy_spt_fp.h"

// M e
// TPM_RC_AUTH_TYPE NV index authorization type is not correct
// TPM_RC_NV_LOCKED NV index read locked
// TPM_RC_NV_UNINITIALIZED the NV index has not been initialized
// TPM_RC_POLICY the comparison to the NV contents failed
// TPM_RC_SIZE the size of nvIndex data starting at offset is less than the size of
// operandB
// TPM_RC_VALUE offset is too large

TPM_RC
TPM2_PolicyNV(
    PolicyNV_In *in                      // IN: input parameter list
)
{
    TPM_RC result;
    SESSION *session;
    NV_REF locator;
    NV_INDEX *nvIndex;
    BYTE nvBuffer[sizeof(in->operandB.t.buffer)];
    TPM2B_NAME nvName;
    TPM_CC commandCode = TPM_CC_PolicyNV;
    HASH_STATE hashState;
    TPM2B_DIGEST argHash;
// Input Validation
    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    //If this is a trial policy, skip all validations and the operation
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // No need to access the actual NV index information for a trial policy.
        nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
        // Common read access checks. NvReadAccessChecks() may return
        // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
        result = NvReadAccessChecks(in->authHandle,
                                    in->nvIndex,
                                    nvIndex->publicArea.attributes);
        if(result != TPM_RC_SUCCESS)
            return result;
        // Make sure that offset is withing range
        if(in->offset > nvIndex->publicArea.dataSize)
            return TPM_RCS_VALUE + RC_PolicyNV_offset;
        // Valid NV data size should not be smaller than input operandB size
        if((nvIndex->publicArea.dataSize - in->offset) < in->operandB.t.size)
            return TPM_RCS_SIZE + RC_PolicyNV_operandB;
        // Get NV data. The size of NV data equals the input operand B size
        NvGetIndexData(nvIndex, locator, in->offset, in->operandB.t.size, nvBuffer);
        // Check to see if the condition is valid
        if(!PolicySptCheckCondition(in->operation, nvBuffer,
                                    in->operandB.t.buffer, in->operandB.t.size))
            return TPM_RC_POLICY;
    }
// Internal Data Update
    // Start argument hash
    argHash.t.size = CryptHashStart(&hashState, session->authHashAlg);
    // add operandB
    CryptDigestUpdate2B(&hashState, &in->operandB.b);
    // add offset
    CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->offset);
    // add operation
    CryptDigestUpdateInt(&hashState, sizeof(TPM_EO), in->operation);
    // complete argument digest
    CryptHashEnd2B(&hashState, &argHash.b);
    // Update policyDigest
    // Start digest
    CryptHashStart(&hashState, session->authHashAlg);
    // add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);
    // add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);
    // add argument digest
    CryptDigestUpdate2B(&hashState, &argHash.b);
    // Adding nvName
    CryptDigestUpdate2B(&hashState, &EntityGetName(in->nvIndex, &nvName)->b);
    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);
    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyNV
