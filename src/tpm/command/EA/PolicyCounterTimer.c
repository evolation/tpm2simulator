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
#include "PolicyCounterTimer_fp.h"
#ifdef TPM_CC_PolicyCounterTimer                        // Conditional expansion of this file
#include "Policy_spt_fp.h"

// M e
// TPM_RC_POLICY the comparison of the selected portion of the TPMS_TIME_INFO with
// operandB failed
// TPM_RC_RANGE offset + size exceed size of TPMS_TIME_INFO structure

TPM_RC
TPM2_PolicyCounterTimer(
    PolicyCounterTimer_In *in                       // IN: input parameter list
)
{
    SESSION *session;
    TIME_INFO infoData;                        // data buffer of TPMS_TIME_INFO
    BYTE *pInfoData = (BYTE *)&infoData;
    UINT16 infoDataSize;
    TPM_CC commandCode = TPM_CC_PolicyCounterTimer;
    HASH_STATE hashState;
    TPM2B_DIGEST argHash;
// Input Validation
    // Get a marshaled time structure
    infoDataSize = TimeGetMarshaled(&infoData);
    // Make sure that the referenced stays within the bounds of the structure.
    // NOTE: the offset checks are made even for a trial policy because the policy
    // will not make any sense if the references are out of bounds of the timer
    // structure.
    if(in->offset > infoDataSize)
        return TPM_RCS_VALUE + RC_PolicyCounterTimer_offset;
    if((UINT32)in->offset + (UINT32)in->operandB.t.size > infoDataSize)
        return TPM_RCS_RANGE;
    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    //If this is a trial policy, skip the check to see if the condition is met.
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // If the command is going to use any part of the counter or timer, need
        // to verify that time is advancing.
        // The time and clock vales are the first two 64-bit values in the clock
        if(in->offset < sizeof(UINT64) + sizeof(UINT64))
        {
            // Using Clock or Time so see if clock is running. Clock doesn't
            // run while NV is unavailable.
            // TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned here.
            RETURN_IF_NV_IS_NOT_AVAILABLE;
        }
        // offset to the starting position
        pInfoData = (BYTE *)infoData;
        // Check to see if the condition is valid
        if(!PolicySptCheckCondition(in->operation, pInfoData + in->offset,
                                    in->operandB.t.buffer, in->operandB.t.size))
            return TPM_RC_POLICY;
    }
// Internal Data Update
    // Start argument list hash
    argHash.t.size = CryptHashStart(&hashState, session->authHashAlg);
    // add operandB
    CryptDigestUpdate2B(&hashState, &in->operandB.b);
    // add offset
    CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->offset);
    // add operation
    CryptDigestUpdateInt(&hashState, sizeof(TPM_EO), in->operation);
    // complete argument hash
    CryptHashEnd2B(&hashState, &argHash.b);
    // update policyDigest
    // start hash
    CryptHashStart(&hashState, session->authHashAlg);
    // add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);
    // add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);
    // add argument digest
    CryptDigestUpdate2B(&hashState, &argHash.b);
    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);
    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyCounterTimer
