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
#include "Clear_fp.h"
#ifdef TPM_CC_Clear          // Conditional expansion of this file

// M e
// TPM_RC_DISABLED Clear command has been disabled

TPM_RC
TPM2_Clear(
    Clear_In *in                         // IN: input parameter list
)
{
    // Input parameter is not reference in command action
    NOT_REFERENCED(in);
    // The command needs NV update. Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    RETURN_IF_NV_IS_NOT_AVAILABLE;
// Input Validation
    // If Clear command is disabled, return an error
    if(gp.disableClear)
        return TPM_RC_DISABLED;
// Internal Data Update
    // Reset storage hierarchy seed from RNG
    CryptRandomGenerate(PRIMARY_SEED_SIZE, gp.SPSeed.t.buffer);
    // Create new shProof and ehProof value from RNG
    CryptRandomGenerate(PROOF_SIZE, gp.shProof.t.buffer);
    CryptRandomGenerate(PROOF_SIZE, gp.ehProof.t.buffer);
    // Enable storage and endorsement hierarchy
    gc.shEnable = gc.ehEnable = TRUE;
    // set the authValue buffers to zero
    MemorySet(&gp.ownerAuth, 0, sizeof(gp.ownerAuth));
    MemorySet(&gp.endorsementAuth, 0, sizeof(gp.endorsementAuth));
    MemorySet(&gp.lockoutAuth, 0, sizeof(gp.lockoutAuth));
    // Set storage, endorsement, and lockout authPolicy to null
    gp.ownerAlg = gp.endorsementAlg = gp.lockoutAlg = TPM_ALG_NULL;
    MemorySet(&gp.ownerPolicy, 0, sizeof(gp.ownerPolicy));
    MemorySet(&gp.endorsementPolicy, 0, sizeof(gp.endorsementPolicy));
    MemorySet(&gp.lockoutPolicy, 0, sizeof(gp.lockoutPolicy));
    // Flush loaded object in storage and endorsement hierarchy
    ObjectFlushHierarchy(TPM_RH_OWNER);
    ObjectFlushHierarchy(TPM_RH_ENDORSEMENT);
    // Flush owner and endorsement object and owner index in NV
    NvFlushHierarchy(TPM_RH_OWNER);
    NvFlushHierarchy(TPM_RH_ENDORSEMENT);
    // Initialize dictionary attack parameters
    DAPreInstall_Init();
    // Reset clock
    go.clock = 0;
    go.clockSafe = YES;
    NvWrite(NV_ORDERLY_DATA, sizeof(ORDERLY_DATA), &go);
    // Reset counters
    gp.resetCount = gr.restartCount = gr.clearCount = 0;
    gp.auditCounter = 0;
    // Save persistent data changes to NV
    // Note: since there are so many changes to the persistent data structure, the
    // entire PERSISTENT_DATA structure is written as a unit
    NvWrite(NV_PERSISTENT_DATA, sizeof(PERSISTENT_DATA), &gp);
    // Reset the PCR authValues (this does not change the PCRs)
    PCR_ClearAuth();
    // Bump the PCR counter
    PCRChanged(0);
    // orderly state should be cleared because of the update to state clear data
    g_clearOrderly = TRUE;
    return TPM_RC_SUCCESS;
}
#endif // CC_Clear
