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
#include "NV_Increment_fp.h"
#ifdef TPM_CC_NV_Increment                 // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES NV index is not a counter
// TPM_RC_NV_AUTHORIZATION authorization failure
// TPM_RC_NV_LOCKED Index is write locked

TPM_RC
TPM2_NV_Increment(
    NV_Increment_In *in                        // IN: input parameter list
)
{
    TPM_RC result;
    NV_REF locator;
    NV_INDEX *nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    UINT64 countValue;
// Input Validation
    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle,
                                 in->nvIndex,
                                 nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;
    // Make sure that this is a counter
    if(!IsNvCounterIndex(nvIndex->publicArea.attributes))
        return TPM_RCS_ATTRIBUTES + RC_NV_Increment_nvIndex;
// Internal Data Update
    // If counter index is not been written, initialize it
    if(!IsNv_TPMA_NV_WRITTEN(nvIndex->publicArea.attributes))
        countValue = NvReadMaxCount();
    else
        // Read NV data in native format for TPM CPU.
        countValue = NvGetUINT64Data(nvIndex, locator);
    // Do the increment
    countValue++;
    // Write NV data back. A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may
    // be returned at this point. If necessary, this function will set the
    // TPMA_NV_WRITTEN attribute
    result = NvWriteUINT64Data(nvIndex, countValue);
    if(result == TPM_RC_SUCCESS)
    {
        // If a counter just rolled over, then force the NV update.
        // Note, if this is an orderly counter, then the write-back needs to be
        // forced, for other counters, the write-back will happen anyway
        if(IsNv_TPMA_NV_ORDERLY(nvIndex->publicArea.attributes)
                && (countValue & MAX_ORDERLY_COUNT) == 0 )
        {
            // Need to force an NV update of orderly data
            SET_NV_UPDATE(UT_ORDERLY);
        }
    }
    return result;
}
#endif // CC_NV_Increment
