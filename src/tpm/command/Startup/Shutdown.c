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
#include "Shutdown_fp.h"
#ifdef TPM_CC_Shutdown         // Conditional expansion of this file

// M e
// TPM_RC_TYPE if PCR bank has been re-configured, a CLEAR StateSave() is
// required

TPM_RC
TPM2_Shutdown(
    Shutdown_In *in                    // IN: input parameter list
)
{
    // The command needs NV update. Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    RETURN_IF_NV_IS_NOT_AVAILABLE;
// Input Validation
    // If PCR bank has been reconfigured, a CLEAR state save is required
    if(g_pcrReConfig && in->shutdownType == TPM_SU_STATE)
        return TPM_RCS_TYPE + RC_Shutdown_shutdownType;
// Internal Data Update
    gp.orderlyState = in->shutdownType;
    // PCR private date state save
    PCRStateSave(in->shutdownType);
    // Save RAM backed NV index data
    NvUpdateIndexOrderlyData();
    // Save all orderly data
    NvWrite(NV_ORDERLY_DATA, sizeof(ORDERLY_DATA), &go);
    if(in->shutdownType == TPM_SU_STATE)
    {
        // Save STATE_RESET and STATE_CLEAR data
        NvWrite(NV_STATE_CLEAR_DATA, sizeof(STATE_CLEAR_DATA), &gc);
        NvWrite(NV_STATE_RESET_DATA, sizeof(STATE_RESET_DATA), &gr);
        // Save the startup flags for resume
        if(g_DrtmPreStartup)
            gp.orderlyState = TPM_SU_STATE | PRE_STARTUP_FLAG;
        else if(g_StartupLocality3)
            gp.orderlyState = TPM_SU_STATE | STARTUP_LOCALITY_3;
    }
    else if(in->shutdownType == TPM_SU_CLEAR)
    {
        // Save STATE_RESET data
        NvWrite(NV_STATE_RESET_DATA, sizeof(STATE_RESET_DATA), &gr);
    }
    else
        FAIL(FATAL_ERROR_INTERNAL);
    NV_SYNC_PERSISTENT(orderlyState);
    return TPM_RC_SUCCESS;
}
#endif // CC_Shutdown
