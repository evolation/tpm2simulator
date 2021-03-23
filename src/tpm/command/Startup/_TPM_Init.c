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
#include "_TPM_Init_fp.h"
// This function is used to process a _TPM_Init indication.
LIB_EXPORT void
_TPM_Init(
    void
)
{
    g_powerWasLost = g_powerWasLost | _plat__WasPowerLost();
#if defined SIMULATION && !defined NDEBUG
    // If power was lost and this was a simulation, put canary in RAM used by NV
    // so that uninitialized memory can be detected more easily
    if(g_powerWasLost)
    {
        memset(&gc, 0xbb, sizeof(gc));
        memset(&gr, 0xbb, sizeof(gr));
        memset(&gp, 0xbb, sizeof(gp));
        memset(&go, 0xbb, sizeof(go));
    }
#endif
#ifdef SIMULATION
    // Clear the flag that forces failure on self-test
    g_forceFailureMode = FALSE;
#endif
    // Set initialization state
    TPMInit();
    // Set g_DRTMHandle as unassigned
    g_DRTMHandle = TPM_RH_UNASSIGNED;
    // No H-CRTM, yet.
    g_DrtmPreStartup = FALSE;
    // Initialize the NvEnvironment.
    g_nvOk = NvPowerOn();
    // Initialize cryptographic functions
    g_inFailureMode = (CryptInit() == FALSE);
    if(!g_inFailureMode)
    {
        // Load the persistent data
        NvReadPersistent();
        // Load the orderly data (clock and DRBG state).
        // If this is not done here, things break
        NvRead(&go, NV_ORDERLY_DATA, sizeof(go));
        // Start clock. Need to do this after NV has been restored.
        TimePowerOn();
    }
    return;
}
