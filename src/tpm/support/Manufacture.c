/******************************************************************************************************************/
/*                                                                                                                */
/*                                                                                                                */
/*  Licenses and Notices                                                                                          */
/*     Copyright Licenses:                                                                                        */
/*     ·  Trusted Computing Group (TCG) grants to the user of the source code in this specification (the         */
/*     "Source Code") a worldwide, irrevocable, nonexclusive, royalty free, copyright license to                  */
/*     reproduce, create derivative works, distribute, display and perform the Source Code and                    */
/*     derivative works thereof, and to grant others the rights granted herein.                                   */
/*     ·  The TCG grants to the user of the other parts of the specification (other than the Source Code)        */
/*     the rights to reproduce, distribute, display, and perform the specification solely for the purpose of      */
/*     developing products based on such documents.                                                               */
/*     Source Code Distribution Conditions:                                                                       */
/*     ·  Redistributions of Source Code must retain the above copyright licenses, this list of conditions       */
/*     and the following disclaimers.                                                                             */
/*     ·  Redistributions in binary form must reproduce the above copyright licenses, this list of conditions    */
/*     and the following disclaimers in the documentation and/or other materials provided with the                */
/*     distribution.                                                                                              */
/*     Disclaimers:                                                                                               */
/*     ·  THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF                                    */
/*     LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH                                      */
/*     RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)                                      */
/*     THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.                                        */
/*     Contact TCG Administration (admin@trustedcomputinggroup.org) for information on specification              */
/*     licensing rights available through TCG membership agreements.                                              */
/*     ·  THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                           */
/*     WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A                                     */
/*     PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF                                          */
/*     INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF                                     */
/*     ANY PROPOSAL, SPECIFICATION OR SAMPLE.                                                                     */
/*     ·  Without limitation, TCG and its members and licensors disclaim all liability, including liability for  */
/*     infringement of any proprietary rights, relating to use of information in this specification and to the    */
/*     implementation of this specification, and TCG disclaims all liability for cost of procurement of           */
/*     substitute goods or services, lost profits, loss of use, loss of data or any incidental, consequential,    */
/*     direct, indirect, or special damages, whether under contract, tort, warranty or otherwise, arising in      */
/*     any way out of use or reliance upon this specification or any information herein.                          */
/*     Any marks and brands contained herein are the property of their respective owners.                         */
/*                                                                                                                */
/******************************************************************************************************************/

// 9.9.1 Description
// This file contains the function that performs the manufacturing of the TPM in a simulated environment.
// These functions should not be used outside of a manufacturing or simulation environment.
// 9.9.2 Includes and Data Definitions
#define MANUFACTURE_C
#include "Tpm.h"
LIB_EXPORT int
TPM_Manufacture(
    int firstTime               // IN: indicates if this is the first call from
    // main()
)
{
    TPM_SU orderlyShutdown;
    // If TPM has been manufactured, return indication.
    if(!firstTime && g_manufactured)
        return 1;
    s_DAPendingOnNV = FALSE;
    // initialize NV
    NvManufacture();
    // Clear the magic value in the DRBG state
    go.drbgState.magic = 0;
    CryptStartup(SU_RESET);
    // default configuration for PCR
    PCRSimStart();
    // initialize pre-installed hierarchy data
    // This should happen after NV is initialized because hierarchy data is
    // stored in NV.
    HierarchyPreInstall_Init();
    // initialize dictionary attack parameters
    DAPreInstall_Init();
    // initialize PP list
    PhysicalPresencePreInstall_Init();
    // initialize command audit list
    CommandAuditPreInstall_Init();
    // first start up is required to be Startup(CLEAR)
    orderlyShutdown = TPM_SU_CLEAR;
    NV_WRITE_PERSISTENT(orderlyState, orderlyShutdown);
    // initialize the firmware version
    gp.firmwareV1 = FIRMWARE_V1;
#ifdef FIRMWARE_V2
    gp.firmwareV2 = FIRMWARE_V2;
#else
    gp.firmwareV2 = 0;
#endif
    NV_SYNC_PERSISTENT(firmwareV1);
    NV_SYNC_PERSISTENT(firmwareV2);
    // initialize the total reset counter to 0
    gp.totalResetCount = 0;
    NV_SYNC_PERSISTENT(totalResetCount);
    // initialize the clock stuff
    go.clock = 0;
    go.clockSafe = YES;
    NvWrite(NV_ORDERLY_DATA, sizeof(ORDERLY_DATA), &go);
    // Commit NV writes. Manufacture process is an artificial process existing
    // only in simulator environment and it is not defined in the specification
    // that what should be the expected behavior if the NV write fails at this
    // point. Therefore, it is assumed the NV write here is always success and
    // no return code of this function is checked.
    NvCommit();
    g_manufactured = TRUE;
    return 0;
}
LIB_EXPORT int
TPM_TearDown(
    void
)
{
    g_manufactured = FALSE;
    return 0;
}
LIB_EXPORT void
TpmEndSimulation(
    void
)
{
#ifdef SIMULATION
    HashLibSimulationEnd();
    SymLibSimulationEnd();
    MathLibSimulationEnd();
#ifdef TPM_ALG_RSA
    RsaSimulationEnd();
#endif
#ifdef TPM_ALG_ECC
    EccSimulationEnd();
#endif
#endif  // SIMULATION
}