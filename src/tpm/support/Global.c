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

// 9.5.1 Description
// This file will instance the TPM variables that are not stack allocated. The descriptions for these variables
// is in Global.h.
// 9.5.2 Includes and Defines
#define GLOBAL_C
#include "Tpm.h"
BOOL g_phEnable;
const UINT16 g_rcIndex[15] = {TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4,
                              TPM_RC_5, TPM_RC_6, TPM_RC_7, TPM_RC_8,
                              TPM_RC_9, TPM_RC_A, TPM_RC_B, TPM_RC_C,
                              TPM_RC_D, TPM_RC_E, TPM_RC_F
                             };
TPM_HANDLE g_exclusiveAuditSession;
UINT64 g_time;
#ifdef CLOCK_STOPS
CLOCK_NONCE g_timeEpoch;
#endif
BOOL g_timeNewEpochNeeded;
BOOL g_pcrReConfig;
TPMI_DH_OBJECT g_DRTMHandle;
BOOL g_DrtmPreStartup;
BOOL g_StartupLocality3;
#ifdef USE_DA_USED
BOOL g_daUsed;
#endif
BOOL g_powerWasLost;
BOOL g_clearOrderly;
TPM_SU g_prevOrderlyState;
UPDATE_TYPE g_updateNV;
BOOL g_nvOk;
TPM_RC g_NvStatus;
TPM2B_AUTH g_platformUniqueDetails;
STATE_CLEAR_DATA gc;
STATE_RESET_DATA gr;
PERSISTENT_DATA gp;
ORDERLY_DATA go;
#ifndef __IGNORE_STATE__             // DO NOT DEFINE THIS VALUE
TPM_HANDLE s_sessionHandles[MAX_SESSION_NUM];
TPMA_SESSION s_attributes[MAX_SESSION_NUM];
TPM_HANDLE s_associatedHandles[MAX_SESSION_NUM];
TPM2B_NONCE s_nonceCaller[MAX_SESSION_NUM];
TPM2B_AUTH s_inputAuthValues[MAX_SESSION_NUM];
SESSION *s_usedSessions[MAX_SESSION_NUM];
UINT32 s_encryptSessionIndex;
UINT32 s_decryptSessionIndex;
UINT32 s_auditSessionIndex;
#endif    // __IGNORE_STATE__
BOOL s_DAPendingOnNV;
#ifdef TPM_CC_GetCommandAuditDigest
TPM2B_DIGEST s_cpHashForCommandAudit;
#endif
UINT64 s_selfHealTimer;
UINT64 s_lockoutTimer;
UINT64 s_maxCounter;
NV_REF s_evictNvEnd;
TPM_RC g_NvStatus;
BYTE s_indexOrderlyRam[RAM_INDEX_SPACE];
NV_INDEX s_cachedNvIndex;
NV_REF s_cachedNvRef;
BYTE *s_cachedNvRamRef;
OBJECT s_objects[MAX_LOADED_OBJECTS];
PCR s_pcrs[IMPLEMENTATION_PCR];
SESSION_SLOT s_sessions[MAX_LOADED_SESSIONS];
UINT32 s_oldestSavedSession;
int s_freeSessionSlots;
#ifndef __IGNORE_STATE__            // DO NOT DEFINE THIS VALUE
UINT32 s_actionInputBuffer[1024];               // action input buffer
UINT32 s_actionOutputBuffer[1024];              // action output buffer
#endif
ALGORITHM_VECTOR g_implementedAlgorithms;
ALGORITHM_VECTOR g_toTest;
CRYPTO_SELF_TEST_STATE g_cryptoSelfTestState;
ALGORITHM_VECTOR AlgToTest;
#ifdef SIMULATION
BOOL g_forceFailureMode;
#endif
BOOL g_inFailureMode;
UINT32 s_failFunction;
UINT32 s_failLine;
UINT32 s_failCode;
#if 0
#ifdef TPM_ALG_ECC
ECC_CURVE c_curves[ECC_CURVE_COUNT];
#endif
#endif    // 0
RAND_STATE *s_random;
BOOL g_manufactured = FALSE;
BOOL g_initialized;
TPM2B_STRING(PRIMARY_OBJECT_CREATION, "Primary Object Creation");
TPM2B_STRING(CFB_KEY, "CFB");
TPM2B_STRING(CONTEXT_KEY, "CONTEXT");
TPM2B_STRING(INTEGRITY_KEY, "INTEGRITY");
TPM2B_STRING(SECRET_KEY, "SECRET");
TPM2B_STRING(SESSION_KEY, "ATH");
TPM2B_STRING(STORAGE_KEY, "STORAGE");
TPM2B_STRING(XOR_KEY, "XOR");
TPM2B_STRING(COMMIT_STRING, "ECDAA Commit");
TPM2B_STRING(DUPLICATE_STRING, "DUPLICATE");
TPM2B_STRING(IDENTITY_STRING, "IDENTITY");
TPM2B_STRING(OBFUSCATE_STRING, "OBFUSCATE");
#ifdef SELF_TEST
TPM2B_STRING(OAEP_TEST_STRING, "OAEP Test Value");
#endif  // SELF_TEST
