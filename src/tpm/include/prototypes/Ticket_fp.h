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

#ifndef _TICKET_FP_H_
#define _TICKET_FP_H_

BOOL
TicketIsSafe(
    TPM2B *buffer
);

void
TicketComputeVerified(
    TPMI_RH_HIERARCHY hierarchy,          // IN: hierarchy constant for ticket
    TPM2B_DIGEST *digest,            // IN: digest
    TPM2B_NAME *keyName,           // IN: name of key that signed the values
    TPMT_TK_VERIFIED *ticket             // OUT: verified ticket
);

void
TicketComputeAuth(
    TPM_ST type,               // IN: the type of ticket.
    TPMI_RH_HIERARCHY hierarchy,          // IN: hierarchy constant for ticket
    UINT64 timeout,            // IN: timeout
    BOOL expiresOnReset,// IN: flag to indicate if ticket expires on
    // TPM Reset
    TPM2B_DIGEST *cpHashA,           // IN: input cpHashA
    TPM2B_NONCE *policyRef,         // IN: input policyRef
    TPM2B_NAME *entityName,        // IN: name of entity
    TPMT_TK_AUTH *ticket             // OUT: Created ticket
);

void
TicketComputeHashCheck(
    TPMI_RH_HIERARCHY hierarchy,         // IN: hierarchy constant for ticket
    TPM_ALG_ID hashAlg,           // IN: the hash algorithm for 'digest'
    TPM2B_DIGEST *digest,           // IN: input digest
    TPMT_TK_HASHCHECK *ticket            // OUT: Created ticket
);

void
TicketComputeCreation(
    TPMI_RH_HIERARCHY hierarchy,         // IN: hierarchy for ticket
    TPM2B_NAME *name,             // IN: object name
    TPM2B_DIGEST *creation,         // IN: creation hash
    TPMT_TK_CREATION *ticket            // OUT: created ticket
);

#ifndef _IMPLEMENTATION_H_
#undef TRUE
#undef FALSE
#if defined ALG_RSA && ALG_RSA == YES
#endif
#if defined ALG_TDES && ALG_TDES == YES
#endif
#if defined ALG_SHA && ALG_SHA == YES
#endif
#if defined ALG_SHA1 && ALG_SHA1 == YES
#endif
#if defined ALG_HMAC && ALG_HMAC == YES
#endif
#if defined ALG_AES && ALG_AES == YES
#endif
#if defined ALG_MGF1 && ALG_MGF1 == YES
#endif
#if defined ALG_KEYEDHASH && ALG_KEYEDHASH == YES
#endif
#if defined ALG_XOR && ALG_XOR == YES
#endif
#if defined ALG_SHA256 && ALG_SHA256 == YES
#endif
#if defined ALG_SHA384 && ALG_SHA384 == YES
#endif
#if defined ALG_SHA512 && ALG_SHA512 == YES
#endif
#if defined ALG_SM3_256 && ALG_SM3_256 == YES
#endif
#if defined ALG_SM4 && ALG_SM4 == YES
#endif
#if defined ALG_RSASSA && ALG_RSASSA == YES
#endif
#if defined ALG_RSAES && ALG_RSAES == YES
#endif
#if defined ALG_RSAPSS && ALG_RSAPSS == YES
#endif
#if defined ALG_OAEP && ALG_OAEP == YES
#endif
#if defined ALG_ECDSA && ALG_ECDSA == YES
#endif
#if defined ALG_ECDH && ALG_ECDH == YES
#endif
#if defined ALG_ECDAA && ALG_ECDAA == YES
#endif
#if defined ALG_SM2 && ALG_SM2 == YES
#endif
#if defined ALG_ECSCHNORR && ALG_ECSCHNORR == YES
#endif
#if defined ALG_ECMQV && ALG_ECMQV == YES
#endif
#if defined ALG_KDF1_SP800_56A && ALG_KDF1_SP800_56A == YES
#endif
#if defined ALG_KDF2 && ALG_KDF2 == YES
#endif
#if defined ALG_KDF1_SP800_108 && ALG_KDF1_SP800_108 == YES
#endif
#if defined ALG_ECC && ALG_ECC == YES
#endif
#if defined ALG_SYMCIPHER && ALG_SYMCIPHER == YES
#endif
#if defined ALG_CAMELLIA && ALG_CAMELLIA == YES
#endif
#if defined ALG_CTR && ALG_CTR == YES
#endif
#if defined ALG_OFB && ALG_OFB == YES
#endif
#if defined ALG_CBC && ALG_CBC == YES
#endif
#if defined ALG_CFB && ALG_CFB == YES
#endif
#if defined ALG_ECB && ALG_ECB == YES
#endif
#ifndef CC_NV_UndefineSpaceSpecial
#endif
#if CC_NV_UndefineSpaceSpecial == YES
#endif
#ifndef CC_EvictControl
#endif
#if CC_EvictControl == YES
#endif
#ifndef CC_HierarchyControl
#endif
#if CC_HierarchyControl == YES
#endif
#ifndef CC_NV_UndefineSpace
#endif
#if CC_NV_UndefineSpace == YES
#endif
#ifndef CC_ChangeEPS
#endif
#if CC_ChangeEPS == YES
#endif
#ifndef CC_ChangePPS
#endif
#if CC_ChangePPS == YES
#endif
#ifndef CC_Clear
#endif
#if CC_Clear == YES
#endif
#ifndef CC_ClearControl
#endif
#if CC_ClearControl == YES
#endif
#ifndef CC_ClockSet
#endif
#if CC_ClockSet == YES
#endif
#ifndef CC_HierarchyChangeAuth
#endif
#if CC_HierarchyChangeAuth == YES
#endif
#ifndef CC_NV_DefineSpace
#endif
#if CC_NV_DefineSpace == YES
#endif
#ifndef CC_PCR_Allocate
#endif
#if CC_PCR_Allocate == YES
#endif
#ifndef CC_PCR_SetAuthPolicy
#endif
#if CC_PCR_SetAuthPolicy == YES
#endif
#ifndef CC_PP_Commands
#endif
#if CC_PP_Commands == YES
#endif
#ifndef CC_SetPrimaryPolicy
#endif
#if CC_SetPrimaryPolicy == YES
#endif
#ifndef CC_FieldUpgradeStart
#endif
#if CC_FieldUpgradeStart == YES
#endif
#ifndef CC_ClockRateAdjust
#endif
#if CC_ClockRateAdjust == YES
#endif
#ifndef CC_CreatePrimary
#endif
#if CC_CreatePrimary == YES
#endif
#ifndef CC_NV_GlobalWriteLock
#endif
#if CC_NV_GlobalWriteLock == YES
#endif
#ifndef CC_GetCommandAuditDigest
#endif
#if CC_GetCommandAuditDigest == YES
#endif
#ifndef CC_NV_Increment
#endif
#if CC_NV_Increment == YES
#endif
#ifndef CC_NV_SetBits
#endif
#if CC_NV_SetBits == YES
#endif
#ifndef CC_NV_Extend
#endif
#if CC_NV_Extend == YES
#endif
#ifndef CC_NV_Write
#endif
#if CC_NV_Write == YES
#endif
#ifndef CC_NV_WriteLock
#endif
#if CC_NV_WriteLock == YES
#endif
#ifndef CC_DictionaryAttackLockReset
#endif
#if CC_DictionaryAttackLockReset == YES
#endif
#ifndef CC_DictionaryAttackParameters
#endif
#if CC_DictionaryAttackParameters == YES
#endif
#ifndef CC_NV_ChangeAuth
#endif
#if CC_NV_ChangeAuth == YES
#endif
#ifndef CC_PCR_Event
#endif
#if CC_PCR_Event == YES
#endif
#ifndef CC_PCR_Reset
#endif
#if CC_PCR_Reset == YES
#endif
#ifndef CC_SequenceComplete
#endif
#if CC_SequenceComplete == YES
#endif
#ifndef CC_SetAlgorithmSet
#endif
#if CC_SetAlgorithmSet == YES
#endif
#ifndef CC_SetCommandCodeAuditStatus
#endif
#if CC_SetCommandCodeAuditStatus == YES
#endif
#ifndef CC_FieldUpgradeData
#endif
#if CC_FieldUpgradeData == YES
#endif
#ifndef CC_IncrementalSelfTest
#endif
#if CC_IncrementalSelfTest == YES
#endif
#ifndef CC_SelfTest
#endif
#if CC_SelfTest == YES
#endif
#ifndef CC_Startup
#endif
#if CC_Startup == YES
#endif
#ifndef CC_Shutdown
#endif
#if CC_Shutdown == YES
#endif
#ifndef CC_StirRandom
#endif
#if CC_StirRandom == YES
#endif
#ifndef CC_ActivateCredential
#endif
#if CC_ActivateCredential == YES
#endif
#ifndef CC_Certify
#endif
#if CC_Certify == YES
#endif
#ifndef CC_PolicyNV
#endif
#if CC_PolicyNV == YES
#endif
#ifndef CC_CertifyCreation
#endif
#if CC_CertifyCreation == YES
#endif
#ifndef CC_Duplicate
#endif
#if CC_Duplicate == YES
#endif
#ifndef CC_GetTime
#endif
#if CC_GetTime == YES
#endif
#ifndef CC_GetSessionAuditDigest
#endif
#if CC_GetSessionAuditDigest == YES
#endif
#ifndef CC_NV_Read
#endif
#if CC_NV_Read == YES
#endif
#ifndef CC_NV_ReadLock
#endif
#if CC_NV_ReadLock == YES
#endif
#ifndef CC_ObjectChangeAuth
#endif
#if CC_ObjectChangeAuth == YES
#endif
#ifndef CC_PolicySecret
#endif
#if CC_PolicySecret == YES
#endif
#ifndef CC_Rewrap
#endif
#if CC_Rewrap == YES
#endif
#ifndef CC_Create
#endif
#if CC_Create == YES
#endif
#ifndef CC_ECDH_ZGen
#endif
#if CC_ECDH_ZGen == YES
#endif
#ifndef CC_HMAC
#endif
#if CC_HMAC == YES
#endif
#ifndef CC_Import
#endif
#if CC_Import == YES
#endif
#ifndef CC_Load
#endif
#if CC_Load == YES
#endif
#ifndef CC_Quote
#endif
#if CC_Quote == YES
#endif
#ifndef CC_RSA_Decrypt
#endif
#if CC_RSA_Decrypt == YES
#endif
#ifndef CC_HMAC_Start
#endif
#if CC_HMAC_Start == YES
#endif
#ifndef CC_SequenceUpdate
#endif
#if CC_SequenceUpdate == YES
#endif
#ifndef CC_Sign
#endif
#if CC_Sign == YES
#endif
#ifndef CC_Unseal
#endif
#if CC_Unseal == YES
#endif
#ifndef CC_PolicySigned
#endif
#if CC_PolicySigned == YES
#endif
#ifndef CC_ContextLoad
#endif
#if CC_ContextLoad == YES
#endif
#ifndef CC_ContextSave
#endif
#if CC_ContextSave == YES
#endif
#ifndef CC_ECDH_KeyGen
#endif
#if CC_ECDH_KeyGen == YES
#endif
#ifndef CC_EncryptDecrypt
#endif
#if CC_EncryptDecrypt == YES
#endif
#ifndef CC_FlushContext
#endif
#if CC_FlushContext == YES
#endif
#ifndef CC_LoadExternal
#endif
#if CC_LoadExternal == YES
#endif
#ifndef CC_MakeCredential
#endif
#if CC_MakeCredential == YES
#endif
#ifndef CC_NV_ReadPublic
#endif
#if CC_NV_ReadPublic == YES
#endif
#ifndef CC_PolicyAuthorize
#endif
#if CC_PolicyAuthorize == YES
#endif
#ifndef CC_PolicyAuthValue
#endif
#if CC_PolicyAuthValue == YES
#endif
#ifndef CC_PolicyCommandCode
#endif
#if CC_PolicyCommandCode == YES
#endif
#ifndef CC_PolicyCounterTimer
#endif
#if CC_PolicyCounterTimer == YES
#endif
#ifndef CC_PolicyCpHash
#endif
#if CC_PolicyCpHash == YES
#endif
#ifndef CC_PolicyLocality
#endif
#if CC_PolicyLocality == YES
#endif
#ifndef CC_PolicyNameHash
#endif
#if CC_PolicyNameHash == YES
#endif
#ifndef CC_PolicyOR
#endif
#if CC_PolicyOR == YES
#endif
#ifndef CC_PolicyTicket
#endif
#if CC_PolicyTicket == YES
#endif
#ifndef CC_ReadPublic
#endif
#if CC_ReadPublic == YES
#endif
#ifndef CC_RSA_Encrypt
#endif
#if CC_RSA_Encrypt == YES
#endif
#ifndef CC_StartAuthSession
#endif
#if CC_StartAuthSession == YES
#endif
#ifndef CC_VerifySignature
#endif
#if CC_VerifySignature == YES
#endif
#ifndef CC_ECC_Parameters
#endif
#if CC_ECC_Parameters == YES
#endif
#ifndef CC_FirmwareRead
#endif
#if CC_FirmwareRead == YES
#endif
#ifndef CC_GetCapability
#endif
#if CC_GetCapability == YES
#endif
#ifndef CC_GetRandom
#endif
#if CC_GetRandom == YES
#endif
#ifndef CC_GetTestResult
#endif
#if CC_GetTestResult == YES
#endif
#ifndef CC_Hash
#endif
#if CC_Hash == YES
#endif
#ifndef CC_PCR_Read
#endif
#if CC_PCR_Read == YES
#endif
#ifndef CC_PolicyPCR
#endif
#if CC_PolicyPCR == YES
#endif
#ifndef CC_PolicyRestart
#endif
#if CC_PolicyRestart == YES
#endif
#ifndef CC_ReadClock
#endif
#if CC_ReadClock == YES
#endif
#ifndef CC_PCR_Extend
#endif
#if CC_PCR_Extend == YES
#endif
#ifndef CC_PCR_SetAuthValue
#endif
#if CC_PCR_SetAuthValue == YES
#endif
#ifndef CC_NV_Certify
#endif
#if CC_NV_Certify == YES
#endif
#ifndef CC_EventSequenceComplete
#endif
#if CC_EventSequenceComplete == YES
#endif
#ifndef CC_HashSequenceStart
#endif
#if CC_HashSequenceStart == YES
#endif
#ifndef CC_PolicyPhysicalPresence
#endif
#if CC_PolicyPhysicalPresence == YES
#endif
#ifndef CC_PolicyDuplicationSelect
#endif
#if CC_PolicyDuplicationSelect == YES
#endif
#ifndef CC_PolicyGetDigest
#endif
#if CC_PolicyGetDigest == YES
#endif
#ifndef CC_TestParms
#endif
#if CC_TestParms == YES
#endif
#ifndef CC_Commit
#endif
#if CC_Commit == YES
#endif
#ifndef CC_PolicyPassword
#endif
#if CC_PolicyPassword == YES
#endif
#ifndef CC_ZGen_2Phase
#endif
#if CC_ZGen_2Phase == YES
#endif
#ifndef CC_EC_Ephemeral
#endif
#if CC_EC_Ephemeral == YES
#endif
#ifndef CC_PolicyNvWritten
#endif
#if CC_PolicyNvWritten == YES
#endif
#ifndef CC_PolicyTemplate
#endif
#if CC_PolicyTemplate == YES
#endif
#ifndef CC_CreateLoaded
#endif
#if CC_CreateLoaded == YES
#endif
#ifndef CC_PolicyAuthorizeNV
#endif
#if CC_PolicyAuthorizeNV == YES
#endif
#ifndef CC_EncryptDecrypt2
#endif
#if CC_EncryptDecrypt2 == YES
#endif
#ifndef CC_Vendor_TCG_Test
#endif
#if CC_Vendor_TCG_Test == YES
#endif
#ifndef COMPRESSED_LISTS
#else
#endif
#ifndef MAX
#endif
#if MAX_DIGEST_SIZE == 0 || MAX_HASH_BLOCK_SIZE == 0
#endif
TPM2B_TYPE(MAX_HASH_BLOCK, MAX_HASH_BLOCK_SIZE);
#ifndef MAX
#endif
#ifndef ALG_AES
#endif
#ifndef MAX_AES_KEY_BITS
#endif
#ifndef ALG_CAMELLIA
#endif
#ifndef MAX_CAMELLIA_KEY_BITS
#endif
#ifndef ALG_SM4
#endif
#ifndef MAX_SM4_KEY_BITS
#endif
#ifndef ALG_TDES
#endif
#ifndef MAX_TDES_KEY_BITS
#endif
#if MAX_SYM_KEY_BITS == 0 || MAX_SYM_BLOCK_SIZE == 0
#endif
TPM2B_TYPE(SEED, PRIMARY_SEED_SIZE);
#endif   // _IMPLEMENTATION_H_
#endif  // _TICKET_FP_H_
