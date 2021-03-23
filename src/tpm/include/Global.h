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

#ifndef GLOBAL_H
#define GLOBAL_H
//#define SELF_TEST
#if defined(_Win32) || defined(WIN32)
_REDUCE_WARNING_LEVEL_(2)
#endif
#include <string.h>
//#include <setjmp.h>
#include <stddef.h>
_NORMAL_WARNING_LEVEL_
#ifdef SIMULATION
#undef CONTEXT_SLOT
# define CONTEXT_SLOT UINT8
#endif
#include "Capabilities.h"
#include "TpmTypes.h"
#include "CommandAttributes.h"
#include "CryptTest.h"
#include "BnValues.h"
#include "CryptHash.h"
#include "CryptRand.h"
#include "CryptEcc.h"
#include "CryptRsa.h"
#include "CryptTest.h"
#include "TpmError.h"
#include "NV.h"
//** Defines and Types
//*** Crypto Self-Test Values
extern ALGORITHM_VECTOR g_implementedAlgorithms;
extern ALGORITHM_VECTOR g_toTest;
//*** Size Types
// These types are used to differentiate the two different size values used.
//
// NUMBYTES is used when a size is a number of bytes (usually a TPM2B)
typedef UINT16 NUMBYTES;
//*** Other Types
// An AUTH_VALUE is a BYTE array containing a digest (TPMU_HA)
typedef BYTE AUTH_VALUE[sizeof(TPMU_HA)];
typedef BYTE TIME_INFO[sizeof(TPMS_TIME_INFO)];
typedef BYTE NAME[sizeof(TPMU_NAME)];
#ifdef CLOCK_STOPS
typedef UINT64 CLOCK_NONCE;
#else
typedef UINT32 CLOCK_NONCE;
#endif
typedef struct
{
    unsigned publicOnly : 1;       //0) SET if only the public portion of
    // an object is loaded
    unsigned epsHierarchy : 1;   //1) SET if the object belongs to EPS
    // Hierarchy
    unsigned ppsHierarchy : 1;   //2) SET if the object belongs to PPS
    // Hierarchy
    unsigned spsHierarchy : 1;   //3) SET f the object belongs to SPS
    // Hierarchy
    unsigned evict : 1;                    //4) SET if the object is a platform or
    // owner evict object. Platform-
    // evict object belongs to PPS
    // hierarchy, owner-evict object
    // belongs to SPS or EPS hierarchy.
    // This bit is also used to mark a
    // completed sequence object so it
    // will be flush when the
    // SequenceComplete command succeeds.
    unsigned primary : 1;              //5) SET for a primary object
    unsigned temporary : 1;        //6) SET for a temporary object
    unsigned stClear : 1;              //7) SET for an stClear object
    unsigned hmacSeq : 1;              //8) SET for an HMAC sequence object
    unsigned hashSeq : 1;              //9) SET for a hash sequence object
    unsigned eventSeq : 1;           //10) SET for an event sequence object
    unsigned ticketSafe : 1;       //11) SET if a ticket is safe to create
    // for hash sequence object
    unsigned firstBlock : 1;       //12) SET if the first block of hash
    // data has been received. It
    // works with ticketSafe bit
    unsigned isParent : 1;           //13) SET if the key has the proper
    // attributes to be a parent key
    unsigned privateExp : 1;      //14) SET when the private exponent
    // of an RSA key has been validated.
    unsigned occupied : 1;           //15) SET when the slot is occupied.
    unsigned derivation : 1;      //16) SET when the key is a derivation
    // parent
    unsigned external : 1;           //17) SET when the object is loaded with
    // TPM2_LoadExternal();
} OBJECT_ATTRIBUTES;
typedef struct OBJECT
{
    // The attributes field is required to be first followed by the publicArea.
    // This allows the overlay of the object structure and a sequence structure
    OBJECT_ATTRIBUTES attributes;                  // object attributes
    TPMT_PUBLIC publicArea;                  // public area of an object
    TPMT_SENSITIVE sensitive;                   // sensitive area of an object
#ifdef TPM_ALG_RSA
    privateExponent_t privateExponent;             // Additional field for the private
#endif
    TPM2B_NAME qualifiedName;               // object qualified name
    TPMI_DH_OBJECT evictHandle;                 // if the object is an evict object,
    // the original handle is kept here.
    // The 'working' handle will be the
    // handle of an object slot.
    TPM2B_NAME name;                        // Name of the object name. Kept here
    // to avoid repeatedly computing it.
} OBJECT;
typedef struct HASH_OBJECT
{
    OBJECT_ATTRIBUTES attributes;                  // The attributes of the HASH object
    TPMI_ALG_PUBLIC type;                        // algorithm
    TPMI_ALG_HASH nameAlg;                     // name algorithm
    TPMA_OBJECT objectAttributes;            // object attributes
    // The data below is unique to a sequence object
    TPM2B_AUTH auth;                        // authorization for use of sequence
    union
    {
        HASH_STATE hashState[HASH_COUNT];
        HMAC_STATE hmacState;
    } state;
} HASH_OBJECT;
typedef BYTE HASH_OBJECT_BUFFER[sizeof(HASH_OBJECT)];
typedef union ANY_OBJECT
{
    OBJECT entity;
    HASH_OBJECT hash;
} ANY_OBJECT;
typedef BYTE ANY_OBJECT_BUFFER[sizeof(ANY_OBJECT)];
typedef UINT32 AUTH_ROLE;
#define AUTH_NONE ((AUTH_ROLE)(0))
#define AUTH_USER ((AUTH_ROLE)(1))
#define AUTH_ADMIN ((AUTH_ROLE)(2))
#define AUTH_DUP ((AUTH_ROLE)(3))
typedef struct SESSION_ATTRIBUTES
{
    unsigned isPolicy : 1;                       //1) SET if the session may only be used
    // for policy
    unsigned isAudit : 1;                       //2) SET if the session is used for audit
    unsigned isBound : 1;                       //3) SET if the session is bound to with an
    // entity. This attribute will be CLEAR
    // if either isPolicy or isAudit is SET.
    unsigned isCpHashDefined : 1;      //3) SET if the cpHash has been defined
    // This attribute is not SET unless
    // 'isPolicy' is SET.
    unsigned isAuthValueNeeded : 1;  //5) SET if the authValue is required for
    // computing the session HMAC. This
    // attribute is not SET unless 'isPolicy'
    // is SET.
    unsigned isPasswordNeeded : 1;   //6) SET if a password authValue is required
    // for authorization This attribute is not
    // SET unless 'isPolicy' is SET.
    unsigned isPPRequired : 1;             //7) SET if physical presence is required to
    // be asserted when the authorization is
    // checked. This attribute is not SET
    // unless 'isPolicy' is SET.
    unsigned isTrialPolicy : 1;             //8) SET if the policy session is created
    // for trial of the policy's policyHash
    // generation. This attribute is not SET
    // unless 'isPolicy' is SET.
    unsigned isDaBound : 1;                         //9) SET if the bind entity had noDA CLEAR.
    // If this is SET, then an authorization
    // failure using this session will count
    // against lockout even if the object
    // being authorized is exempt from DA.
    unsigned isLockoutBound : 1;              //10) SET if the session is bound to
    // lockoutAuth.
    unsigned includeAuth : 1;                    //11) This attribute is SET when the
    // authValue of an object is to be
    // included in the computation of the
    // HMAC key for the command and response
    // computations. (was 'requestWasBound')
    unsigned checkNvWritten : 1;              //12) SET if the TPMA_NV_WRITTEN attribute
    // needs to be checked when the policy is
    // used for authorization for NV access.
    // If this is SET for any other type, the
    // policy will fail.
    unsigned nvWrittenState : 1;              //13) SET if TPMA_NV_WRITTEN is required to
    // be SET. Used when 'checkNvWritten' is
    // SET
    unsigned isTemplateSet : 1;              //14) SET if the templateHash needs to be
    // checked for Create, CreatePrimary, or
    // CreateLoaded.
} SESSION_ATTRIBUTES;
typedef struct SESSION
{
    SESSION_ATTRIBUTES attributes;                         // session attributes
    UINT32 pcrCounter;                         // PCR counter value when PCR is
    // included (policy session)
    // If no PCR is included, this
    // value is 0.
    UINT64 startTime;                          // The value in g_time when the session
    // was started (policy session)
    UINT64 timeout;                            // The timeout relative to g_time
    // There is no timeout if this value
    // is 0.
    CLOCK_NONCE epoch;                              // The g_clockEpoch value when the
    // session was started. If g_clockEpoch
    // does not match this value when the
    // timeout is used, then
    // then the command will fail.
    TPM_CC commandCode;                        // command code (policy session)
    TPM_ALG_ID authHashAlg;                        // session hash algorithm
    TPMA_LOCALITY commandLocality;                    // command locality (policy session)
    TPMT_SYM_DEF symmetric;                          // session symmetric algorithm (if any)
    TPM2B_AUTH sessionKey;                         // session secret value used for
    // this session
    TPM2B_NONCE nonceTPM;                           // last TPM-generated nonce for
    // generating HMAC and encryption keys
    union
    {
        TPM2B_NAME boundEntity;                        // value used to track the entity to
        // which the session is bound
        TPM2B_DIGEST cpHash;                             // the required cpHash value for the
        // command being authorized
        TPM2B_DIGEST nameHash;                   // the required nameHash
        TPM2B_DIGEST templateHash;               // the required template for creation
    } u1;
    union
    {
        TPM2B_DIGEST auditDigest;                // audit session digest
        TPM2B_DIGEST policyDigest;               // policyHash
    } u2;                                              // audit log and policyHash may
    // share space to save memory
} SESSION;
#define EXPIRES_ON_RESET INT32_MIN
#define TIMEOUT_ON_RESET UINT64_MAX
#define EXPIRES_ON_RESTART (INT32_MIN + 1)
#define TIMEOUT_ON_RESTART (UINT64_MAX - 1)
typedef BYTE SESSION_BUF[sizeof(SESSION)];
typedef struct PCR_SAVE
{
#ifdef TPM_ALG_SHA1
    BYTE sha1[NUM_STATIC_PCR][SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    BYTE sha256[NUM_STATIC_PCR][SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    BYTE sha384[NUM_STATIC_PCR][SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    BYTE sha512[NUM_STATIC_PCR][SHA512_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SM3_256
    BYTE sm3_256[NUM_STATIC_PCR][SM3_256_DIGEST_SIZE];
#endif
    // This counter increments whenever the PCR are updated.
    // NOTE: A platform-specific specification may designate
    // certain PCR changes as not causing this counter
    // to increment.
    UINT32 pcrCounter;
} PCR_SAVE;
#if defined NUM_POLICY_PCR_GROUP && NUM_POLICY_PCR_GROUP > 0
typedef struct PCR_POLICY
{
    TPMI_ALG_HASH hashAlg[NUM_POLICY_PCR_GROUP];
    TPM2B_DIGEST a;
    TPM2B_DIGEST policy[NUM_POLICY_PCR_GROUP];
} PCR_POLICY;
#endif
typedef struct PCR_AUTH_VALUE
{
    TPM2B_DIGEST auth[NUM_AUTHVALUE_PCR_GROUP];
} PCR_AUTHVALUE;
typedef enum
{
    SU_RESET,
    SU_RESTART,
    SU_RESUME
} STARTUP_TYPE;
typedef struct NV_INDEX
{
    TPMS_NV_PUBLIC publicArea;
    TPM2B_AUTH authValue;
} NV_INDEX;
typedef UINT32 NV_REF;
typedef BYTE *NV_RAM_REF;
#if BIG_ENDIAN_TPM == YES
typedef struct
{
    UINT32 pinCount;
    UINT32 pinLimit;
} PIN_DATA;
#else
typedef struct
{
    UINT32 pinLimit;
    UINT32 pinCount;
} PIN_DATA;
#endif
typedef union
{
    UINT64 intVal;
    PIN_DATA pin;
} NV_PIN;
#ifdef TPM_ALG_ECC
#define COMMIT_INDEX_MASK ((UINT16)((sizeof(gr.commitArray)*8)-1))
#endif
extern const UINT16 g_rcIndex[15];
extern TPM_HANDLE g_exclusiveAuditSession;
extern UINT64 g_time;
#ifdef CLOCK_STOPS
extern CLOCK_NONCE g_timeEpoch;
#else
#define g_timeEpoch gp.timeEpoch
#endif
extern BOOL g_timeNewEpochNeeded;
extern BOOL g_phEnable;
extern BOOL g_pcrReConfig;
extern TPMI_DH_OBJECT g_DRTMHandle;
extern BOOL g_DrtmPreStartup;
extern BOOL g_StartupLocality3;
#define SU_NONE_VALUE (0xFFFF)
#define TPM_SU_NONE (TPM_SU)(SU_NONE_VALUE)
#define SU_DA_USED_VALUE (SU_NONE_VALUE - 1)
#define TPM_SU_DA_USED (TPM_SU)(SU_DA_USED_VALUE)
#define PRE_STARTUP_FLAG 0x8000
#define STARTUP_LOCALITY_3 0x4000
#ifdef USE_DA_USED
extern BOOL g_daUsed;
#endif
typedef BYTE UPDATE_TYPE;
#define UT_NONE (UPDATE_TYPE)0
#define UT_NV (UPDATE_TYPE)1
#define UT_ORDERLY (UPDATE_TYPE)(UT_NV + 2)
extern UPDATE_TYPE g_updateNV;
extern BOOL g_powerWasLost;
extern BOOL g_clearOrderly;
extern TPM_SU g_prevOrderlyState;
extern BOOL g_nvOk;
extern TPM_RC g_NvStatus;
extern TPM2B_AUTH g_platformUniqueAuthorities;              // Reserved for RNG
extern TPM2B_AUTH g_platformUniqueDetails;              // referenced by VENDOR_PERMANENT
typedef struct
{
//*********************************************************************************
// Hierarchy
//*********************************************************************************
// The values in this section are related to the hierarchies.
    BOOL disableClear;                       // TRUE if TPM2_Clear() using
    // lockoutAuth is disabled
    // Hierarchy authPolicies
    TPMI_ALG_HASH ownerAlg;
    TPMI_ALG_HASH endorsementAlg;
    TPMI_ALG_HASH lockoutAlg;
    TPM2B_DIGEST ownerPolicy;
    TPM2B_DIGEST endorsementPolicy;
    TPM2B_DIGEST lockoutPolicy;
    // Hierarchy authValues
    TPM2B_AUTH ownerAuth;
    TPM2B_AUTH endorsementAuth;
    TPM2B_AUTH lockoutAuth;
    // Primary Seeds
    TPM2B_SEED EPSeed;
    TPM2B_SEED SPSeed;
    TPM2B_SEED PPSeed;
    // Note there is a nullSeed in the state_reset memory.
    // Hierarchy proofs
    TPM2B_AUTH phProof;
    TPM2B_AUTH shProof;
    TPM2B_AUTH ehProof;
    // Note there is a nullProof in the state_reset memory.
//*********************************************************************************
// Reset Events
//*********************************************************************************
// A count that increments at each TPM reset and never get reset during the life
// time of TPM. The value of this counter is initialized to 1 during TPM
// manufacture process. It is used to invalidate all saved contexts after a TPM
// Reset.
    UINT64 totalResetCount;
// This counter increments on each TPM Reset. The counter is reset by
// TPM2_Clear().
    UINT32 resetCount;
//*********************************************************************************
// PCR
//*********************************************************************************
// This structure hold the policies for those PCR that have an update policy.
// This implementation only supports a single group of PCR controlled by
// policy. If more are required, then this structure would be changed to
// an array.
#if defined NUM_POLICY_PCR_GROUP && NUM_POLICY_PCR_GROUP > 0
    PCR_POLICY pcrPolicies;
#endif
// This structure indicates the allocation of PCR. The structure contains a
// list of PCR allocations for each implemented algorithm. If no PCR are
// allocated for an algorithm, a list entry still exists but the bit map
// will contain no SET bits.
    TPML_PCR_SELECTION pcrAllocated;
//*********************************************************************************
// Physical Presence
//*********************************************************************************
// The PP_LIST type contains a bit map of the commands that require physical
// to be asserted when the authorization is evaluated. Physical presence will be
// checked if the corresponding bit in the array is SET and if the authorization
// handle is TPM_RH_PLATFORM.
//
// These bits may be changed with TPM2_PP_Commands().
    BYTE ppList[(COMMAND_COUNT + 7)   / 8];
//*********************************************************************************
// Dictionary attack values
//*********************************************************************************
// These values are used for dictionary attack tracking and control.
    UINT32 failedTries;                      // the current count of unexpired
    // authorization failures
    UINT32 maxTries;                         // number of unexpired authorization
    // failures before the TPM is in
    // lockout
    UINT32 recoveryTime;                     // time between authorization failures
    // before failedTries is decremented
    UINT32 lockoutRecovery;                  // time that must expire between
    // authorization failures associated
    // with lockoutAuth
    BOOL lockOutAuthEnabled;               // TRUE if use of lockoutAuth is
    // allowed
//*****************************************************************************
// Orderly State
//*****************************************************************************
// The orderly state for current cycle
    TPM_SU orderlyState;
//*****************************************************************************
// Command audit values.
//*****************************************************************************
    BYTE auditCommands[((COMMAND_COUNT + 1) + 7)     / 8];
    TPMI_ALG_HASH auditHashAlg;
    UINT64 auditCounter;
//*****************************************************************************
// Algorithm selection
//*****************************************************************************
//
// The 'algorithmSet' value indicates the collection of algorithms that are
// currently in used on the TPM. The interpretation of value is vendor dependent.
    UINT32 algorithmSet;
//*****************************************************************************
// Firmware version
//*****************************************************************************
// The firmwareV1 and firmwareV2 values are instanced in TimeStamp.c. This is
// a scheme used in development to allow determination of the linker build time
// of the TPM. An actual implementation would implement these values in a way that
// is consistent with vendor needs. The values are maintained in RAM for simplified
// access with a master version in NV. These values are modified in a
// vendor-specific way.
// g_firmwareV1 contains the more significant 32-bits of the vendor version number.
// In the reference implementation, if this value is printed as a hex
// value, it will have the format of YYYYMMDD
    UINT32 firmwareV1;
// g_firmwareV1 contains the less significant 32-bits of the vendor version number.
// In the reference implementation, if this value is printed as a hex
// value, it will have the format of 00 HH MM SS
    UINT32 firmwareV2;
//*****************************************************************************
// Timer Epoch
//*****************************************************************************
// timeEpoch contains a nonce that has a vendor=specific size (should not be
// less than 8 bytes. This nonce changes when the clock epoch changes. The clock
// epoch changes when there is a discontinuity in the timing of the TPM.
#ifndef CLOCK_STOPS
    CLOCK_NONCE timeEpoch;
#endif
} PERSISTENT_DATA;
extern PERSISTENT_DATA gp;
typedef struct orderly_data
{
//*****************************************************************************
// TIME
//*****************************************************************************
// Clock has two parts. One is the state save part and one is the NV part. The
// state save version is updated on each command. When the clock rolls over, the
// NV version is updated. When the TPM starts up, if the TPM was shutdown in and
// orderly way, then the sClock value is used to initialize the clock. If the
// TPM shutdown was not orderly, then the persistent value is used and the safe
// attribute is clear.
    UINT64 clock;                        // The orderly version of clock
    TPMI_YES_NO clockSafe;                    // Indicates if the clock value is
    // safe.
    // In many implementations, the quality of the entropy available is not that
    // high. To compensate, the current value of the drbgState can be saved and
    // restored on each power cycle. This prevents the internal state from reverting
    // to the initial state on each power cycle and starting with a limited amount
    // of entropy. By keeping the old state and adding entropy, the entropy will
    // accumulate.
    DRBG_STATE drbgState;
} ORDERLY_DATA;
# define drbgDefault go.drbgState
extern ORDERLY_DATA go;
typedef struct state_clear_data
{
//*****************************************************************************
// Hierarchy Control
//*****************************************************************************
    BOOL shEnable;                     // default reset is SET
    BOOL ehEnable;                     // default reset is SET
    BOOL phEnableNV;                   // default reset is SET
    TPMI_ALG_HASH platformAlg;                  // default reset is TPM_ALG_NULL
    TPM2B_DIGEST platformPolicy;               // default reset is an Empty Buffer
    TPM2B_AUTH platformAuth;                 // default reset is an Empty Buffer
//*****************************************************************************
// PCR
//*****************************************************************************
// The set of PCR to be saved on Shutdown(STATE)
    PCR_SAVE pcrSave;                          // default reset is 0...0
// This structure hold the authorization values for those PCR that have an
// update authorization.
// This implementation only supports a single group of PCR controlled by
// authorization. If more are required, then this structure would be changed to
// an array.
    PCR_AUTHVALUE pcrAuthValues;
} STATE_CLEAR_DATA;
extern STATE_CLEAR_DATA gc;
typedef struct state_reset_data
{
//*****************************************************************************
// Hierarchy Control
//*****************************************************************************
    TPM2B_AUTH nullProof;                        // The proof value associated with
    // the TPM_RH_NULL hierarchy. The
    // default reset value is from the RNG.
    TPM2B_SEED nullSeed;                         // The seed value for the TPM_RN_NULL
    // hierarchy. The default reset value
    // is from the RNG.
//*****************************************************************************
// Context
//*****************************************************************************
// The 'clearCount' counter is incremented each time the TPM successfully executes
// a TPM Resume. The counter is included in each saved context that has 'stClear'
// SET (including descendants of keys that have 'stClear' SET). This prevents these
// objects from being loaded after a TPM Resume.
// If 'clearCount' is at its maximum value when the TPM receives a Shutdown(STATE),
// the TPM will return TPM_RC_RANGE and the TPM will only accept Shutdown(CLEAR).
    UINT32 clearCount;                       // The default reset value is 0.
    UINT64 objectContextID;                  // This is the context ID for a saved
    // object context. The default reset
    // value is 0.
#ifndef NDEBUG
#undef CONTEXT_SLOT
#define CONTEXT_SLOT BYTE
#endif
    CONTEXT_SLOT contextArray[MAX_ACTIVE_SESSIONS];                             // This array contains
    // contains the values used to track
    // the version numbers of saved
    // contexts (see
    // Session.c in for details). The
    // default reset value is {0}.
    CONTEXT_COUNTER contextCounter;                   // This is the value from which the
    // 'contextID' is derived. The
    // default reset value is {0}.
//*****************************************************************************
// Command Audit
//*****************************************************************************
// When an audited command completes, ExecuteCommand() checks the return
// value. If it is TPM_RC_SUCCESS, and the command is an audited command, the
// TPM will extend the cpHash and rpHash for the command to this value. If this
// digest was the Zero Digest before the cpHash was extended, the audit counter
// is incremented.
    TPM2B_DIGEST commandAuditDigest;               // This value is set to an Empty Digest
    // by TPM2_GetCommandAuditDigest() or a
    // TPM Reset.
//*****************************************************************************
// Boot counter
//*****************************************************************************
    UINT32 restartCount;                     // This counter counts TPM Restarts.
    // The default reset value is 0.
//*********************************************************************************
// PCR
//*********************************************************************************
// This counter increments whenever the PCR are updated. This counter is preserved
// across TPM Resume even though the PCR are not preserved. This is because
// sessions remain active across TPM Restart and the count value in the session
// is compared to this counter so this counter must have values that are unique
// as long as the sessions are active.
// NOTE: A platform-specific specification may designate that certain PCR changes
// do not increment this counter to increment.
    UINT32 pcrCounter;                       // The default reset value is 0.
#ifdef TPM_ALG_ECC
//*****************************************************************************
// ECDAA
//*****************************************************************************
    UINT64 commitCounter;                    // This counter increments each time
    // TPM2_Commit() returns
    // TPM_RC_SUCCESS. The default reset
    // value is 0.
    TPM2B_NONCE commitNonce;                      // This random value is used to compute
    // the commit values. The default reset
    // value is from the RNG.
// This implementation relies on the number of bits in g_commitArray being a
// power of 2 (8, 16, 32, 64, etc.) and no greater than 64K.
    BYTE commitArray[16];             // The default reset value is {0}.
#endif    //TPM_ALG_ECC
} STATE_RESET_DATA;
extern STATE_RESET_DATA gr;
#define NV_PERSISTENT_DATA (0)
#define NV_STATE_RESET_DATA (NV_PERSISTENT_DATA + sizeof(PERSISTENT_DATA))
#define NV_STATE_CLEAR_DATA (NV_STATE_RESET_DATA + sizeof(STATE_RESET_DATA))
#define NV_ORDERLY_DATA (NV_STATE_CLEAR_DATA + sizeof(STATE_CLEAR_DATA))
#define NV_INDEX_RAM_DATA (NV_ORDERLY_DATA + sizeof(ORDERLY_DATA))
#define NV_USER_DYNAMIC (NV_INDEX_RAM_DATA + sizeof(s_indexOrderlyRam))
#define NV_USER_DYNAMIC_END NV_MEMORY_SIZE
#define NV_READ_PERSISTENT(to, from) \
 NvRead(&to, offsetof(PERSISTENT_DATA, from), sizeof(to))
#define NV_WRITE_PERSISTENT(to, from) \
 NvWrite(offsetof(PERSISTENT_DATA, to), sizeof(gp.to), &from)
#define CLEAR_PERSISTENT(item) \
 NvClearPersistent(offsetof(PERSISTENT_DATA, item), sizeof(gp.item))
#define NV_SYNC_PERSISTENT(item) NV_WRITE_PERSISTENT(item, gp.item)
typedef UINT16 COMMAND_INDEX;
#define UNIMPLEMENTED_COMMAND_INDEX ((COMMAND_INDEX)(~0))
typedef struct _COMMAND_FLAGS_
{
    unsigned trialPolicy : 1;     //1) If SET, one of the handles references a
    // trial policy and authorization may be
    // skipped. This is only allowed for a policy
    // command.
} COMMAND_FLAGS;
typedef struct _COMMAND_
{
    TPM_ST tag;                     // the parsed command tag
    TPM_CC code;                    // the parsed command code
    COMMAND_INDEX index;                   // the computed command index
    UINT32 handleNum;               // the number of entity handles in the
    // handle area of the command
    TPM_HANDLE handles[MAX_HANDLE_NUM];             // the parsed handle values
    UINT32 sessionNum;              // the number of sessions found
    INT32 parameterSize;           // starts out with the parsed command size
    // and is reduced and values are
    // unmarshaled. Just before calling the
    // command actions, this should be zero.
    // After the command actions, this number
    // should grow as values are marshaled
    // in to the response buffer.
    INT32 authSize;                // this is initialized with the parsed size
    // of authorizationSize field and should
    // be zero when the authorizations are
    // parsed.
    BYTE *parameterBuffer;            // input to ExecuteCommand
    BYTE *responseBuffer;             // input to ExecuteCommand
#if ALG_SHA1
    TPM2B_SHA1_DIGEST sha1CpHash;
    TPM2B_SHA1_DIGEST sha1RpHash;
#endif
#if ALG_SHA256
    TPM2B_SHA256_DIGEST sha256CpHash;
    TPM2B_SHA256_DIGEST sha256RpHash;
#endif
#if ALG_SHA384
    TPM2B_SHA384_DIGEST sha384CpHash;
    TPM2B_SHA384_DIGEST sha384RpHash;
#endif
#if ALG_SHA512
    TPM2B_SHA512_DIGEST sha512CpHash;
    TPM2B_SHA512_DIGEST sha512RpHash;
#endif
#if ALG_SM3_256
    TPM2B_SM3_256_DIGEST sm3_256CpHash;
    TPM2B_SM3_256_DIGEST sm3_256RpHash;
#endif
} COMMAND;
extern const TPM2B *PRIMARY_OBJECT_CREATION;
extern const TPM2B *SECRET_KEY;
extern const TPM2B *SESSION_KEY;
extern const TPM2B *STORAGE_KEY;
extern const TPM2B *INTEGRITY_KEY;
extern const TPM2B *CONTEXT_KEY;
extern const TPM2B *CFB_KEY;
extern const TPM2B *XOR_KEY;
extern const TPM2B *DUPLICATE_STRING;
extern const TPM2B *OBFUSCATE_STRING;
extern const TPM2B *IDENTITY_STRING;
extern const TPM2B *COMMIT_STRING;
#ifdef SELF_TEST
extern const TPM2B *OAEP_TEST_STRING;
#endif   // SELF_TEST
extern BOOL g_manufactured;
extern BOOL g_initialized;
#if defined SESSION_PROCESS_C || defined GLOBAL_C || defined MANUFACTURE_C
extern TPM_HANDLE s_sessionHandles[MAX_SESSION_NUM];
extern TPMA_SESSION s_attributes[MAX_SESSION_NUM];
extern TPM_HANDLE s_associatedHandles[MAX_SESSION_NUM];
extern TPM2B_NONCE s_nonceCaller[MAX_SESSION_NUM];
extern TPM2B_AUTH s_inputAuthValues[MAX_SESSION_NUM];
extern SESSION *s_usedSessions[MAX_SESSION_NUM];
#define UNDEFINED_INDEX (0xFFFF)
extern UINT32 s_encryptSessionIndex;
extern UINT32 s_decryptSessionIndex;
extern UINT32 s_auditSessionIndex;
#ifdef TPM_CC_GetCommandAuditDigest
extern TPM2B_DIGEST s_cpHashForCommandAudit;
#endif
extern BOOL s_DAPendingOnNV;
#endif   // SESSION_PROCESS_C
#if defined DA_C || defined GLOBAL_C || defined MANUFACTURE_C
extern UINT64 s_selfHealTimer;
extern UINT64 s_lockoutTimer;
#endif   // DA_C
#if defined NV_C || defined GLOBAL_C
extern NV_REF s_evictNvEnd;
extern BYTE s_indexOrderlyRam[RAM_INDEX_SPACE];          // The orderly NV Index data
extern UINT64 s_maxCounter;
extern NV_INDEX s_cachedNvIndex;
extern NV_REF s_cachedNvRef;
extern BYTE *s_cachedNvRamRef;
#define NV_REF_INIT (NV_REF)0xFFFFFFFF
#endif
#if defined OBJECT_C || defined GLOBAL_C
extern OBJECT s_objects[MAX_LOADED_OBJECTS];
#endif     // OBJECT_C
#if defined PCR_C || defined GLOBAL_C
typedef struct
{
#ifdef TPM_ALG_SHA1
    // SHA1 PCR
    BYTE sha1Pcr[SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    // SHA256 PCR
    BYTE sha256Pcr[SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    // SHA384 PCR
    BYTE sha384Pcr[SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    // SHA512 PCR
    BYTE sha512Pcr[SHA512_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SM3_256
    // SHA256 PCR
    BYTE sm3_256Pcr[SM3_256_DIGEST_SIZE];
#endif
} PCR;
typedef struct
{
    unsigned int stateSave : 1;                        // if the PCR value should be
    // saved in state save
    unsigned int resetLocality : 5;                 // The locality that the PCR
    // can be reset
    unsigned int extendLocality : 5;               // The locality that the PCR
    // can be extend
} PCR_Attributes;
extern PCR s_pcrs[IMPLEMENTATION_PCR];
#endif    // PCR_C
#if defined SESSION_C || defined GLOBAL_C
typedef struct
{
    BOOL occupied;
    SESSION session;                  // session structure
} SESSION_SLOT;
extern SESSION_SLOT s_sessions[MAX_LOADED_SESSIONS];
extern UINT32 s_oldestSavedSession;
extern int s_freeSessionSlots;
#endif    // SESSION_C
#if defined IO_BUFFER_C || defined GLOBAL_C
extern UINT32 s_actionInputBuffer[1024];                                // action input buffer
extern UINT32 s_actionOutputBuffer[1024];                               // action output buffer
#endif    // MEMORY_LIB_C
extern BOOL g_inFailureMode;                    // Indicates that the TPM is in failure mode
#ifdef SIMULATION
extern BOOL g_forceFailureMode;                 // flag to force failure mode during test
#endif
typedef void(FailFunction)(const char *function, int line, int code);
#if defined TPM_FAIL_C || defined GLOBAL_C || 1
extern UINT32 s_failFunction;
extern UINT32 s_failLine;                         // the line in the file at which
// the error was signaled
extern UINT32 s_failCode;                         // the error code used
extern FailFunction *LibFailCallback;
#endif    // TPM_FAIL_C
extern const TPMA_CC s_ccAttr[];
extern const COMMAND_ATTRIBUTES s_commandAttributes[];
#endif  // GLOBAL_H
