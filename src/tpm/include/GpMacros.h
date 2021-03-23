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

#ifndef GP_MACROS_H
#define GP_MACROS_H
#ifndef NULL
#define NULL 0
#endif
#include "swap.h"
#include "VendorString.h"
#ifdef SELF_TEST
# define TEST(alg) if(TEST_BIT(alg, g_toTest)) CryptTestAlgorithm(alg, NULL)
# define TEST_HASH(alg) \
 if(TEST_BIT(alg, g_toTest) \
 && (alg != ALG_NULL_VALUE)) \
 CryptTestAlgorithm(alg, NULL)
#else
# define TEST(alg)
# define TEST_HASH(alg)
#endif   // SELF_TEST
#if defined _POSIX_
# define FUNCTION_NAME 0
#else
# define FUNCTION_NAME __FUNCTION__
#endif
#ifdef NO_FAIL_TRACE
# define FAIL(errorCode) (TpmFail(errorCode))
#else
# define FAIL(errorCode) (TpmFail(FUNCTION_NAME, __LINE__, errorCode))
#endif
#ifndef NO_LONGJMP
# define FAIL_RETURN(returnCode)
# define TPM_FAIL_RETURN NORETURN void
#else
# define FAIL_RETURN(returnCode) return (returnCode)
# define TPM_FAIL_RETURN void
#endif
#define REQUIRE(condition, errorCode, returnCode) \
 { \
 if(!!(condition)) \
 { \
 FAIL(FATAL_ERROR_errorCode); \
 FAIL_RETURN(returnCode); \
 } \
 }
#define PARAMETER_CHECK(condition, returnCode) \
 REQUIRE((condition), PARAMETER, returnCode)
#if defined(EMPTY_ASSERT)
# define pAssert(a) ((void)0)
#else
# define pAssert(a) (!!(a) ? 1 : (FAIL(FATAL_ERROR_PARAMETER), 0))
#endif
#define PCR_SELECT_MIN ((PLATFORM_PCR+7)/8)
#define PCR_SELECT_MAX ((IMPLEMENTATION_PCR+7)/8)
#define MAX_ORDERLY_COUNT ((1 << ORDERLY_BITS) - 1)
#define PRIVATE_VENDOR_SPECIFIC_BYTES \
 ((MAX_RSA_KEY_BYTES/2) * (3 + CRT_FORMAT_RSA * 2))
#ifdef COMPILER_CHECKS
# define cAssert pAssert
#else
# define cAssert(value)
#endif
#define ERROR_RETURN(returnCode) \
 { \
 retVal = returnCode; \
 goto Exit; \
 }
#ifndef MAX
# define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
# define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef IsOdd
# define IsOdd(a) (((a) & 1) != 0)
#endif
#ifndef BITS_TO_BYTES
# define BITS_TO_BYTES(bits) (((bits) + 7) >> 3)
#endif
#define TEST_BIT(bit, vector) TestBit((bit), (BYTE *)&(vector), sizeof(vector))
#define SET_BIT(bit, vector) SetBit((bit), (BYTE *)&(vector), sizeof(vector))
#define CLEAR_BIT(bit, vector) ClearBit((bit), (BYTE *)&(vector), sizeof(vector))
#ifndef LIB_EXPORT
# define LIB_EXPORT
# define LIB_IMPORT
#endif
#ifndef NORETURN
# define NORETURN _Noreturn
#endif
#ifndef NOT_REFERENCED
# define NOT_REFERENCED(x = x) ((void) (x))
#endif
#if !defined NDEBUG && !defined DEBUG
# define DEBUG YES
#endif
#define STD_RESPONSE_HEADER (sizeof(TPM_ST) + sizeof(UINT32) + sizeof(TPM_RC))
#ifndef CONTEXT_HASH_ALGORITHM
# if defined ALG_SHA512 && ALG_SHA512 == YES
# define CONTEXT_HASH_ALGORITHM SHA512
# elif defined ALG_SHA384 && ALG_SHA384 == YES
# define CONTEXT_HASH_ALGORITHM SHA384
# elif defined ALG_SHA256 && ALG_SHA256 == YES
# define CONTEXT_HASH_ALGORITHM SHA256
# elif defined ALG_SM3_256 && ALG_SM3_256 == YES
# define CONTEXT_HASH_ALGORITHM SM3_256
# elif defined ALG_SHA1 && ALG_SHA1 == YES
# define CONTEXT_HASH_ALGORITHM SHA1
# endif
#endif
#define JOIN(x,y) x##y
#define CONCAT(x,y) JOIN(x, y)
#ifndef CONTEXT_INTEGRITY_HASH_ALG
#define CONTEXT_INTEGRITY_HASH_ALG CONCAT(TPM_ALG_, CONTEXT_HASH_ALGORITHM)
#define CONTEXT_INTEGRITY_HASH_SIZE CONCAT(CONTEXT_HASH_ALGORITHM, _DIGEST_SIZE)
#endif
#define PROOF_SIZE CONTEXT_INTEGRITY_HASH_SIZE
#ifndef CONTEXT_ENCRYPT_ALG
#define CONTEXT_ENCRYPT_ALG CONCAT(TPM_ALG_, CONTEXT_ENCRYPT_ALGORITHM)
#define CONTEXT_ENCRYPT_KEY_BITS \
 CONCAT(CONCAT(MAX_, CONTEXT_ENCRYPT_ALGORITHM), _KEY_BITS)
#define CONTEXT_ENCRYPT_KEY_BYTES ((CONTEXT_ENCRYPT_KEY_BITS+7)/8)
#endif
#ifndef MAX_ECC_KEY_BYTES
#define MAX_ECC_KEY_BYTES 0
#endif
#ifndef MAX_ECC_KEY_BYTES
# define MAX_ECC_KEY_BYTES MAX_DIGEST_SIZE
#endif
#define LABEL_MAX_BUFFER MIN(MAX_ECC_KEY_BYTES, MAX_DIGEST_SIZE)
#if LABEL_MAX_BUFFER < 32
#error "The size allowed for the label is not large enough for interoperability."
#endif
#endif   // GP_MACROS_H
