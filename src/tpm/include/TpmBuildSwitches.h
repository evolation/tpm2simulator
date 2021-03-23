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

#ifndef _TPM_BUILD_SWITCHES_H_
#define _TPM_BUILD_SWITCHES_H_
#ifndef INLINE_FUNCTIONS
//# define INLINE_FUNCTIONS
#endif
#include "CompilerDependencies.h"
#define USE_BN_ECC_DATA
#ifndef SIMULATION
# define SIMULATION
#endif
#if !defined LIBRARY_COMPATIBILITY_CHECK && defined SIMULATION
# define LIBRARY_COMPATABILITY_CHECK
#endif
#ifndef FIPS_COMPLIANT
//# define FIPS_COMPLIANT
#endif
#ifndef USE_DA_USED
# define USE_DA_USED
#endif
#ifndef TABLE_DRIVEN_DISPATCH
# define TABLE_DRIVEN_DISPATCH
#endif
#ifndef SELF_TEST
#define SELF_TEST
#endif
#ifndef RSA_KEY_SIEVE
# define RSA_KEY_SIEVE
#endif
#if !defined RSA_INSTRUMENT && defined RSA_KEY_SIEVE && defined SIMULATION
//#define RSA_INSTRUMENT
#endif
#if defined RSA_KEY_SIEVE && !defined NDEBUG && !defined RSA_INSTRUMENT
//# define RSA_INSTRUMENT
#endif
#ifndef _DRBG_STATE_SAVE
# define _DRBG_STATE_SAVE               // Comment this out if no state save is wanted
#endif
#ifndef COMPRESSED_LISTS
# define COMPRESSED_LISTS
#endif
#ifndef CLOCK_STOPS
//# define CLOCK_STOPS
#endif
#ifdef SIMULATION
# ifndef USE_RSA_KEY_CACHE
//# define USE_RSA_KEY_CACHE
# endif
# if defined USE_RSA_KEY_CACHE && !defined USE_KEY_CACHE_FILE
# define USE_KEY_CACHE_FILE
# endif
# if !defined NDEBUG && !defined USE_DEBUG_RNG
# define USE_DEBUG_RNG
# endif
#else
# undef USE_RSA_KEY_CACHE
# undef USE_KEY_CACHE_FILE
# undef USE_DEBUG_RNG
# undef RSA_INSTRUMENT
#endif       // SIMULATION
#ifndef NDEBUG
#ifndef COMPILER_CHECKS
//# define COMPILER_CHECKS
#endif
#ifndef RUNTIME_SIZE_CHECKS
#define RUNTIME_SIZE_CHECKS
#endif
#ifndef DRBG_DEBUG_PRINT
//# define DRBG_DEBUG_PRINT
#endif
#endif   // NDEBUG
#endif   // _TPM_BUILD_SWITCHES_H_
