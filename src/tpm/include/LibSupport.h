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

#ifndef _LIB_SUPPORT_H_
#define _LIB_SUPPORT_H_
#define OSSL 1
#define LTC 2
#define MSBN 3
#define SYMCRYPT 4
#if RADIX_BITS == 32
# define RADIX_BYTES 4
#elif RADIX_BITS == 64
# define RADIX_BYTES 8
#else
#error "RADIX_BITS must either be 32 or 64."
#endif
#if HASH_LIB == OSSL
# include "ossl/TpmToOsslHash.h"
#elif HASH_LIB == LTC
# include "ltc/TpmToLtcHash.h"
#elif HASH_LIB == SYMCRYPT
#include "symcrypt/TpmToSymcryptHash.h"
#else
# error "No hash library selected"
#endif
#if SYM_LIB == OSSL
# include "ossl/TpmToOsslSym.h"
#elif SYM_LIB == LTC
# include "ltc/TpmToLtcSym.h"
#elif SYM_LIB == SYMCRYPT
#include "symcrypt/TpmToSymcryptSym.h"
#else
# error "No symmetric library selected"
#endif
#undef MIN
#undef MIN
#if MATH_LIB == OSSL
# define MATHLIB_H "ossl/TpmToOsslMath.h"
#elif MATH_LIB == LTC
# define MATHLIB_H "ltc/TpmToLtcMath.h"
#elif MATH_LIB == MSBN
#define MATHLIB_H "msbn/TpmToMsBnMath.h"
#else
# error "No math library selected"
#endif
#endif   // _LIB_SUPPORT_H_
