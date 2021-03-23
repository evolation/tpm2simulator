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

#ifndef _CRYPT_RSA_H
#define _CRYPT_RSA_H

// This structure is a succinct representation of the cryptographic components of an RSA key. It is used
// in

// testing
typedef struct
{
    UINT32 exponent;          // The public exponent pointer
    TPM2B *publicKey;             // Pointer to the public modulus
    TPM2B *privateKey;            // The private prime
} RSA_KEY;

// These values are used in the bigNum representation of various RSA values.
#define RSA_BITS (MAX_RSA_KEY_BYTES * 8)
BN_TYPE(rsa, RSA_BITS);
#define BN_RSA(name) BN_VAR(name, RSA_BITS)
#define BN_RSA_INITIALIZED(name, initializer) \
 BN_INITIALIZED(name, RSA_BITS, initializer)
#define BN_PRIME(name) BN_VAR(name, (RSA_BITS          / 2))
BN_TYPE(prime, (RSA_BITS    / 2));
#define BN_PRIME_INITIALIZED(name, initializer) \
 BN_INITIALIZED(name, RSA_BITS   / 2, initializer)
typedef struct privateExponent
{
#if CRT_FORMAT_RSA == NO
    bn_rsa_t D;
#else
    bn_prime_t Q;
    bn_prime_t dP;
    bn_prime_t dQ;
    bn_prime_t qInv;
#endif    // CRT_FORMAT_RSA
} privateExponent_t;
#endif          // _CRYPT_RSA_H
