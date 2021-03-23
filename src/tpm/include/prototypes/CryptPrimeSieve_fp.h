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

#ifndef _CRYPTPRIMESIEVE_FP_H_
#define _CRYPTPRIMESIEVE_FP_H_

#if defined RSA_KEY_SIEVE               //%
LIB_EXPORT uint32_t
RsaNextPrime(
    uint32_t lastPrime
);

#ifndef USE_NIBBLE
#else
#endif
LIB_EXPORT int
FindNthSetBit(
    const UINT16 aSize,              // IN: the size of the array to check
    const BYTE *a,                    // IN: the array to check
    const UINT32 n                   // IN, the number of the SET bit
);

LIB_EXPORT UINT32
PrimeSieve(
    bigNum bnN,                     // IN/OUT: number to sieve
    UINT32 fieldSize,               // IN: size of the field area in bytes
    BYTE *field                      // IN: field
);

#ifdef SIEVE_DEBUG
LIB_EXPORT uint32_t
SetFieldSize(
    uint32_t newFieldSize
);

#endif     // SIEVE_DEBUG
LIB_EXPORT TPM_RC
PrimeSelectWithSieve(
    bigNum candidate,               // IN/OUT: The candidate to filter
    UINT32 e,                       // IN: the exponent
    RAND_STATE *rand                    // IN: the random number generator state
);

#ifdef RSA_INSTRUMENT
char *
PrintTuple(
    UINT32 *i
);

void
RsaSimulationEnd(
    void
);

LIB_EXPORT void
GetSieveStats(
    uint32_t *trials,
    uint32_t *emptyFields,
    uint32_t *averageBits
);

#endif
#endif     //% RSA_KEY_SIEVE
#ifndef RSA_INSTRUMENT
void
RsaSimulationEnd(
    void
);

#endif
#endif  // _CRYPTPRIMESIEVE_FP_H_
