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

#ifndef _CRYPTECCSIGNATURE_FP_H_
#define _CRYPTECCSIGNATURE_FP_H_

#ifdef TPM_ALG_ECC
TPM_RC
BnSignEcdsa(
    bigNum bnR,                     // OUT: r component of the signature
    bigNum bnS,                     // OUT: s component of the signature
    bigCurve E,                       // IN: the curve used in the signature
    // process
    bigNum bnD,                     // IN: private signing key
    const TPM2B_DIGEST *digest,                 // IN: the digest to sign
    RAND_STATE *rand                    // IN: used in debug of signing
);

#if ALG_ECDAA
#endif  // ALG_ECDAA
#if ALG_ECSCHNORR         //%
#endif      // ALG_ECSCHNORR
#if ALG_SM2
#ifdef _SM2_SIGN_DEBUG
#endif  // _SM2_SIGN_DEBUG
#endif  // ALG_SM2
LIB_EXPORT TPM_RC
CryptEccSign(
    TPMT_SIGNATURE *signature,                   // OUT: signature
    OBJECT *signKey,               // IN: ECC key to sign the hash
    const TPM2B_DIGEST *digest,                // IN: digest to sign
    TPMT_ECC_SCHEME *scheme,                // IN: signing scheme
    RAND_STATE *rand
);

#if ALG_ECDSA             //%
TPM_RC
BnValidateSignatureEcdsa(
    bigNum bnR,                               // IN: r component of the signature
    bigNum bnS,                               // IN: s component of the signature
    bigCurve E,                                 // IN: the curve used in the signature
    // process
    bn_point_t *ecQ,                              // IN: the public point of the key
    const TPM2B_DIGEST *digest                            // IN: the digest that was signed
);

#endif            //% ALG_ECDSA
#if ALG_SM2
#endif     //% ALG_SM2
#if ALG_ECSCHNORR
#endif          // ALG_ECSCHNORR
LIB_EXPORT TPM_RC
CryptEccValidateSignature(
    TPMT_SIGNATURE *signature,                 // IN: signature to be verified
    OBJECT *signKey,                   // IN: ECC key signed the hash
    const TPM2B_DIGEST *digest                     // IN: digest that was signed
);

LIB_EXPORT TPM_RC
CryptEccCommitCompute(
    TPMS_ECC_POINT *K,                               // OUT: [d]B or [r]Q
    TPMS_ECC_POINT *L,                               // OUT: [r]B
    TPMS_ECC_POINT *E,                               // OUT: [r]M
    TPM_ECC_CURVE curveId,                       // IN: the curve for the computations
    TPMS_ECC_POINT *M,                               // IN: M (optional)
    TPMS_ECC_POINT *B,                               // IN: B (optional)
    TPM2B_ECC_PARAMETER *d,                               // IN: d (optional)
    TPM2B_ECC_PARAMETER *r                                // IN: the computed r value (required)
);

#endif     // TPM_ALG_ECC
#endif  // _CRYPTECCSIGNATURE_FP_H_
