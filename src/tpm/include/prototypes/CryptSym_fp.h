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

#ifndef _CRYPTSYM_FP_H_
#define _CRYPTSYM_FP_H_

union tpmCryptKeySchedule_t {
#ifdef TPM_ALG_AES
    tpmKeyScheduleAES AES;
#endif
#ifdef TPM_ALG_SM4
    tpmKeyScheduleSM4 SM4;
#endif
#ifdef TPM_ALG_CAMELLIA
    tpmKeyScheduleCAMELLIA CAMELLIA;
#endif
#ifdef TPM_ALG_TDES
    tpmKeyScheduleTDES TDES[3];
#endif
#if SYMMETRIC_ALIGNMENT == 8
    uint64_t alignment;
#else
    uint32_t alignment;
#endif
};
#ifdef TPM_ALG_AES
#else
#endif
#ifdef TPM_ALG_SM4
#else
#endif
#ifdef TPM_ALG_CAMELLIA
#else
#endif
#ifdef TPM_ALG_TDES
#else
#endif
BOOL
CryptSymInit(
    void
);

BOOL
CryptSymStartup(
    void
);

LIB_EXPORT INT16
CryptGetSymmetricBlockSize(
    TPM_ALG_ID symmetricAlg,      // IN: the symmetric algorithm
    UINT16 keySizeInBits      // IN: the key size
);

LIB_EXPORT TPM_RC
CryptSymmetricEncrypt(
    BYTE *dOut,            // OUT:
    TPM_ALG_ID algorithm,      // IN: the symmetric algorithm
    UINT16 keySizeInBits,  // IN: key size in bits
    const BYTE *key,             // IN: key buffer. The size of this buffer
    // in bytes is (keySizeInBits + 7)  / 8
    TPM2B_IV *ivInOut,         // IN/OUT: IV for decryption.
    TPM_ALG_ID mode,           // IN: Mode to use
    INT32 dSize,          // IN: data size (may need to be a
    // multiple of the blockSize)
    const BYTE *dIn              // IN: data buffer
);

LIB_EXPORT TPM_RC
CryptSymmetricDecrypt(
    BYTE *dOut,                       // OUT: decrypted data
    TPM_ALG_ID algorithm,                // IN: the symmetric algorithm
    UINT16 keySizeInBits,            // IN: key size in bits
    const BYTE *key,                        // IN: key buffer. The size of this buffer
    // in bytes is (keySizeInBits + 7)  / 8
    TPM2B_IV *ivInOut,                    // IN/OUT: IV for decryption.
    TPM_ALG_ID mode,                     // IN: Mode to use
    INT32 dSize,                    // IN: data size (may need to be a
    // multiple of the blockSize)
    const BYTE *dIn                         // IN: data buffer
);

TPM_RC
CryptSymKeyValidate(
    TPMT_SYM_DEF_OBJECT *symDef,
    TPM2B_SYM_KEY *key
);

#endif  // _CRYPTSYM_FP_H_
