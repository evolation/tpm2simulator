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

#ifndef SUPPORT_LIBRARY_FUNCTION_PROTOTYPES_H
#define SUPPORT_LIBRARY_FUNCTION_PROTOTYPES_H
LIB_EXPORT int SupportLibInit(void);
void
MathLibraryCompatibilityCheck(
    void
);
LIB_EXPORT BOOL
BnModMult(bigNum result, bigConst op1, bigConst op2, bigConst modulus);
LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier);
LIB_EXPORT BOOL BnDiv(bigNum quotient, bigNum remainder,
                      bigConst dividend, bigConst divisor);
#define BnMod(a, b) BnDiv(NULL, (a), (a), (b))
#ifdef TPM_ALG_RSA
LIB_EXPORT BOOL BnGcd(bigNum gcd, bigConst number1, bigConst number2);
LIB_EXPORT BOOL BnModExp(bigNum result, bigConst number,
                         bigConst exponent, bigConst modulus);
LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number,
                             bigConst modulus);
#endif   // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
LIB_EXPORT BOOL BnEccModMult(bigPoint R, pointConst S, bigConst d, bigCurve E);
LIB_EXPORT BOOL BnEccModMult2(bigPoint R, pointConst S, bigConst d,
                              pointConst Q, bigConst u, bigCurve E);
LIB_EXPORT BOOL BnEccAdd(bigPoint R, pointConst S, pointConst Q, bigCurve E);
LIB_EXPORT bigCurve BnCurveInitialize(bigCurve E, TPM_ECC_CURVE curveId);
#endif   // TPM_ALG_ECC
#endif
