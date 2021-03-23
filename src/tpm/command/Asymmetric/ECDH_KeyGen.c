/******************************************************************************************************************/
/*                                                                                                                */
/*                                                                                                                */
/*  Licenses and Notices                                                                                          */
/*     Copyright Licenses:                                                                                        */
/*     Trusted     Computing    Group   (TCG)     grants    to   the  user  of   the  source  code        in     this  specification   (the                                                                                            */
/*     "Source Code") a worldwide, irrevocable, nonexclusive, royalty free, copyright license to reproduce,       */
/*     create   derivative      works,  distribute,     display  and  perform     the     Source     Code        and   derivative  works                                                                                               */
/*     thereof, and to grant others the rights granted herein.                                                    */
/*     The TCG grants to the user of the other parts of the specification (other than the Source Code) the        */
/*     rights  to  reproduce,   distribute,       display,  and  perform     the  specification      solely      for   the  purpose     of                                                                                             */
/*     developing products based on such documents.                                                               */
/*     Source Code Distribution Conditions:                                                                       */
/*     Redistributions of Source Code must retain the above copyright licenses, this list of conditions and       */
/*     the following disclaimers.                                                                                 */
/*     Redistributions in binary form must reproduce the above copyright licenses, this list of conditions and    */
/*     the following disclaimers in the documentation and/or other materials provided with the distribution.      */
/*     Disclaimers:                                                                                               */
/*     THE     COPYRIGHT        LICENSES          SET   FORTH         ABOVE      DO   NOT  REPRESENT                   ANY  FORM       OF                                                                                              */
/*     LICENSE     OR  WAIVER,          EXPRESS         OR       IMPLIED,    BY      ESTOPPEL        OR          OTHERWISE,        WITH                                                                                                */
/*     RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES) THAT                                 */
/*     MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE. Contact TCG                                 */
/*     Administration (admin@trustedcomputinggroup.org) for information on specification licensing rights         */
/*     available through TCG membership agreements.                                                               */
/*     THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                               */
/*     WHATSOEVER,              INCLUDING    ANY        WARRANTY      OF     MERCHANTABILITY                  OR       FITNESS     FOR  A                                                                                              */
/*     PARTICULAR         PURPOSE,           ACCURACY,           COMPLETENESS,             OR        NONINFRINGEMENT                   OF                                                                                              */
/*     INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF ANY                                 */
/*     PROPOSAL, SPECIFICATION OR SAMPLE.                                                                         */
/*     Without     limitation,  TCG     and  its  members        and  licensors  disclaim  all       liability,  including  liability   for                                                                                            */
/*     infringement of any proprietary rights, relating to use of information in this specification and to the    */
/*     implementation     of    this    specification,  and      TCG  disclaims      all  liability  for  cost    of   procurement      of                                                                                             */
/*     substitute goods or services, lost profits, loss of use, loss of data or any incidental, consequential,    */
/*     direct, indirect, or special damages, whether under contract, tort, warranty or otherwise, arising in any  */
/*     way out of use or reliance upon this specification or any information herein.                              */
/*     Any marks and brands contained herein are the property of their respective owners.                         */
/*                                                                                                                */
/******************************************************************************************************************/

#include "Tpm.h"
#include "ECDH_KeyGen_fp.h"
#ifdef TPM_CC_ECDH_KeyGen           // Conditional expansion of this file
#ifdef TPM_ALG_ECC

// M e
// TPM_RC_KEY keyHandle does not reference an ECC key

TPM_RC
TPM2_ECDH_KeyGen(
    ECDH_KeyGen_In *in,                        // IN: input parameter list
    ECDH_KeyGen_Out *out                        // OUT: output parameter list
)
{
    OBJECT *eccKey;
    TPM2B_ECC_PARAMETER sensitive;
    TPM_RC result;
// Input Validation
    eccKey = HandleToObject(in->keyHandle);
    // Referenced key must be an ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
        return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;
// Command Output
    do
    {
        TPMT_PUBLIC *keyPublic = &eccKey->publicArea;
        // Create ephemeral ECC key
        result = CryptEccNewKeyPair(&out->pubPoint.point, &sensitive,
                                    keyPublic->parameters.eccDetail.curveID);
        if(result == TPM_RC_SUCCESS)
        {
            // Compute Z
            result = CryptEccPointMultiply(&out->zPoint.point,
                                           keyPublic->parameters.eccDetail.curveID,
                                           &keyPublic->unique.ecc,
                                           &sensitive,
                                           NULL, NULL);
            // The point in the key is not on the curve. Indicate
            // that the key is bad.
            if(result == TPM_RC_ECC_POINT)
                return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;
            // The other possible error from CryptEccPointMultiply is
            // TPM_RC_NO_RESULT indicating that the multiplication resulted in
            // the point at infinity, so get a new random key and start over
            // BTW, this never happens.
        }
    } while(result == TPM_RC_NO_RESULT);
    return result;
}
#endif // ALG_ECC
#endif // CC_ECDH_KeyGen
