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
#include "Attest_spt_fp.h"
#include "Certify_fp.h"
#ifdef TPM_CC_Certify        // Conditional expansion of this file

// M e
// TPM_RC_KEY key referenced by signHandle is not a signing key
// TPM_RC_SCHEME inScheme is not compatible with signHandle
// TPM_RC_VALUE digest generated for inScheme is greater or has larger size than the
// modulus of signHandle, or the buffer for the result in signature is too
// small (for an RSA key); invalid commit status (for an ECC key with a
// split scheme).

TPM_RC
TPM2_Certify(
    Certify_In *in,                   // IN: input parameter list
    Certify_Out *out                   // OUT: output parameter list
)
{
    TPMS_ATTEST certifyInfo;
    OBJECT *signObject = HandleToObject(in->signHandle);
    OBJECT *certifiedObject = HandleToObject(in->objectHandle);
// Input validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_Certify_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_Certify_inScheme;
// Command Output
    // Filling in attest information
    // Common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
                     &certifyInfo);
    // Certify specific fields
    certifyInfo.type = TPM_ST_ATTEST_CERTIFY;
    // NOTE: the certified object is not allowed to be TPM_ALG_NULL so
    // 'certifiedObject' will never be NULL
    certifyInfo.attested.certify.name = certifiedObject->name;
    certifyInfo.attested.certify.qualifiedName = certifiedObject->qualifiedName;
    // Sign attestation structure. A NULL signature will be returned if
    // signHandle is TPM_RH_NULL. A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned
    // by SignAttestInfo()
    return SignAttestInfo(signObject, &in->inScheme, &certifyInfo,
                          &in->qualifyingData, &out->certifyInfo, &out->signature);
}
#endif // CC_Certify
