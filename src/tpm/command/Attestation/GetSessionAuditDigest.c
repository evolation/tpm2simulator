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
#include "GetSessionAuditDigest_fp.h"
#ifdef TPM_CC_GetSessionAuditDigest           // Conditional expansion of this file

// M e
// TPM_RC_KEY key referenced by signHandle is not a signing key
// TPM_RC_SCHEME inScheme is incompatible with signHandle type; or both scheme and
// key's default scheme are empty; or scheme is empty while key's
// default scheme requires explicit input scheme (split signing); or non-
// empty default key scheme differs from scheme
// TPM_RC_TYPE sessionHandle does not reference an audit session
// TPM_RC_VALUE digest generated for the given scheme is greater than the modulus of
// signHandle (for an RSA key); invalid commit status or failed to
// generate r value (for an ECC key)

TPM_RC
TPM2_GetSessionAuditDigest(
    GetSessionAuditDigest_In *in,               // IN: input parameter list
    GetSessionAuditDigest_Out *out               // OUT: output parameter list
)
{
    SESSION *session = SessionGet(in->sessionHandle);
    TPMS_ATTEST auditInfo;
    OBJECT *signObject = HandleToObject(in->signHandle);
// Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_GetSessionAuditDigest_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_GetSessionAuditDigest_inScheme;
    // session must be an audit session
    if(session->attributes.isAudit == CLEAR)
        return TPM_RCS_TYPE + RC_GetSessionAuditDigest_sessionHandle;
// Command Output
    // Fill in attest information common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
                     &auditInfo);
    // SessionAuditDigest specific fields
    auditInfo.type = TPM_ST_ATTEST_SESSION_AUDIT;
    auditInfo.attested.sessionAudit.sessionDigest = session->u2.auditDigest;
    // Exclusive audit session
    auditInfo.attested.sessionAudit.exclusiveSession
        = (g_exclusiveAuditSession == in->sessionHandle);
    // Sign attestation structure. A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject, &in->inScheme, &auditInfo,
                          &in->qualifyingData, &out->auditInfo,
                          &out->signature);
}
#endif // CC_GetSessionAuditDigest
