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
#include "CertifyCreation_fp.h"
#ifdef TPM_CC_CertifyCreation       // Conditional expansion of this file

// M e
// TPM_RC_KEY key referenced by signHandle is not a signing key
// TPM_RC_SCHEME inScheme is not compatible with signHandle
// TPM_RC_TICKET creationTicket does not match objectHandle
// TPM_RC_VALUE digest generated for inScheme is greater or has larger size than the
// modulus of signHandle, or the buffer for the result in signature is too
// small (for an RSA key); invalid commit status (for an ECC key with a
// split scheme).

TPM_RC
TPM2_CertifyCreation(
    CertifyCreation_In *in,                 // IN: input parameter list
    CertifyCreation_Out *out                 // OUT: output parameter list
)
{
    TPMT_TK_CREATION ticket;
    TPMS_ATTEST certifyInfo;
    OBJECT *certified = HandleToObject(in->objectHandle);
    OBJECT *signObject = HandleToObject(in->signHandle);
// Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_CertifyCreation_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_CertifyCreation_inScheme;
    // CertifyCreation specific input validation
    // Re-compute ticket
    TicketComputeCreation(in->creationTicket.hierarchy, &certified->name,
                          &in->creationHash, &ticket);
    // Compare ticket
    if(!MemoryEqual2B(&ticket.digest.b, &in->creationTicket.digest.b))
        return TPM_RCS_TICKET + RC_CertifyCreation_creationTicket;
// Command Output
    // Common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
                     &certifyInfo);
    // CertifyCreation specific fields
    // Attestation type
    certifyInfo.type = TPM_ST_ATTEST_CREATION;
    certifyInfo.attested.creation.objectName = certified->name;
    // Copy the creationHash
    certifyInfo.attested.creation.creationHash = in->creationHash;
    // Sign attestation structure. A NULL signature will be returned if
    // signObject is TPM_RH_NULL. A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    return SignAttestInfo(signObject, &in->inScheme, &certifyInfo,
                          &in->qualifyingData, &out->certifyInfo,
                          &out->signature);
}
#endif // CC_CertifyCreation
