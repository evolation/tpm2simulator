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
#include "Quote_fp.h"
#ifdef TPM_CC_Quote       // Conditional expansion of this file

// M e
// TPM_RC_KEY signHandle does not reference a signing key;
// TPM_RC_SCHEME the scheme is not compatible with sign key type, or input scheme is
// not compatible with default scheme, or the chosen scheme is not a
// valid sign scheme

TPM_RC
TPM2_Quote(
    Quote_In *in,                      // IN: input parameter list
    Quote_Out *out                      // OUT: output parameter list
)
{
    TPMI_ALG_HASH hashAlg;
    TPMS_ATTEST quoted;
    OBJECT *signObject = HandleToObject(in->signHandle);
// Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_Quote_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_Quote_inScheme;
// Command Output
    // Filling in attest information
    // Common fields
    // FillInAttestInfo may return TPM_RC_SCHEME or TPM_RC_KEY
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &quoted);
    // Quote specific fields
    // Attestation type
    quoted.type = TPM_ST_ATTEST_QUOTE;
    // Get hash algorithm in sign scheme. This hash algorithm is used to
    // compute PCR digest. If there is no algorithm, then the PCR cannot
    // be digested and this command returns TPM_RC_SCHEME
    hashAlg = in->inScheme.details.any.hashAlg;
    if(hashAlg == TPM_ALG_NULL)
        return TPM_RCS_SCHEME + RC_Quote_inScheme;
    // Compute PCR digest
    PCRComputeCurrentDigest(hashAlg, &in->PCRselect,
                            &quoted.attested.quote.pcrDigest);
    // Copy PCR select. "PCRselect" is modified in PCRComputeCurrentDigest
    // function
    quoted.attested.quote.pcrSelect = in->PCRselect;
    // Sign attestation structure. A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject, &in->inScheme, &quoted, &in->qualifyingData,
                          &out->quoted, &out->signature);
}
#endif // CC_Quote
