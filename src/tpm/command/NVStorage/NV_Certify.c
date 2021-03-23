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
#include "NV_Certify_fp.h"
#ifdef TPM_CC_NV_Certify              // Conditional expansion of this file

// M e
// TPM_RC_NV_AUTHORIZATION the authorization was valid but the authorizing entity (authHandle) is
// not allowed to read from the Index referenced by nvIndex
// TPM_RC_KEY signHandle does not reference a signing key
// TPM_RC_NV_LOCKED Index referenced by nvIndex is locked for reading
// TPM_RC_NV_RANGE offset plus size extends outside of the data range of the Index
// referenced by nvIndex
// TPM_RC_NV_UNINITIALIZED Index referenced by nvIndex has not been written
// TPM_RC_SCHEME inScheme is not an allowed value for the key definition

TPM_RC
TPM2_NV_Certify(
    NV_Certify_In *in,                   // IN: input parameter list
    NV_Certify_Out *out                   // OUT: output parameter list
)
{
    TPM_RC result;
    NV_REF locator;
    NV_INDEX *nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPMS_ATTEST certifyInfo;
    OBJECT *signObject = HandleToObject(in->signHandle);
// Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_NV_Certify_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_NV_Certify_inScheme;
    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvReadAccessChecks(in->authHandle, in->nvIndex,
                                nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;
    // make sure that the selection is within the range of the Index (cast to avoid
    // any wrap issues with addition)
    if((UINT32)in->size + (UINT32)in->offset > (UINT32)nvIndex->publicArea.dataSize)
        return TPM_RC_NV_RANGE;
    // Make sure the data will fit the return buffer
    if(in->size > MAX_NV_BUFFER_SIZE)
        return TPM_RCS_VALUE + RC_NV_Certify_size;
// Command Output
    // Fill in attest information common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
                     &certifyInfo);
    // NV certify specific fields
    // Attestation type
    certifyInfo.type = TPM_ST_ATTEST_NV;
    // Get the name of the index
    NvGetIndexName(nvIndex, &certifyInfo.attested.nv.indexName);
    // Set the return size
    certifyInfo.attested.nv.nvContents.t.size = in->size;
    // Set the offset
    certifyInfo.attested.nv.offset = in->offset;
    // Perform the read
    NvGetIndexData(nvIndex, locator, in->offset, in->size,
                   certifyInfo.attested.nv.nvContents.t.buffer);
    // Sign attestation structure. A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject, &in->inScheme, &certifyInfo,
                          &in->qualifyingData, &out->certifyInfo, &out->signature);
}
#endif // CC_NV_Certify
