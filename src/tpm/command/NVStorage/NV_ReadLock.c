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
#include "NV_ReadLock_fp.h"
#ifdef TPM_CC_NV_ReadLock             // Conditional expansion of this file

// M e
// TPM_RC_ATTRIBUTES TPMA_NV_READ_STCLEAR is not SET so Index referenced by
// nvIndex may not be write locked
// TPM_RC_NV_AUTHORIZATION the authorization was valid but the authorizing entity (authHandle) is
// not allowed to read from the Index referenced by nvIndex

TPM_RC
TPM2_NV_ReadLock(
    NV_ReadLock_In *in                      // IN: input parameter list
)
{
    TPM_RC result;
    NV_REF locator;
    // The referenced index has been checked multiple times before this is called
    // so it must be present and will be loaded into cache
    NV_INDEX *nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPMA_NV nvAttributes = nvIndex->publicArea.attributes;
// Input Validation
    // Common read access checks. NvReadAccessChecks() may return
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    result = NvReadAccessChecks(in->authHandle,
                                in->nvIndex,
                                nvAttributes);
    if(result == TPM_RC_NV_AUTHORIZATION)
        return TPM_RC_NV_AUTHORIZATION;
    // Index is already locked for write
    else if(result == TPM_RC_NV_LOCKED)
        return TPM_RC_SUCCESS;
    // If NvReadAccessChecks return TPM_RC_NV_UNINITALIZED, then continue.
    // It is not an error to read lock an uninitialized Index.
    // if TPMA_NV_READ_STCLEAR is not set, the index can not be read-locked
    if(nvAttributes.TPMA_NV_READ_STCLEAR == CLEAR)
        return TPM_RCS_ATTRIBUTES + RC_NV_ReadLock_nvIndex;
// Internal Data Update
    // Set the READLOCK attribute
    nvAttributes.TPMA_NV_READLOCKED = SET;
    // Write NV info back
    return NvWriteIndexAttributes(nvIndex->publicArea.nvIndex,
                                  locator,
                                  nvAttributes);
}
#endif // CC_NV_ReadLock
