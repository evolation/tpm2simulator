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
#include "EncryptDecrypt2_fp.h"
#include "EncryptDecrypt_fp.h"
#include "EncryptDecrypt_spt_fp.h"
#ifdef TPM_CC_EncryptDecrypt2       // Conditional expansion of this file

// M e
// TPM_RC_KEY is not a symmetric decryption key with both public and private
// portions loaded
// TPM_RC_SIZE IvIn size is incompatible with the block cipher mode; or inData size is
// not an even multiple of the block size for CBC or ECB mode
// TPM_RC_VALUE keyHandle is restricted and the argument mode does not match the
// key's mode

TPM_RC
TPM2_EncryptDecrypt2(
    EncryptDecrypt2_In *in,                // IN: input parameter list
    EncryptDecrypt2_Out *out                // OUT: output parameter list
)
{
    TPM_RC result;
    // EncryptDecyrptShared() performs the operations as shown in
    // TPM2_EncrypDecrypt
    result = EncryptDecryptShared(in->keyHandle, in->decrypt, in->mode,
                                  &in->ivIn, &in->inData,
                                  (EncryptDecrypt_Out *)out);
    // Handle response code swizzle.
    switch(result)
    {
    case TPM_RCS_MODE + RC_EncryptDecrypt_mode:
        result = TPM_RCS_MODE + RC_EncryptDecrypt2_mode;
        break;
    case TPM_RCS_SIZE + RC_EncryptDecrypt_ivIn:
        result = TPM_RCS_SIZE + RC_EncryptDecrypt2_ivIn;
        break;
    case TPM_RCS_SIZE + RC_EncryptDecrypt_inData:
        result = TPM_RCS_SIZE + RC_EncryptDecrypt2_inData;
        break;
    default:
        break;
    }
    return result;
}
#endif // CC_EncryptDecrypt2
