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

#ifdef TPM_CC_EncryptDecrypt2 // Command must be defined

#ifndef _ENCRYPTDECRYPT2_H_
#define _ENCRYPTDECRYPT2_H_

// Type definition for input structure
typedef struct {
    TPMI_DH_OBJECT		keyHandle;
    TPM2B_MAX_BUFFER		inData;
    TPMI_YES_NO		decrypt;
    TPMI_ALG_SYM_MODE		mode;
    TPM2B_IV		ivIn;
} EncryptDecrypt2_In;

// Type definition for output structure
typedef struct {
    TPM2B_MAX_BUFFER		outData;
    TPM2B_IV		ivOut;
} EncryptDecrypt2_Out;

// Definition of response code modifiers
#define RC_EncryptDecrypt2_keyHandle		(TPM_RC_H + TPM_RC_1)
#define RC_EncryptDecrypt2_inData		(TPM_RC_P + TPM_RC_1)
#define RC_EncryptDecrypt2_decrypt		(TPM_RC_P + TPM_RC_2)
#define RC_EncryptDecrypt2_mode		(TPM_RC_P + TPM_RC_3)
#define RC_EncryptDecrypt2_ivIn		(TPM_RC_P + TPM_RC_4)



// Declaration of function prototypes
TPM_RC
TPM2_EncryptDecrypt2(
    EncryptDecrypt2_In *in,                // IN: input parameter list
    EncryptDecrypt2_Out *out                // OUT: output parameter list
);


#endif // _ENCRYPTDECRYPT2_H_
#endif  // TPM_CC_EncryptDecrypt2
