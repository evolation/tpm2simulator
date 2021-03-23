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
#include "PolicyTicket_fp.h"
#ifdef TPM_CC_PolicyTicket               // Conditional expansion of this file
#include "Policy_spt_fp.h"

// M e
// TPM_RC_CPHASH policy's cpHash was previously set to a different value
// TPM_RC_EXPIRED timeout value in the ticket is in the past and the ticket has expired
// TPM_RC_SIZE timeout or cpHash has invalid size for the
// TPM_RC_TICKET ticket is not valid

TPM_RC
TPM2_PolicyTicket(
    PolicyTicket_In *in                        // IN: input parameter list
)
{
    TPM_RC result;
    SESSION *session;
    UINT64 authTimeout;
    TPMT_TK_AUTH ticketToCompare;
    TPM_CC commandCode = TPM_CC_PolicySecret;
    BOOL expiresOnReset;
// Input Validation
    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    // NOTE: A trial policy session is not allowed to use this command.
    // A ticket is used in place of a previously given authorization. Since
    // a trial policy doesn't actually authenticate, the validated
    // ticket is not necessary and, in place of using a ticket, one
    // should use the intended authorization for which the ticket
    // would be a substitute.
    if(session->attributes.isTrialPolicy)
        return TPM_RCS_ATTRIBUTES + RC_PolicyTicket_policySession;
    // Restore timeout data. The format of timeout buffer is TPM-specific.
    // In this implementation, we simply copy the value of timeout to the
    // buffer.
    if(in->timeout.t.size != sizeof(UINT64) + 1)
        return TPM_RCS_SIZE + RC_PolicyTicket_timeout;
    authTimeout = BYTE_ARRAY_TO_UINT64(in->timeout.t.buffer);
    expiresOnReset = in->timeout.t.buffer[sizeof(authTimeout)];
    // Do the normal checks on the cpHashA and timeout values
    result = PolicyParameterChecks(session, authTimeout,
                                   &in->cpHashA,
                                   NULL,                                 // no nonce
                                   0,                                    // no bad nonce return
                                   RC_PolicyTicket_cpHashA,
                                   RC_PolicyTicket_timeout);
    if(result != TPM_RC_SUCCESS)
        return result;
    // Validate Ticket
    // Re-generate policy ticket by input parameters
    TicketComputeAuth(in->ticket.tag, in->ticket.hierarchy,
                      authTimeout, expiresOnReset, &in->cpHashA, &in->policyRef,
                      &in->authName, &ticketToCompare);
    // Compare generated digest with input ticket digest
    if(!MemoryEqual2B(&in->ticket.digest.b, &ticketToCompare.digest.b))
        return TPM_RCS_TICKET + RC_PolicyTicket_ticket;
// Internal Data Update
    // Is this ticket to take the place of a TPM2_PolicySigned() or
    // a TPM2_PolicySecret()?
    if(in->ticket.tag == TPM_ST_AUTH_SIGNED)
        commandCode = TPM_CC_PolicySigned;
    else if(in->ticket.tag == TPM_ST_AUTH_SECRET)
        commandCode = TPM_CC_PolicySecret;
    else
        // There could only be two possible tag values. Any other value should
        // be caught by the ticket validation process.
        FAIL(FATAL_ERROR_INTERNAL);
    // Update policy context
    PolicyContextUpdate(commandCode, &in->authName, &in->policyRef,
                        &in->cpHashA, authTimeout, session);
    return TPM_RC_SUCCESS;
}
#endif // CC_PolicyTicket
