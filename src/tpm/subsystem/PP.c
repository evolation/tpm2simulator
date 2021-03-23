/******************************************************************************************************************/
/*                                                                                                                */
/*                                                                                                                */
/*  Licenses and Notices                                                                                          */
/*     Copyright Licenses:                                                                                        */
/*     ·  Trusted Computing Group (TCG) grants to the user of the source code in this specification (the         */
/*     "Source Code") a worldwide, irrevocable, nonexclusive, royalty free, copyright license to                  */
/*     reproduce, create derivative works, distribute, display and perform the Source Code and                    */
/*     derivative works thereof, and to grant others the rights granted herein.                                   */
/*     ·  The TCG grants to the user of the other parts of the specification (other than the Source Code)        */
/*     the rights to reproduce, distribute, display, and perform the specification solely for the purpose of      */
/*     developing products based on such documents.                                                               */
/*     Source Code Distribution Conditions:                                                                       */
/*     ·  Redistributions of Source Code must retain the above copyright licenses, this list of conditions       */
/*     and the following disclaimers.                                                                             */
/*     ·  Redistributions in binary form must reproduce the above copyright licenses, this list of conditions    */
/*     and the following disclaimers in the documentation and/or other materials provided with the                */
/*     distribution.                                                                                              */
/*     Disclaimers:                                                                                               */
/*     ·  THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF                                    */
/*     LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH                                      */
/*     RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)                                      */
/*     THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.                                        */
/*     Contact TCG Administration (admin@trustedcomputinggroup.org) for information on specification              */
/*     licensing rights available through TCG membership agreements.                                              */
/*     ·  THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED WARRANTIES                           */
/*     WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR FITNESS FOR A                                     */
/*     PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR NONINFRINGEMENT OF                                          */
/*     INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY OTHERWISE ARISING OUT OF                                     */
/*     ANY PROPOSAL, SPECIFICATION OR SAMPLE.                                                                     */
/*     ·  Without limitation, TCG and its members and licensors disclaim all liability, including liability for  */
/*     infringement of any proprietary rights, relating to use of information in this specification and to the    */
/*     implementation of this specification, and TCG disclaims all liability for cost of procurement of           */
/*     substitute goods or services, lost profits, loss of use, loss of data or any incidental, consequential,    */
/*     direct, indirect, or special damages, whether under contract, tort, warranty or otherwise, arising in      */
/*     any way out of use or reliance upon this specification or any information herein.                          */
/*     Any marks and brands contained herein are the property of their respective owners.                         */
/*                                                                                                                */
/******************************************************************************************************************/

// 8.8.1 Introduction
// This file contains the functions that support the physical presence operations of the TPM.
// 8.8.2 Includes
#include "Tpm.h"
void
PhysicalPresencePreInstall_Init(
    void
)
{
    COMMAND_INDEX commandIndex;
    // Clear all the PP commands
    MemorySet(&gp.ppList, 0, sizeof(gp.ppList));
    // Any command that is PP_REQUIRED should be SET
    for(commandIndex = 0; commandIndex < COMMAND_COUNT; commandIndex++)
    {
        if(s_commandAttributes[commandIndex] & IS_IMPLEMENTED
                && s_commandAttributes[commandIndex] & PP_REQUIRED)
            SET_BIT(commandIndex, gp.ppList);
    }
    // Write PP list to NV
    NV_SYNC_PERSISTENT(ppList);
    return;
}
void
PhysicalPresenceCommandSet(
    TPM_CC commandCode             // IN: command code
)
{
    COMMAND_INDEX commandIndex = CommandCodeToCommandIndex(commandCode);
    // if the command isn't implemented, the do nothing
    if(commandIndex == UNIMPLEMENTED_COMMAND_INDEX)
        return;
    // only set the bit if this is a command for which PP is allowed
    if(s_commandAttributes[commandIndex] & PP_COMMAND)
        SET_BIT(commandIndex, gp.ppList);
    return;
}
void
PhysicalPresenceCommandClear(
    TPM_CC commandCode                 // IN: command code
)
{
    COMMAND_INDEX commandIndex = CommandCodeToCommandIndex(commandCode);
    // If the command isn't implemented, then don't do anything
    if(commandIndex == UNIMPLEMENTED_COMMAND_INDEX)
        return;
    // Only clear the bit if the command does not require PP
    if((s_commandAttributes[commandIndex] & PP_REQUIRED) == 0)
        CLEAR_BIT(commandIndex, gp.ppList);
    return;
}
BOOL
PhysicalPresenceIsRequired(
    COMMAND_INDEX commandIndex                // IN: command index
)
{
    // Check the bit map. If the bit is SET, PP authorization is required
    return (TEST_BIT(commandIndex, gp.ppList));
}
TPMI_YES_NO
PhysicalPresenceCapGetCCList(
    TPM_CC commandCode,                // IN: start command code
    UINT32 count,                      // IN: count of returned TPM_CC
    TPML_CC *commandList                  // OUT: list of TPM_CC
)
{
    TPMI_YES_NO more = NO;
    COMMAND_INDEX commandIndex;
    // Initialize output handle list
    commandList->count = 0;
    // The maximum count of command we may return is MAX_CAP_CC
    if(count > MAX_CAP_CC) count = MAX_CAP_CC;
    // Collect PP commands
    for(commandIndex = GetClosestCommandIndex(commandCode);
            commandIndex != UNIMPLEMENTED_COMMAND_INDEX;
            commandIndex = GetNextCommandIndex(commandIndex))
    {
        if(PhysicalPresenceIsRequired(commandIndex))
        {
            if(commandList->count < count)
            {
                // If we have not filled up the return list, add this command
                // code to it
                commandList->commandCodes[commandList->count]
                    = GetCommandCode(commandIndex);
                commandList->count++;
            }
            else
            {
                // If the return list is full but we still have PP command
                // available, report this and stop iterating
                more = YES;
                break;
            }
        }
    }
    return more;
}
