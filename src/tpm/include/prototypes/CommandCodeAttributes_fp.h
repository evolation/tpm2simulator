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

#ifndef _COMMANDCODEATTRIBUTES_FP_H_
#define _COMMANDCODEATTRIBUTES_FP_H_

#ifndef CC_VEND
#endif
#ifndef COMPRESSED_LISTS
#else
#endif
COMMAND_INDEX
GetClosestCommandIndex(
    TPM_CC commandCode                        // IN: the command code to start at
);

COMMAND_INDEX
CommandCodeToCommandIndex(
    TPM_CC commandCode                     // IN: the command code to look up
);

COMMAND_INDEX
GetNextCommandIndex(
    COMMAND_INDEX commandIndex     // IN: the starting index
);

TPM_CC
GetCommandCode(
    COMMAND_INDEX commandIndex     // IN: the command index
);

AUTH_ROLE
CommandAuthRole(
    COMMAND_INDEX commandIndex,    // IN: command index
    UINT32 handleIndex      // IN: handle index (zero based)
);

#ifndef INLINE_FUNCTIONS
int
EncryptSize(
    COMMAND_INDEX commandIndex     // IN: command index
);

#endif   // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
int
DecryptSize(
    COMMAND_INDEX commandIndex     // IN: command index
);

#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
BOOL
IsSessionAllowed(
    COMMAND_INDEX commandIndex             // IN: the command to be checked
);

#endif    // INLINE_FUNCTIONS
#ifndef INLINE_FUNCTIONS
BOOL
IsHandleInResponse(
    COMMAND_INDEX commandIndex
);

#endif    // INLINE_FUNCTIONS
BOOL
IsWriteOperation(
    COMMAND_INDEX commandIndex             // IN: Command to check
);

BOOL
IsReadOperation(
    COMMAND_INDEX commandIndex              // IN: Command to check
);

TPMI_YES_NO
CommandCapGetCCList(
    TPM_CC commandCode,              // IN: start command code
    UINT32 count,                    // IN: maximum count for number of entries in
    // 'commandList'
    TPML_CCA *commandList                // OUT: list of TPMA_CC
);

#ifndef INLINE_FUNCTIONS
BOOL
IsVendorCommand(
    COMMAND_INDEX commandIndex             // IN: command index to check
);

#endif    // INLINE_FUNCTIONS
#endif  // _COMMANDCODEATTRIBUTES_FP_H_
