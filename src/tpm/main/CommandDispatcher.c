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

// 6.3.1 Introduction
// CommandDispatcher() performs the following operations:
// · unmarshals command parameters from the input buffer;
// NOTE Unlike other unmarshaling functions, parmBufferStart does not advance. parmBufferSize Is
// reduced.
// · invokes the function that performs the command actions;
// · marshals the returned handles, if any; and
// · marshals the returned parameters, if any, into the output buffer putting in the parameterSize field
// if authorization sessions are present.
// NOTE 1 The output buffer is the return from the MemoryGetResponseBuffer() function. It includes the
// header, handles,
// response parameters, and authorization area. respParmSize is the response parameter size, and does not
// include the header, handles, or authorization area.
// NOTE 2 The reference implementation is permitted to do compare operations over a union as a byte array.
// Therefore,
// the command parameter in structure must be initialized (e.g., zeroed) before unmarshaling so that the compare
// operation is valid in cases where some bytes are unused.
// 6.3.2 Includes
#include "Tpm.h"
#ifdef TABLE_DRIVEN_DISPATCH   //%
typedef TPM_RC(NoFlagFunction)(void *target, BYTE **buffer, INT32 *size);
typedef TPM_RC(FlagFunction)(void *target, BYTE **buffer, INT32 *size, BOOL flag);
typedef FlagFunction *UNMARSHAL_t;
typedef INT16(MarshalFunction)(void *source, BYTE **buffer, INT32 *size);
typedef MarshalFunction *MARSHAL_t;
typedef TPM_RC(COMMAND_NO_ARGS)(void);
typedef TPM_RC(COMMAND_IN_ARG)(void *in);
typedef TPM_RC(COMMAND_OUT_ARG)(void *out);
typedef TPM_RC(COMMAND_INOUT_ARG)(void *in, void *out);
typedef union
{
    COMMAND_NO_ARGS *noArgs;
    COMMAND_IN_ARG *inArg;
    COMMAND_OUT_ARG *outArg;
    COMMAND_INOUT_ARG *inOutArg;
} COMMAND_t;
typedef struct
{
    COMMAND_t command;                 // Address of the command
    UINT16 inSize;                  // Maximum size of the input structure
    UINT16 outSize;                 // Maximum size of the output structure
    UINT16 typesOffset;             // address of the types field
    UINT16 offsets[1];
} COMMAND_DESCRIPTOR_t;
#ifdef COMPRESSED_LISTS
# define PAD_LIST 0
#else
# define PAD_LIST 1
#endif
#define _COMMAND_TABLE_DISPATCH_
#include "CommandDispatchData.h"
#define TEST_COMMAND TPM_CC_Startup
#define NEW_CC
#else
#include "Commands.h"
#endif
TPM_RC
ParseHandleBuffer(
    COMMAND *command
)
{
    TPM_RC result;
#if defined TABLE_DRIVEN_DISPATCH
    COMMAND_DESCRIPTOR_t *desc;
    BYTE *types;
    BYTE type;
    BYTE dtype;
    // Make sure that nothing strange has happened
    pAssert(command->index
            < sizeof(s_CommandDataArray)                     / sizeof(COMMAND_DESCRIPTOR_t *));
    // Get the address of the descriptor for this command
    desc = s_CommandDataArray[command->index];
    pAssert(desc != NULL);
    // Get the associated list of unmarshaling data types.
    types = &((BYTE *)desc)[desc->typesOffset];
// if(s_ccAttr[commandIndex].commandIndex == TEST_COMMAND)
// commandIndex = commandIndex;
    // No handles yet
    command->handleNum = 0;
    // Get the first type value
    for(type = *types++;
            // check each byte to make sure that we have not hit the start
            // of the parameters
            (dtype = (type & 0x7F)) < PARAMETER_FIRST_TYPE;
            // get the next type
            type = *types++)
    {
        // See if unmarshaling of this handle type requires a flag
        if(dtype < HANDLE_FIRST_FLAG_TYPE)
        {
            // Look up the function to do the unmarshaling
            NoFlagFunction *f = (NoFlagFunction *)UnmarshalArray[dtype];
            // call it
            result = f(&(command->handles[command->handleNum]),
                       &command->parameterBuffer,
                       &command->parameterSize);
        }
        else
        {
            // Look up the function
            FlagFunction *f = UnmarshalArray[dtype];
            // Call it setting the flag to the appropriate value
            result = f(&(command->handles[command->handleNum]),
                       &command->parameterBuffer,
                       &command->parameterSize, (type & 0x80) != 0);
        }
        // Got a handle
        // We do this first so that the match for the handle offset of the
        // response code works correctly.
        command->handleNum += 1;
        if(result != TPM_RC_SUCCESS)
            // if the unmarshaling failed, return the response code with the
            // handle indication set
            return result + TPM_RC_H + (command->handleNum * TPM_RC_1);
    }
#else
    BYTE **handleBufferStart = &command->parameterBuffer;
    INT32 *bufferRemainingSize = &command->parameterSize;
    TPM_HANDLE *handles = &command->handles[0];
    UINT32 *handleCount = &command->handleNum;
    switch(command->code)
    {
#include "HandleProcess.h"
#undef handles
    default:
        FAIL(FATAL_ERROR_INTERNAL);
        break;
    }
#endif
    return TPM_RC_SUCCESS;
}
TPM_RC
CommandDispatcher(
    COMMAND *command
)
{
#if !defined TABLE_DRIVEN_DISPATCH
    TPM_RC result;
    BYTE *parm_buffer = command->parameterBuffer;
    INT32 *paramBufferSize = &command->parameterSize;
    BYTE *responseBuffer = command->responseBuffer;
    INT32 resHandleSize = 0;
    INT32 *responseHandleSize = &resHandleSize;
    INT32 *respParmSize = &command->parameterSize;
    BYTE rHandle[4];
    BYTE *responseHandle = &rHandle[0];
    INT32 rSize = MAX_RESPONSE_SIZE;                       // used to make sure that the marshaling
    // operation does not run away due to
    // bad parameter in the function
    // output.
    TPM_HANDLE *handles = &command->handles[0];
    switch(GetCommandCode(command->index))
    {
#include "CommandDispatcher.h"
    default:
        FAIL(FATAL_ERROR_INTERNAL);
        break;
    }
    command->responseBuffer = responseBuffer;
    command->handleNum = 0;
    // The response handle was marshaled into rHandle. 'Unmarshal' it into
    // handles.
    if(*responseHandleSize > 0)
    {
        command->handles[command->handleNum++] = BYTE_ARRAY_TO_UINT32(rHandle);
    }
    return TPM_RC_SUCCESS;
#else
    COMMAND_DESCRIPTOR_t *desc;
    BYTE *types;
    BYTE type;
    UINT16 *offsets;
    UINT16 offset = 0;
    UINT32 maxInSize;
    BYTE *commandIn;
    INT32 maxOutSize;
    BYTE *commandOut;
    COMMAND_t cmd;
    TPM_HANDLE *handles;
    UINT32 hasInParameters = 0;
    BOOL hasOutParameters = FALSE;
    UINT32 pNum = 0;
    BYTE dType;                   // dispatch type
    TPM_RC result;
// Get the address of the descriptor for this command
    pAssert(command->index
            < sizeof(s_CommandDataArray)                              / sizeof(COMMAND_DESCRIPTOR_t *));
    desc = s_CommandDataArray[command->index];
// Get the list of parameter types for this command
    pAssert(desc != NULL);
    types = &((BYTE *)desc)[desc->typesOffset];
// Get a pointer to the list of parameter offsets
    offsets = &desc->offsets[0];
// pointer to handles
    handles = command->handles;
// Get the size required to hold all the unmarshaled parameters for this command
    maxInSize = desc->inSize;
// and the size of the output parameter structure returned by this command
    maxOutSize = desc->outSize;
// Get a buffer for the input parameters
    commandIn = MemoryGetActionInputBuffer(maxInSize);
// And the output parameters
    commandOut = (BYTE *)MemoryGetActionOutputBuffer((UINT32)maxOutSize);
// Get the address of the action code dispatch
    cmd = desc->command;
// Copy any handles into the input buffer
    for(type = *types++; (type & 0x7F) < PARAMETER_FIRST_TYPE; type = *types++)
    {
        // 'offset' was initialized to zero so the first unmarshaling will always
        // be to the start of the data structure
        *(TPM_HANDLE *)&(commandIn[offset]) = *handles++;
        // This check is used so that we don't have to add an additional offset
        // value to the offsets list to correspond to the stop value in the
        // command parameter list.
        if(*types != 0xFF)
            offset = *offsets++;
        maxInSize -= sizeof(TPM_HANDLE);
        hasInParameters++;
    }
// Exit loop with type containing the last value read from types
// maxInSize has the amount of space remaining in the command action input
// buffer. Make sure that we don't have more data to unmarshal than is going to
// fit.
// type contains the last value read from types so it is not necessary to
// reload it, which is good because *types now points to the next value
    for(; (dType = (type & 0x7F)) <= PARAMETER_LAST_TYPE; type = *types++)
    {
        pNum++;
        if(dType < PARAMETER_FIRST_FLAG_TYPE)
        {
            NoFlagFunction *f = (NoFlagFunction *)UnmarshalArray[dType];
            result = f(&commandIn[offset], &command->parameterBuffer,
                       &command->parameterSize);
        }
        else
        {
            FlagFunction *f = UnmarshalArray[dType];
            result = f(&commandIn[offset], &command->parameterBuffer,
                       &command->parameterSize,
                       (type & 0x80) != 0);
        }
        if(result != TPM_RC_SUCCESS)
            return result + TPM_RC_P + (TPM_RC_1 * pNum);
        // This check is used so that we don't have to add an additional offset
        // value to the offsets list to correspond to the stop value in the
        // command parameter list.
        if(*types != 0xFF)
            offset = *offsets++;
        hasInParameters++;
    }
// Should have used all the bytes in the input
    if(command->parameterSize != 0)
        return TPM_RC_SIZE;
// The command parameter unmarshaling stopped when it hit a value that was out
// of range for unmarshaling values and left *types pointing to the first
// marshaling type. If that type happens to be the STOP value, then there
// are no response parameters. So, set the flag to indicate if there are
// output parameters.
    hasOutParameters = *types != 0xFF;
// There are four cases for calling, with and without input parameters and with
// and without output parameters.
    if(hasInParameters > 0)
    {
        if(hasOutParameters)
            result = cmd.inOutArg(commandIn, commandOut);
        else
            result = cmd.inArg(commandIn);
    }
    else
    {
        if(hasOutParameters)
            result = cmd.outArg(commandOut);
        else
            result = cmd.noArgs();
    }
    if(result != TPM_RC_SUCCESS)
        return result;
// Offset in the marshaled output structure
    offset = 0;
// Process the return handles, if any
    command->handleNum = 0;
// Could make this a loop to process output handles but there is only ever
// one handle in the outputs (for now).
    type = *types++;
    if((dType = (type & 0x7F)) < RESPONSE_PARAMETER_FIRST_TYPE)
    {
        // The out->handle value was referenced as TPM_HANDLE in the
        // action code so it has to be properly aligned.
        command->handles[command->handleNum++] =
            *((TPM_HANDLE *)&(commandOut[offset]));
        maxOutSize -= sizeof(UINT32);
        type = *types++;
        offset = *offsets++;
    }
// Use the size of the command action output buffer as the maximum for the
    // number of bytes that can get marshaled. Since the marshaling code has
    // no pointers to data, all of the data being returned has to be in the
    // command action output buffer. If we try to marshal more bytes than
    // could fit into the output buffer, we need to fail.
    for(; (dType = (type & 0x7F)) <= RESPONSE_PARAMETER_LAST_TYPE
            && !g_inFailureMode; type = *types++)
    {
        const MARSHAL_t f = MarshalArray[dType];
        command->parameterSize += f(&commandOut[offset], &command->responseBuffer,
                                    &maxOutSize);
        offset = *offsets++;
    }
    return (maxOutSize < 0) ? TPM_RC_FAILURE : TPM_RC_SUCCESS;
#endif
}
