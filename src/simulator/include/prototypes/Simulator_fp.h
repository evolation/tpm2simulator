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

#ifndef _SIMULATOR_FP_H_
#define _SIMULATOR_FP_H_

#ifdef _MSC_VER
#else
#endif
void RsaKeyCacheControl(int state);
#ifndef __IGNORE_STATE__
char InputBuffer[MAX_BUFFER];                 //The input data buffer for the simulator.
char OutputBuffer[MAX_BUFFER];                //The output data buffer for the simulator.
struct;

BOOL
PlatformServer(
    SOCKET s
);

DWORD WINAPI
PlatformSvcRoutine(
    LPVOID port
);

int
PlatformSignalService(
    int PortNumber
);

int
RegularCommandService(
    int PortNumber
);

int
StartTcpServer(
    int PortNumber
);

BOOL
ReadBytes(
    SOCKET s,
    char *buffer,
    int NumBytes
);

BOOL
WriteBytes(
    SOCKET s,
    char *buffer,
    int NumBytes
);

BOOL
WriteUINT32(
    SOCKET s,
    uint32_t val
);

BOOL
ReadVarBytes(
    SOCKET s,
    char *buffer,
    uint32_t *BytesReceived,
    int MaxLen
);

BOOL
WriteVarBytes(
    SOCKET s,
    char *buffer,
    int BytesToSend
);

BOOL
TpmServer(
    SOCKET s
);

void
_rpc__Signal_PowerOn(
    BOOL isReset
);

void
_rpc__Signal_Restart(
    void
);

void
_rpc__Signal_PowerOff(
    void
);

void
_rpc__ForceFailureMode(
    void
);

void
_rpc__Signal_PhysicalPresenceOn(
    void
);

void
_rpc__Signal_PhysicalPresenceOff(
    void
);

void
_rpc__Signal_Hash_Start(
    void
);

void
_rpc__Signal_Hash_Data(
    _IN_BUFFER input
);

void
_rpc__Signal_HashEnd(
    void
);

void
_rpc__Send_Command(
    unsigned char locality,
    _IN_BUFFER request,
    _OUT_BUFFER *response
);

void
_rpc__Signal_CancelOn(
    void
);

void
_rpc__Signal_CancelOff(
    void
);

void
_rpc__Signal_NvOn(
    void
);

void
_rpc__Signal_NvOff(
    void
);

void RsaKeyCacheControl(int state);
void
_rpc__RsaKeyCacheControl(
    int state
);

void
_rpc__Shutdown(
    void
);

void* MainPointer;
int
main(
    int argc,
    char *argv[]
);

#endif  // _SIMULATOR_FP_H_
