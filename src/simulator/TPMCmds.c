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


// D.6.1. Description

// This file contains the entry point for the simulator.

// D.6.2. Includes, Defines, Data Definitions, and Function Prototypes
#include "TpmBuildSwitches.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#if defined(_Win32) || defined(WIN32)
#include <windows.h>
#include <winsock.h>
#endif
#include "TpmTcpProtocol.h"
#include "Manufacture_fp.h"
#include "Platform_fp.h"
#include "Simulator_fp.h"
#define PURPOSE \
"TPM Reference Simulator.\nCopyright Microsoft 2010, 2011.\n"
#define DEFAULT_TPM_PORT 2321
void* MainPointer;

// D.6.3. Functions

// D.6.3.1. Usage()

// This function prints the proper calling sequence for the simulator.
static void
Usage(
    char *pszProgramName
)
{
    fprintf(stderr, "%s", PURPOSE);
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s - Starts the TPM server listening on port %d\n",
            pszProgramName, DEFAULT_TPM_PORT);
    fprintf(stderr,
            "%s PortNum - Starts the TPM server listening on port PortNum\n",
            pszProgramName);
    fprintf(stderr, "%s ? - This message\n", pszProgramName);
    exit(1);
}

// D.6.3.2. main()

// This is the main entry point for the simulator.

// main: register the interface, start listening for clients
int
main(
    int argc,
    char *argv[]
)
{
    int portNum = DEFAULT_TPM_PORT;
    if(argc > 2)
    {
        Usage(argv[0]);
    }
    if(argc == 2)
    {
        if(strcmp(argv[1], "?") == 0)
        {
            Usage(argv[0]);
        }
        portNum = atoi(argv[1]);
        if(portNum <= 0 || portNum > 65535)
        {
            Usage(argv[0]);
        }
    }
    _plat__NVEnable(NULL);
    if(TPM_Manufacture(1) != 0)
    {
        exit(1);
    }
    // Coverage test - repeated manufacturing attempt
    if(TPM_Manufacture(0) != 1)
    {
        exit(2);
    }
    // Coverage test - re-manufacturing
    TPM_TearDown();
    if(TPM_Manufacture(1) != 0)
    {
        exit(3);
    }
    // Disable NV memory
    _plat__NVDisable();
    StartTcpServer(portNum);
    return EXIT_SUCCESS;
}
