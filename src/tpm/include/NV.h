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

#ifndef _NV_H_
#define _NV_H_
#ifdef TPM_NT_ORDINARY
# define NV_ATTRIBUTES_TO_TYPE(attributes) (attributes.TPM_NT)
#else
# define NV_ATTRIBUTES_TO_TYPE(attributes) \
 ( attributes.TPMA_NV_COUNTER \
 + (attributes.TPMA_NV_BITS << 1) \
 + (attributes.TPMA_NV_EXTEND << 2) \
 )
#endif
#ifdef TPM_NT_ORDINARY
# define IsNvOrdinaryIndex(attributes) (attributes.TPM_NT == TPM_NT_ORDINARY)
#else
# define IsNvOrdinaryIndex(attributes) \
 ((attributes.TPMA_NV_COUNTER == CLEAR) \
 && (attributes.TPMA_NV_BITS == CLEAR) \
 && (attributes.TPMA_NV_EXTEND == CLEAR)
# define TPM_NT_ORDINARY (0)
#endif
#ifdef TPM_NT_COUNTER
# define IsNvCounterIndex(attributes) (attributes.TPM_NT == TPM_NT_COUNTER)
#else
# define IsNvCounterIndex(attributes) (attributes.TPMA_NV_COUNTER == SET)
# define TPM_NT_COUNTER (1)
#endif
#ifdef TPM_NT_BITS
# define IsNvBitsIndex(attributes) (attributes.TPM_NT == TPM_NT_BITS)
#else
# define IsNvBitsIndex(attributes) (attributes.TPMA_NV_BITS == SET)
# define TPM_NT_BITS (2)
#endif
#ifdef TPM_NT_EXTEND
# define IsNvExtendIndex(attributes) (attributes.TPM_NT == TPM_NT_EXTEND)
#else
# define IsNvExtendIndex(attributes) (attributes.TPMA_NV_EXTEND == SET)
# define TPM_NT_EXTEND (4)
#endif
#ifdef TPM_NT_PIN_PASS
# define IsNvPinPassIndex(attributes) (attributes.TPM_NT == TPM_NT_PIN_PASS)
#endif
#ifdef TPM_NT_PIN_FAIL
# define IsNvPinFailIndex(attributes) (attributes.TPM_NT == TPM_NT_PIN_FAIL)
#endif
typedef struct {
    UINT32 size;
    TPM_HANDLE handle;
} NV_ENTRY_HEADER;
#define NV_EVICT_OBJECT_SIZE \
 (sizeof(UINT32) + sizeof(TPM_HANDLE) + sizeof(OBJECT))
#define NV_INDEX_COUNTER_SIZE \
 (sizeof(UINT32) + sizeof(NV_INDEX) + sizeof(UINT64))
#define NV_RAM_INDEX_COUNTER_SIZE \
 (sizeof(NV_RAM_HEADER) + sizeof(UINT64))
typedef struct {
    UINT32 size;
    TPM_HANDLE handle;
    TPMA_NV attributes;
} NV_RAM_HEADER;
typedef UINT32 NV_LIST_TERMINATOR[3];
#define NV_RAM_REF_INIT 0
#define RAM_ORDERLY_START \
 (&s_indexOrderlyRam[0])
#define NV_ORDERLY_START \
 (NV_INDEX_RAM_DATA)
#define RAM_ORDERLY_END \
 (RAM_ORDERLY_START + sizeof(s_indexOrderlyRam))
#define NV_ORDERLY_END \
 (NV_ORDERLY_START + sizeof(s_indexOrderlyRam))
#define ORDERLY_RAM_ADDRESS_OK(start, offset) \
 ((start >= RAM_ORDERLY_START) && ((start + offset - 1) < RAM_ORDERLY_END))
#define RETURN_IF_NV_IS_NOT_AVAILABLE \
{ \
 if(g_NvStatus != TPM_RC_SUCCESS) \
 return g_NvStatus; \
}
#define RETURN_IF_ORDERLY \
{ \
 if(NvClearOrderly() != TPM_RC_SUCCESS) \
 return g_NvStatus; \
}
#define NV_IS_AVAILABLE (g_NvStatus == TPM_RC_SUCCESS)
#define IS_ORDERLY(value) (value < SU_DA_USED_VALUE)
#define NV_IS_ORDERLY (IS_ORDERLY(gp.orderlyState))
#define SET_NV_UPDATE(type) g_updateNV |= (type)
#endif   // _NV_H_
