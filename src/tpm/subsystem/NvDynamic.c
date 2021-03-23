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

// 8.4.1 Introduction
// The NV memory is divided into two area: dynamic space for user defined NV Indices and evict objects,
// and reserved space for TPM persistent and state save data.
// The entries in dynamic space are a linked list of entries. Each entry has, as its first field, a size. If the size
// field is zero, it marks the end of the list.
// An Index allocation will contain an NV_INDEX structure. If the Index does not have the orderly attribute,
// the NV_INDEX is followed immediately by the NV data.
// An evict object entry contains a handle followed by an OBJECT structure. This results in both the Index
// and Evict Object having an identifying handle as the first field following the size field.
// When an Index has the orderly attribute, the data is kept in RAM. This RAM is saved to backing store in
// NV memory on any orderly shutdown. The entries in orderly memory are also a linked list using a size
// field as the first entry.
// The attributes of an orderly index are maintained in RAM memory in order to reduce the number of NV
// writes needed for orderly data. When an orderly index is created, an entry is made in the dynamic NV
// memory space that holds the Index authorizations (authPolicy and authValue) and the size of the data.
// This entry is only modified if the authValue of the index is changed. The more volatile data of the index is
// kept in RAM. When an orderly Index is created or deleted, the RAM data is copied to NV backing store so
// that the image in the backing store matches the layout of RAM. In normal operation. The RAM data is
// also copied on any orderly shutdown. In normal operation, the only other reason for writing to the backing
// store for RAM is when a counter is first written (TPMA_NV_WRITTEN changes from CLEAR to SET) or
// when a counter "rolls over."
// Static space contains items that are individually modifiable. The values are in the
// gp
// PERSISTEND_DATA structure in RAM and mapped to locations in NV.
// 8.4.2 Includes, Defines and Data Definitions
#define NV_C
#include "Tpm.h"
#include "PlatformData.h"
static NV_REF
NvNext(
    NV_REF *iter,                 // IN/OUT: the list iterator
    TPM_HANDLE *handle                // OUT: the handle of the next item.
)
{
    NV_REF currentAddr;
    NV_ENTRY_HEADER header;
    // If iterator is at the beginning of list
    if(*iter == NV_REF_INIT)
    {
        // Initialize iterator
        *iter = NV_USER_DYNAMIC;
    }
    // if we are going to return what the iter is currently pointing to...
    currentAddr = *iter + sizeof(UINT32);
    // If iterator reaches the end of NV space, then don't advance and return
    // that we are at the end of the list. The end of the list occurs when
    // we don't have space for a size and a handle
// if(*iter + sizeof(UINT32) > s_evictNvEnd)
// return 0;
    // read the header of the next entry
    NvRead(&header, *iter, sizeof(NV_ENTRY_HEADER));
    // if the size field is zero, then we have hit the end of the list
    if(header.size == 0)
        // leave the *iter pointing at the end of the list
        return 0;
    // advance the header by the size of the entry
    *iter += header.size;
    if(handle != NULL)
        *handle = header.handle;
    return currentAddr;
}
static NV_REF
NvNextByType(
    TPM_HANDLE *handle,                       // OUT: the handle of the found type
    NV_REF *iter,                         // IN: the iterator
    TPM_HT type                        // IN: the handle type to look for
)
{
    NV_REF addr;
    TPM_HANDLE nvHandle;
    while((addr = NvNext(iter, &nvHandle)) != 0)
    {
        // addr: the address of the location containing the handle of the value
        // iter: the next location.
        if(HandleGetType(nvHandle) == type)
            break;
    }
    if(handle != NULL)
        *handle = nvHandle;
    return addr;
}
#define NvNextIndex(handle, iter) \
 NvNextByType(handle, iter, TPM_HT_NV_INDEX)
#define NvNextEvict(handle, iter) \
 NvNextByType(handle, iter, TPM_HT_PERSISTENT)
static NV_REF
NvGetEnd(
    void
)
{
    NV_REF iter = NV_REF_INIT;
    NV_REF currentAddr;
    // Scan until the next address is 0
    while((currentAddr = NvNext(&iter, NULL)) != 0);
    return iter;
}
static UINT32
NvGetFreeBytes(
    void
)
{
    return s_evictNvEnd - NvGetEnd();
}
static BOOL
NvTestSpace(
    UINT32 size,                   // IN: size of the entity to be added
    BOOL isIndex,                // IN: TRUE if the entity is an index
    BOOL isCounter                       // IN: TRUE if the index is a counter
)
{
    UINT32 remainBytes = NvGetFreeBytes();
    UINT32 reserved = sizeof(UINT32)                      // size of the forward pointer
                      + sizeof(NV_LIST_TERMINATOR);
// Do a compile time sanity check on the setting for NV_MEMORY_SIZE
#if NV_MEMORY_SIZE < 1024
#error "NV_MEMORY_SIZE probably isn't large enough"
#endif
    // For NV Index, need to make sure that we do not allocate an Index if this
    // would mean that the TPM cannot allocate the minimum number of evict
    // objects.
    if(isIndex)
    {
        // Get the number of persistent objects allocated
        UINT32 persistentNum = NvCapGetPersistentNumber();
        // If we have not allocated the requisite number of evict objects, then we
        // need to reserve space for them.
        // NOTE: some of this is not written as simply as it might seem because
        // the values are all unsigned and subtracting needs to be done carefully
        // so that an underflow doesn't cause problems.
        if(persistentNum < MIN_EVICT_OBJECTS)
            reserved += (MIN_EVICT_OBJECTS - persistentNum) * NV_EVICT_OBJECT_SIZE;
    }
    // If this is not an index or is not a counter, reserve space for the
    // required number of counter indices
    if(!isIndex || !isCounter)
    {
        // Get the number of counters
        UINT32 counterNum = NvCapGetCounterNumber();
        // If the required number of counters have not been allocated, reserved
        // space for the extra needed counters
        if(counterNum < MIN_COUNTER_INDICES)
            reserved += (MIN_COUNTER_INDICES - counterNum) * NV_INDEX_COUNTER_SIZE;
    }
    // Check that the requested allocation will fit after making sure that there
    // will be no chance of overflow
    return ((reserved < remainBytes)
            && (size <= remainBytes)
            && (size + reserved <= remainBytes));
}
NV_REF
NvWriteNvListEnd(
    NV_REF end
)
{
    BYTE listEndMarker[sizeof(NV_LIST_TERMINATOR)] = {0};
    UINT64 maxCount = NvReadMaxCount();
    // This is a constant check that can be resolved at compile time.
    cAssert(sizeof(UINT64) <= sizeof(NV_LIST_TERMINATOR) - sizeof(UINT32));
    MemoryCopy(&listEndMarker[sizeof(UINT32)], &maxCount, sizeof(UINT64));
    pAssert(end + sizeof(NV_LIST_TERMINATOR) <= s_evictNvEnd);
    NvWrite(end, sizeof(NV_LIST_TERMINATOR), &listEndMarker);
    return end + sizeof(NV_LIST_TERMINATOR);
}
static TPM_RC
NvAdd(
    UINT32 totalSize,                 // IN: total size needed for this entity For
    // evict object, totalSize is the same as
    // bufferSize. For NV Index, totalSize is
    // bufferSize plus index data size
    UINT32 bufferSize,                // IN: size of initial buffer
    TPM_HANDLE handle,                    // IN: optional handle
    BYTE *entity                       // IN: initial buffer
)
{
    NV_REF newAddr;                      // IN: where the new entity will start
    NV_REF nextAddr;
    RETURN_IF_NV_IS_NOT_AVAILABLE;
    // Get the end of data list
    newAddr = NvGetEnd();
    // Step over the forward pointer
    nextAddr = newAddr + sizeof(UINT32);
    // Optionally write the handle. For indices, the handle is TPM_RH_UNASSIGNED
    // so that the handle in the nvIndex is used instead of writing this value
    if(handle != TPM_RH_UNASSIGNED)
    {
        NvWrite((UINT32)nextAddr, sizeof(TPM_HANDLE), &handle);
        nextAddr += sizeof(TPM_HANDLE);
    }
    // Write entity data
    NvWrite((UINT32)nextAddr, bufferSize, entity);
    // Advance the pointer by the amount of the total
    nextAddr += totalSize;
    // Finish by writing the link value
    // Write the next offset (relative addressing)
    totalSize = nextAddr - newAddr;
    // Write link value
    NvWrite((UINT32)newAddr, sizeof(UINT32), &totalSize);
    // Write the list terminator
    NvWriteNvListEnd(nextAddr);
    return TPM_RC_SUCCESS;
}
static TPM_RC
NvDelete(
    NV_REF entityRef                  // IN: reference to entity to be deleted
)
{
    UINT32 entrySize;
    // adjust entityAddr to back up and point to the forward pointer
    NV_REF entryRef = entityRef - sizeof(UINT32);
    NV_REF endRef = NvGetEnd();
    NV_REF nextAddr;            // address of the next entry
    RETURN_IF_NV_IS_NOT_AVAILABLE;
    // Get the offset of the next entry. That is, back up and point to the size
    // field of the entry
    NvRead(&entrySize, entryRef, sizeof(UINT32));
    // The next entry after the one being deleted is at a relative offset
    // from the current entry
    nextAddr = entryRef + entrySize;
    // If this is not the last entry, move everything up
    if(nextAddr < endRef)
    {
        pAssert(nextAddr > entryRef);
        _plat__NvMemoryMove(nextAddr,
                            entryRef,
                            (endRef - nextAddr));
    }
    // The end of the used space is now moved up by the amount of space we just
    // reclaimed
    endRef -= entrySize;
    // Write the end marker, and make the new end equal to the first byte after
    // the just added end value. This will automatically update the NV value for
    // maxCounte
    endRef = NvWriteNvListEnd(endRef);
    // Clear the reclaimed memory
    _plat__NvMemoryClear(endRef, entrySize);
    return TPM_RC_SUCCESS;
}
static NV_RAM_REF
NvRamNext(
    NV_RAM_REF *iter,                       // IN/OUT: the list iterator
    TPM_HANDLE *handle                      // OUT: the handle of the next item.
)
{
    NV_RAM_REF currentAddr;
    NV_RAM_HEADER header;
    // If iterator is at the beginning of list
    if(*iter == NV_RAM_REF_INIT)
    {
        // Initialize iterator
        *iter = &s_indexOrderlyRam[0];
    }
    // if we are going to return what the iter is currently pointing to...
    currentAddr = *iter;
    // If iterator reaches the end of NV space, then don't advance and return
    // that we are at the end of the list. The end of the list occurs when
    // we don't have space for a size and a handle
    if(*iter + sizeof(NV_RAM_HEADER) >= RAM_ORDERLY_END)
        return NULL;
    // read the header of the next entry
    MemoryCopy(&header, *iter, sizeof(NV_RAM_HEADER));
    // if the size field is zero, then we have hit the end of the list
    if(header.size == 0)
        // leave the *iter pointing at the end of the list
        return 0;
    // advance the header by the size of the entry
    *iter += header.size;
    pAssert(*iter <= RAM_ORDERLY_END);
    if(handle != NULL)
        *handle = header.handle;
    return currentAddr;
}
static NV_RAM_REF
NvRamGetEnd(
    void
)
{
    NV_RAM_REF iter = NV_RAM_REF_INIT;
    NV_RAM_REF currentAddr;
    // Scan until the next address is 0
    while((currentAddr = NvRamNext(&iter, NULL)) != 0);
    return iter;
}
static BOOL
NvRamTestSpaceIndex(
    UINT32 size                 // IN: size of the data to be added to RAM
)
{
    UINT32 remaining = RAM_ORDERLY_END - NvRamGetEnd();
    UINT32 needed = sizeof(NV_RAM_HEADER) + size;
    // NvRamGetEnd points to the next available byte.
    return remaining >= needed;
}
static NV_RAM_REF
NvRamGetIndex(
    TPMI_RH_NV_INDEX handle               // IN: NV handle
)
{
    NV_RAM_REF iter = NV_RAM_REF_INIT;
    NV_RAM_REF currentAddr;
    TPM_HANDLE foundHandle;
    while((currentAddr = NvRamNext(&iter, &foundHandle)) != 0)
    {
        if(handle == foundHandle)
            break;
    }
    pAssert(ORDERLY_RAM_ADDRESS_OK(currentAddr, 0));
    return currentAddr;
}
void
NvUpdateIndexOrderlyData(
    void
)
{
    // Write reserved RAM space to NV
    NvWrite(NV_INDEX_RAM_DATA, sizeof(s_indexOrderlyRam), s_indexOrderlyRam);
}
static void
NvAddRAM(
    TPMS_NV_PUBLIC *index                  // IN: the index descriptor
)
{
    NV_RAM_HEADER header;
    NV_RAM_REF end = NvRamGetEnd();
    header.size = sizeof(NV_RAM_HEADER) + index->dataSize;
    header.handle = index->nvIndex;
    MemoryCopy(&header.attributes, &index->attributes, sizeof(TPMA_NV));
    pAssert(ORDERLY_RAM_ADDRESS_OK(end, header.size));
    // Copy the header to the memory
    MemoryCopy(end, &header, sizeof(NV_RAM_HEADER));
    // Clear the data area (just in case)
    MemorySet(end + sizeof(NV_RAM_HEADER), 0, index->dataSize);
    // Step over this new entry
    end += header.size;
    // If the end marker will fit, add it
    if(end + sizeof(NV_RAM_HEADER) < RAM_ORDERLY_END)
        MemorySet(end, 0, sizeof(NV_RAM_HEADER));
    // Write reserved RAM space to NV to reflect the newly added NV Index
    SET_NV_UPDATE(UT_ORDERLY);
    return;
}
static void
NvDeleteRAM(
    TPMI_RH_NV_INDEX handle                  // IN: NV handle
)
{
    NV_RAM_REF nodeAddress;
    NV_RAM_REF nextNode;
    UINT32 size;
    NV_RAM_REF lastUsed = NvRamGetEnd();
    nodeAddress = NvRamGetIndex(handle);
    pAssert(nodeAddress != 0);
    // Get node size
    MemoryCopy(&size, nodeAddress, sizeof(size));
    // Get the offset of next node
    nextNode = nodeAddress + size;
    // Copy the data
    MemoryCopy(nodeAddress, nextNode, lastUsed - nextNode);
    // Clear out the reclaimed space
    MemorySet(lastUsed - size, 0, size);
    // Write reserved RAM space to NV to reflect the newly delete NV Index
    SET_NV_UPDATE(UT_ORDERLY);
    return;
}
void
NvReadNvIndexInfo(
    NV_REF ref,                       // IN: points to NV where index is located
    NV_INDEX *nvIndex                   // OUT: place to receive index data
)
{
    pAssert(nvIndex != NULL);
    NvRead(nvIndex, ref, sizeof(NV_INDEX));
}
void
NvReadObject(
    NV_REF ref,                       // IN: points to NV where index is located
    OBJECT *object                    // OUT: place to receive the object data
)
{
    NvRead(object, (ref + sizeof(TPM_HANDLE)), sizeof(OBJECT));
}
static NV_REF
NvFindEvict(
    TPM_HANDLE nvHandle,
    OBJECT *object
)
{
    NV_REF found = NvFindHandle(nvHandle);
    // If we found the handle and the request included an object pointer, fill it in
    if(found != 0 && object != NULL)
        NvReadObject(found, object);
    return found;
}
BOOL
NvIndexIsDefined(
    TPM_HANDLE nvHandle                 // IN: Index to look for
)
{
    return (NvFindHandle(nvHandle) != 0);
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

static TPM_RC
NvConditionallyWrite(
    NV_REF entryAddr,               // IN: stating address
    UINT32 size,                    // IN: size of the data to write
    void *data                    // IN: the data to write
)
{
    // If the index data is actually changed, then a write to NV is required
    if(_plat__NvIsDifferent(entryAddr, size, data))
    {
        // Write the data if NV is available
        if(g_NvStatus == TPM_RC_SUCCESS)
        {
            NvWrite(entryAddr, size, data);
            // NV needs an update           //??
            SET_NV_UPDATE(UT_NV);                       //??
        }
        return g_NvStatus;
    }
    return TPM_RC_SUCCESS;
}
static TPMA_NV
NvReadNvIndexAttributes(
    NV_REF locator          // IN: reference to an NV index
)
{
    TPMA_NV attributes;
    NvRead(&attributes,
           locator + offsetof(NV_INDEX, publicArea.attributes),
           sizeof(TPMA_NV));
    return attributes;
}
static TPMA_NV
NvReadRamIndexAttributes(
    NV_RAM_REF ref              // IN: pointer to a NV_RAM_HEADER
)
{
    TPMA_NV attributes;
    MemoryCopy(&attributes, ref + offsetof(NV_RAM_HEADER, attributes),
               sizeof(TPMA_NV));
    return attributes;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

static TPM_RC
NvWriteNvIndexAttributes(
    NV_REF locator,         // IN: location of the index
    TPMA_NV attributes       // IN: attributes to write
)
{
    return NvConditionallyWrite(
               locator + offsetof(NV_INDEX, publicArea.attributes),
               sizeof(TPMA_NV),
               &attributes);
}
static void
NvWriteRamIndexAttributes(
    NV_RAM_REF ref,                 // IN: address of the header
    TPMA_NV attributes           // IN: the attributes to write
)
{
    MemoryCopy(ref + offsetof(NV_RAM_HEADER, attributes), &attributes,
               sizeof(TPMA_NV));
}
BOOL
NvIsPlatformPersistentHandle(
    TPM_HANDLE handle               // IN: handle
)
{
    return (handle >= PLATFORM_PERSISTENT && handle <= PERSISTENT_LAST);
}
BOOL
NvIsOwnerPersistentHandle(
    TPM_HANDLE handle               // IN: handle
)
{
    return (handle >= PERSISTENT_FIRST && handle < PLATFORM_PERSISTENT);
}

// E r
// M e
// TPM_RC_HANDLE


// TPM_RC_NV_READLOCKED

// TPM_RC_NV_WRITELOCKED


TPM_RC
NvIndexIsAccessible(
    TPMI_RH_NV_INDEX handle                  // IN: handle
)
{
    NV_INDEX *nvIndex = NvGetIndexInfo(handle, NULL);
    if(nvIndex == NULL)
        // If index is not found, return TPM_RC_HANDLE
        return TPM_RC_HANDLE;
    if(gc.shEnable == FALSE || gc.phEnableNV == FALSE)
    {
        // if shEnable is CLEAR, an ownerCreate NV Index should not be
        // indicated as present
        if(!IsNv_TPMA_NV_PLATFORMCREATE(nvIndex->publicArea.attributes))
        {
            if(gc.shEnable == FALSE)
                return TPM_RC_HANDLE;
        }
        // if phEnableNV is CLEAR, a platform created Index should not
        // be visible
        else if(gc.phEnableNV == FALSE)
            return TPM_RC_HANDLE;
    }
#if 0   // Writelock test
    // If the Index is write locked and this is an NV Write operation...
    if(IsNv_TPMA_NV_WRITELOCKED(nvIndex->publicArea.attributes)
            && IsWriteOperation(commandIndex))
    {
        // then return a locked indication unless the command is TPM2_NV_WriteLock
        if(GetCommandCode(commandIndex) != TPM_CC_NV_WriteLock)
            return TPM_RC_NV_LOCKED;
        return TPM_RC_SUCCESS;
    }
#endif
#if 0       // Readlock Test
    // If the Index is read locked and this is an NV Read operation...
    if(IsNv_TPMA_NV_READLOCKED(nvIndex->publicArea.attributes)
            && IsReadOperation(commandIndex))
    {
        // then return a locked indication unless the command is TPM2_NV_ReadLock
        if(GetCommandCode(commandIndex) != TPM_CC_NV_ReadLock)
            return TPM_RC_NV_LOCKED;
    }
#endif
    // NV Index is accessible
    return TPM_RC_SUCCESS;
}

// E r
// M e
// TPM_RC_HANDLE

TPM_RC
NvGetEvictObject(
    TPM_HANDLE handle,                // IN: handle
    OBJECT *object                // OUT: object data
)
{
    NV_REF entityAddr;                       // offset points to the entity
    // Find the address of evict object and copy to object
    entityAddr = NvFindEvict(handle, object);
    // whether there is an error or not, make sure that the evict
    // status of the object is set so that the slot will get freed on exit
    // Must do this after NvFindEvict loads the object
    object->attributes.evict = SET;
    // If handle is not found, return an error
    if(entityAddr == 0)
        return TPM_RC_HANDLE;
    return TPM_RC_SUCCESS;
}
void
NvIndexCacheInit(
    void
)
{
    s_cachedNvRef = NV_REF_INIT;
    s_cachedNvRamRef = NV_RAM_REF_INIT;
    s_cachedNvIndex.publicArea.nvIndex = TPM_RH_UNASSIGNED;
}
void
NvGetIndexData(
    NV_INDEX *nvIndex,              // IN: the in RAM index descriptor
    NV_REF locator,               // IN: where the data is located
    UINT32 offset,                // IN: offset of NV data
    UINT16 size,                  // IN: size of NV data
    void *data                  // OUT: data buffer
)
{
    TPMA_NV nvAttributes;
    pAssert(nvIndex != NULL);
    nvAttributes = nvIndex->publicArea.attributes;
    pAssert(nvAttributes.TPMA_NV_WRITTEN == SET);
    if(nvAttributes.TPMA_NV_ORDERLY == SET)
    {
        // Get data from RAM buffer
        NV_RAM_REF ramAddr = NvRamGetIndex(nvIndex->publicArea.nvIndex);
        pAssert(ramAddr != 0 && (size <=
                                 ((NV_RAM_HEADER *)ramAddr)->size - sizeof(NV_RAM_HEADER) - offset));
        MemoryCopy(data, ramAddr + sizeof(NV_RAM_HEADER) + offset, size);
    }
    else
    {
        // Validate that read falls within range of the index
        pAssert(offset <= nvIndex->publicArea.dataSize
                && size <= (nvIndex->publicArea.dataSize - offset));
        NvRead(data, locator + sizeof(NV_INDEX) + offset, size);
    }
    return;
}
UINT64
NvGetUINT64Data(
    NV_INDEX *nvIndex,                // IN: the in RAM index descriptor
    NV_REF locator               // IN: where index exists in NV
)
{
    UINT64 intVal;
    // Read the value and convert it to internal format
    NvGetIndexData(nvIndex, locator, 0, 8, &intVal);
    return BYTE_ARRAY_TO_UINT64(((BYTE *)&intVal));
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

TPM_RC
NvWriteIndexAttributes(
    TPM_HANDLE handle,
    NV_REF locator,              // IN: location of the index
    TPMA_NV attributes            // IN: attributes to write
)
{
    TPM_RC result;
    if(IsNv_TPMA_NV_ORDERLY(attributes))
    {
        NV_RAM_REF ram = NvRamGetIndex(handle);
        NvWriteRamIndexAttributes(ram, attributes);
        result = TPM_RC_SUCCESS;
    }
    else
    {
        result = NvWriteNvIndexAttributes(locator, attributes);
    }
    return result;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

TPM_RC
NvWriteIndexAuth(
    NV_REF locator,              // IN: location of the index
    TPM2B_AUTH *authValue            // IN: the authValue to write
)
{
    TPM_RC result;
    if(locator == s_cachedNvRef)
    {
        MemoryCopy2B(&s_cachedNvIndex.authValue.b, &authValue->b,
                     sizeof(s_cachedNvIndex.authValue.t.buffer));
    }
    result = NvConditionallyWrite(
                 locator + offsetof(NV_INDEX, authValue),
                 sizeof(UINT16) + authValue->t.size,
                 authValue);
    return result;
}
NV_INDEX *
NvGetIndexInfo(
    TPM_HANDLE nvHandle,             // IN: the index handle
    NV_REF *locator              // OUT: location of the index
)
{
    if(s_cachedNvIndex.publicArea.nvIndex != nvHandle)
    {
        s_cachedNvIndex.publicArea.nvIndex = TPM_RH_UNASSIGNED;
        s_cachedNvRamRef = 0;
        s_cachedNvRef = NvFindHandle(nvHandle);
        if(s_cachedNvRef == 0)
            return NULL;
        NvReadNvIndexInfo(s_cachedNvRef, &s_cachedNvIndex);
        if(IsNv_TPMA_NV_ORDERLY(s_cachedNvIndex.publicArea.attributes))
        {
            s_cachedNvRamRef = NvRamGetIndex(nvHandle);
            s_cachedNvIndex.publicArea.attributes =
                NvReadRamIndexAttributes(s_cachedNvRamRef);
        }
    }
    if(locator != NULL)
        *locator = s_cachedNvRef;
    return &s_cachedNvIndex;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

TPM_RC
NvWriteIndexData(
    NV_INDEX *nvIndex,                  // IN: the description of the index
    UINT32 offset,                   // IN: offset of NV data
    UINT32 size,                     // IN: size of NV data
    void *data                      // IN: data buffer
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    pAssert(nvIndex != NULL);
    // Make sure that this is dealing with the 'default' index.
    // Note: it is tempting to change the calling sequence so that the 'default' is
    // presumed.
    pAssert(nvIndex->publicArea.nvIndex == s_cachedNvIndex.publicArea.nvIndex);
    // Validate that write falls within range of the index
    pAssert(offset <= nvIndex->publicArea.dataSize
            && size <= (nvIndex->publicArea.dataSize - offset));
    // Update TPMA_NV_WRITTEN bit if necessary
    if(!IsNv_TPMA_NV_WRITTEN(nvIndex->publicArea.attributes))
    {
        // Update the in memory version of the attributes
        nvIndex->publicArea.attributes.TPMA_NV_WRITTEN = SET;
        // If this is not orderly, then update the NV version of
        // the attributes
        if(!IsNv_TPMA_NV_ORDERLY(nvIndex->publicArea.attributes))
        {
            result = NvWriteNvIndexAttributes(s_cachedNvRef,
                                              nvIndex->publicArea.attributes);
            if(result != TPM_RC_SUCCESS)
                return result;
            // If this is a partial write of an ordinary index, clear the whole
            // index.
            if(IsNvOrdinaryIndex(nvIndex->publicArea.attributes)
                    && (nvIndex->publicArea.dataSize > size))
                _plat__NvMemoryClear(s_cachedNvRef + sizeof(NV_INDEX),
                                     nvIndex->publicArea.dataSize);
        }
        else
        {
            // This is orderly so update the RAM version
            MemoryCopy(s_cachedNvRamRef + offsetof(NV_RAM_HEADER, attributes),
                       &nvIndex->publicArea.attributes, sizeof(TPMA_NV));
            // If setting WRITTEN for an orderly counter, make sure that the
            // state saved version of the counter is saved
            if(IsNvCounterIndex(nvIndex->publicArea.attributes))
                SET_NV_UPDATE(UT_ORDERLY);
            // If setting the written attribute on an ordinary index, make sure that
            // the data is all cleared out in case there is a partial write. This
            // is only necessary for ordinary indices because all of the other types
            // are always written in total.
            else if(IsNvOrdinaryIndex(nvIndex->publicArea.attributes))
                MemorySet(s_cachedNvRamRef + sizeof(NV_RAM_HEADER),
                          0, nvIndex->publicArea.dataSize);
        }
    }
    // If this is orderly data, write it to RAM
    if(IsNv_TPMA_NV_ORDERLY(nvIndex->publicArea.attributes))
    {
        // Note: if this is the first write to a counter, the code above will queue
        // the write to NV of the RAM data in order to update TPMA_NV_WRITTEN. In
        // process of doing that write, it will also write the initial counter value
        // Update RAM
        MemoryCopy(s_cachedNvRamRef + sizeof(NV_RAM_HEADER) + offset, data, size);
        // And indicate that the TPM is no longer orderly
        g_clearOrderly = TRUE;
    }
    else
    {
        // Offset into the index to the first byte of the data to be written to NV
        result = NvConditionallyWrite(s_cachedNvRef + sizeof(NV_INDEX) + offset,
                                      size, data);
    }
    return result;
}
TPM_RC
NvWriteUINT64Data(
    NV_INDEX *nvIndex,                     // IN: the description of the index
    UINT64 intValue                  // IN: the value to write
)
{
    BYTE bytes[8];
    UINT64_TO_BYTE_ARRAY(intValue, bytes);
    return NvWriteIndexData(nvIndex, 0, 8, &bytes);
}
TPM2B_NAME *
NvGetIndexName(
    NV_INDEX *nvIndex,                     // IN: the index over which the name is to be
    // computed
    TPM2B_NAME *name                         // OUT: name of the index
)
{
    UINT16 dataSize, digestSize;
    BYTE marshalBuffer[sizeof(TPMS_NV_PUBLIC)];
    BYTE *buffer;
    HASH_STATE hashState;
    // Marshal public area
    buffer = marshalBuffer;
    dataSize = TPMS_NV_PUBLIC_Marshal(&nvIndex->publicArea, &buffer, NULL);
    // hash public area
    digestSize = CryptHashStart(&hashState, nvIndex->publicArea.nameAlg);
    CryptDigestUpdate(&hashState, dataSize, marshalBuffer);
    // Complete digest leaving room for the nameAlg
    CryptHashEnd(&hashState, digestSize, &name->b.buffer[2]);
    // Include the nameAlg
    UINT16_TO_BYTE_ARRAY(nvIndex->publicArea.nameAlg, name->b.buffer);
    name->t.size = digestSize + 2;
    return name;
}
TPM2B_NAME *
NvGetNameByIndexHandle(
    TPMI_RH_NV_INDEX handle,                    // IN: handle of the index
    TPM2B_NAME *name                        // OUT: name of the index
)
{
    NV_INDEX *nvIndex = NvGetIndexInfo(handle, NULL);
    return NvGetIndexName(nvIndex, name);
}

// E r
// M e
// TPM_RC_NV_SPACE

TPM_RC
NvDefineIndex(
    TPMS_NV_PUBLIC *publicArea,             // IN: A template for an area to create.
    TPM2B_AUTH *authValue               // IN: The initial authorization value
)
{
    // The buffer to be written to NV memory
    NV_INDEX nvIndex;                         // the index data
    UINT16 entrySize;                       // size of entry
    TPM_RC result;
    entrySize = sizeof(NV_INDEX);
    // only allocate data space for Indices that are going to be written to NV.
    // Orderly indices don't need space.
    if(!IsNv_TPMA_NV_ORDERLY(publicArea->attributes))
        entrySize += publicArea->dataSize;
    // Check if we have enough space to create the NV Index
    // In this implementation, the only resource limitation is the available NV
    // space (and possibly RAM space.) Other implementation may have other
    // limitation on counter or on NV slots
    if(!NvTestSpace(entrySize, TRUE, IsNvCounterIndex(publicArea->attributes)))
        return TPM_RC_NV_SPACE;
    // if the index to be defined is RAM backed, check RAM space availability
    // as well
    if(IsNv_TPMA_NV_ORDERLY(publicArea->attributes)
            && !NvRamTestSpaceIndex(publicArea->dataSize))
        return TPM_RC_NV_SPACE;
    // Copy input value to nvBuffer
    nvIndex.publicArea = *publicArea;
    // Copy the authValue
    nvIndex.authValue = *authValue;
    // Add index to NV memory
    result = NvAdd(entrySize, sizeof(NV_INDEX), TPM_RH_UNASSIGNED, (BYTE *)&nvIndex);
    if(result == TPM_RC_SUCCESS)
    {
        // If the data of NV Index is RAM backed, add the data area in RAM as well
        if(IsNv_TPMA_NV_ORDERLY(publicArea->attributes))
            NvAddRAM(publicArea);
    }
    return result;
}

// E r
// M e
// TPM_RC_NV_HANDLE
// TPM_RC_NV_SPACE

TPM_RC
NvAddEvictObject(
    TPMI_DH_OBJECT evictHandle,                // IN: new evict handle
    OBJECT *object                        // IN: object to be added
)
{
    TPM_HANDLE temp = object->evictHandle;
    TPM_RC result;
    // Check if we have enough space to add the evict object
    // An evict object needs 8 bytes in index table + sizeof OBJECT
    // In this implementation, the only resource limitation is the available NV
    // space. Other implementation may have other limitation on evict object
    // handle space
    if(!NvTestSpace(sizeof(OBJECT) + sizeof(TPM_HANDLE), FALSE, FALSE))
        return TPM_RC_NV_SPACE;
    // Set evict attribute and handle
    object->attributes.evict = SET;
    object->evictHandle = evictHandle;
    // Now put this in NV
    result = NvAdd(sizeof(OBJECT), sizeof(OBJECT), evictHandle, (BYTE *)object);
    // Put things back the way they were
    object->attributes.evict = CLEAR;
    object->evictHandle = temp;
    return result;
}

// E r
// M e
// TPM_RC_NV_UNAVAILABLE
// TPM_RC_NV_RATE

TPM_RC
NvDeleteIndex(
    NV_INDEX *nvIndex,            // IN: an in RAM index descriptor
    NV_REF entityAddr        // IN: location in NV
)
{
    TPM_RC result;
    if(nvIndex != NULL)
    {
        // Whenever a counter is deleted, make sure that the MaxCounter value is
        // updated to reflect the value
        if(IsNvCounterIndex(nvIndex->publicArea.attributes)
                && IsNv_TPMA_NV_WRITTEN(nvIndex->publicArea.attributes))
            NvUpdateMaxCount(NvGetUINT64Data(nvIndex, entityAddr));
        result = NvDelete(entityAddr);
        if(result != TPM_RC_SUCCESS)
            return result;
        // If the NV Index is RAM back, delete the RAM data as well
        if(IsNv_TPMA_NV_ORDERLY(nvIndex->publicArea.attributes))
            NvDeleteRAM(nvIndex->publicArea.nvIndex);
        NvIndexCacheInit();
    }
    return TPM_RC_SUCCESS;
}
TPM_RC
NvDeleteEvict(
    TPM_HANDLE handle            // IN: handle of entity to be deleted
)
{
    NV_REF entityAddr = NvFindEvict(handle, NULL);            // pointer to entity
    TPM_RC result = TPM_RC_SUCCESS;
    if(entityAddr != 0)
        result = NvDelete(entityAddr);
    return result;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

TPM_RC
NvFlushHierarchy(
    TPMI_RH_HIERARCHY hierarchy            // IN: hierarchy to be flushed.
)
{
    NV_REF iter = NV_REF_INIT;
    NV_REF currentAddr;
    TPM_HANDLE entityHandle;
    TPM_RC result = TPM_RC_SUCCESS;
    while((currentAddr = NvNext(&iter, &entityHandle)) != 0)
    {
        if(HandleGetType(entityHandle) == TPM_HT_NV_INDEX)
        {
            NV_INDEX nvIndex;
            // If flush endorsement or platform hierarchy, no NV Index would be
            // flushed
            if(hierarchy == TPM_RH_ENDORSEMENT || hierarchy == TPM_RH_PLATFORM)
                continue;
            // Get the index information
            NvReadNvIndexInfo(currentAddr, &nvIndex);
            // For storage hierarchy, flush OwnerCreated index
            if(!IsNv_TPMA_NV_PLATFORMCREATE(nvIndex.publicArea.attributes))
            {
                // Delete the index (including RAM for orderly)
                result = NvDeleteIndex(&nvIndex, currentAddr);
                if(result != TPM_RC_SUCCESS)
                    break;
                // Re-iterate from beginning after a delete
                iter = NV_REF_INIT;
            }
        }
        else if(HandleGetType(entityHandle) == TPM_HT_PERSISTENT)
        {
            OBJECT_ATTRIBUTES attributes;
            NvRead(&attributes,
                   (UINT32)(currentAddr
                            + sizeof(TPM_HANDLE)
                            + offsetof(OBJECT, attributes)),
                   sizeof(OBJECT_ATTRIBUTES));
            // If the evict object belongs to the hierarchy to be flushed
            if((hierarchy == TPM_RH_PLATFORM && attributes.ppsHierarchy == SET)
                    || (hierarchy == TPM_RH_OWNER && attributes.spsHierarchy == SET)
                    || (hierarchy == TPM_RH_ENDORSEMENT
                        && attributes.epsHierarchy == SET))
            {
                // Delete the evict object
                result = NvDelete(currentAddr);
                if(result != TPM_RC_SUCCESS)
                    break;
                // Re-iterate from beginning after a delete
                iter = NV_REF_INIT;
            }
        }
        else
        {
            FAIL(FATAL_ERROR_INTERNAL);
        }
    }
    return result;
}

// E r
// M e
// TPM_RC_NV_RATE
// TPM_RC_NV_UNAVAILABLE

TPM_RC
NvSetGlobalLock(
    void
)
{
    NV_REF iter = NV_REF_INIT;
    NV_RAM_REF ramIter = NV_RAM_REF_INIT;
    NV_REF currentAddr;
    NV_RAM_REF currentRamAddr;
    TPM_RC result = TPM_RC_SUCCESS;
    // Check all normal Indices
    while((currentAddr = NvNextIndex(NULL, &iter)) != 0)
    {
        TPMA_NV attributes = NvReadNvIndexAttributes(currentAddr);
        // See if it should be locked
        if(!IsNv_TPMA_NV_ORDERLY(attributes)
                && IsNv_TPMA_NV_GLOBALLOCK(attributes))
        {
            attributes.TPMA_NV_WRITELOCKED = SET;
            result = NvWriteNvIndexAttributes(currentAddr, attributes);
            if(result != TPM_RC_SUCCESS)
                return result;
        }
    }
    // Now search all the orderly attributes
    while((currentRamAddr = NvRamNext(&ramIter, NULL)) != 0)
    {
        // See if it should be locked
        TPMA_NV attributes = NvReadRamIndexAttributes(currentRamAddr);
        if(IsNv_TPMA_NV_GLOBALLOCK(attributes))
        {
            attributes.TPMA_NV_WRITELOCKED = SET;
            NvWriteRamIndexAttributes(currentRamAddr, attributes);
        }
    }
    return result;
}
static void
InsertSort(
    TPML_HANDLE *handleList,               // IN/OUT: sorted handle list
    UINT32 count,                    // IN: maximum count in the handle list
    TPM_HANDLE entityHandle              // IN: handle to be inserted
)
{
    UINT32 i, j;
    UINT32 originalCount;
    // For a corner case that the maximum count is 0, do nothing
    if(count == 0)
        return;
    // For empty list, add the handle at the beginning and return
    if(handleList->count == 0)
    {
        handleList->handle[0] = entityHandle;
        handleList->count++;
        return;
    }
    // Check if the maximum of the list has been reached
    originalCount = handleList->count;
    if(originalCount < count)
        handleList->count++;
    // Insert the handle to the list
    for(i = 0; i < originalCount; i++)
    {
        if(handleList->handle[i] > entityHandle)
        {
            for(j = handleList->count - 1; j > i; j--)
            {
                handleList->handle[j] = handleList->handle[j - 1];
            }
            break;
        }
    }
    // If a slot was found, insert the handle in this position
    if(i < originalCount || handleList->count > originalCount)
        handleList->handle[i] = entityHandle;
    return;
}
TPMI_YES_NO
NvCapGetPersistent(
    TPMI_DH_OBJECT handle,                          // IN: start handle
    UINT32 count,                           // IN: maximum number of returned handles
    TPML_HANDLE *handleList                       // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    NV_REF iter = NV_REF_INIT;
    NV_REF currentAddr;
    TPM_HANDLE entityHandle;
    pAssert(HandleGetType(handle) == TPM_HT_PERSISTENT);
    // Initialize output handle list
    handleList->count = 0;
    // The maximum count of handles we may return is MAX_CAP_HANDLES
    if(count > MAX_CAP_HANDLES) count = MAX_CAP_HANDLES;
    while((currentAddr = NvNextEvict(&entityHandle, &iter)) != 0)
    {
        // Ignore persistent handles that have values less than the input handle
        if(entityHandle < handle)
            continue;
        // if the handles in the list have reached the requested count, and there
        // are still handles need to be inserted, indicate that there are more.
        if(handleList->count == count)
            more = YES;
        // A handle with a value larger than start handle is a candidate
        // for return. Insert sort it to the return list. Insert sort algorithm
        // is chosen here for simplicity based on the assumption that the total
        // number of NV Indices is small. For an implementation that may allow
        // large number of NV Indices, a more efficient sorting algorithm may be
        // used here.
        InsertSort(handleList, count, entityHandle);
    }
    return more;
}
TPMI_YES_NO
NvCapGetIndex(
    TPMI_DH_OBJECT handle,                     // IN: start handle
    UINT32 count,                      // IN: max number of returned handles
    TPML_HANDLE *handleList                    // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    NV_REF iter = NV_REF_INIT;
    NV_REF currentAddr;
    TPM_HANDLE nvHandle;
    pAssert(HandleGetType(handle) == TPM_HT_NV_INDEX);
    // Initialize output handle list
    handleList->count = 0;
    // The maximum count of handles we may return is MAX_CAP_HANDLES
    if(count > MAX_CAP_HANDLES) count = MAX_CAP_HANDLES;
    while((currentAddr = NvNextIndex(&nvHandle, &iter)) != 0)
    {
        // Ignore index handles that have values less than the 'handle'
        if(nvHandle < handle)
            continue;
        // if the count of handles in the list has reached the requested count,
        // and there are still handles to report, set more.
        if(handleList->count == count)
            more = YES;
        // A handle with a value larger than start handle is a candidate
        // for return. Insert sort it to the return list. Insert sort algorithm
        // is chosen here for simplicity based on the assumption that the total
        // number of NV Indices is small. For an implementation that may allow
        // large number of NV Indices, a more efficient sorting algorithm may be
        // used here.
        InsertSort(handleList, count, nvHandle);
    }
    return more;
}
UINT32
NvCapGetIndexNumber(
    void
)
{
    UINT32 num = 0;
    NV_REF iter = NV_REF_INIT;
    while(NvNextIndex(NULL, &iter) != 0)
        num++;
    return num;
}
UINT32
NvCapGetPersistentNumber(
    void
)
{
    UINT32 num = 0;
    NV_REF iter = NV_REF_INIT;
    TPM_HANDLE handle;
    while(NvNextEvict(&handle, &iter) != 0)
        num++;
    return num;
}
UINT32
NvCapGetPersistentAvail(
    void
)
{
    UINT32 availNVSpace;
    UINT32 counterNum = NvCapGetCounterNumber();
    UINT32 reserved = sizeof(NV_LIST_TERMINATOR);
    // Get the available space in NV storage
    availNVSpace = NvGetFreeBytes();
    if(counterNum < MIN_COUNTER_INDICES)
    {
        // Some space has to be reserved for counter objects.
        reserved += (MIN_COUNTER_INDICES - counterNum) * NV_INDEX_COUNTER_SIZE;
        if(reserved > availNVSpace)
            availNVSpace = 0;
        else
            availNVSpace -= reserved;
    }
    return availNVSpace      / NV_EVICT_OBJECT_SIZE;
}
UINT32
NvCapGetCounterNumber(
    void
)
{
    NV_REF iter = NV_REF_INIT;
    NV_REF currentAddr;
    UINT32 num = 0;
    while((currentAddr = NvNextIndex(NULL, &iter)) != 0)
    {
        TPMA_NV attributes = NvReadNvIndexAttributes(currentAddr);
        if(IsNvCounterIndex(attributes))
            num++;
    }
    return num;
}
static TPMA_NV
NvSetStartupAttributes(
    TPMA_NV attributes,                          // IN: attributes to change
    STARTUP_TYPE type                       // IN: start up type
)
{
    // Clear read lock
    attributes.TPMA_NV_READLOCKED = CLEAR;
    // Will change a non counter index to the unwritten state if:
    // a) TPMA_NV_CLEAR_STCLEAR is SET
    // b) orderly and TPM Reset
    if(!IsNvCounterIndex(attributes))
    {
        if(IsNv_TPMA_NV_CLEAR_STCLEAR(attributes)
                || (IsNv_TPMA_NV_ORDERLY(attributes) && (type == SU_RESET)))
            attributes.TPMA_NV_WRITTEN = CLEAR;
    }
    // Unlock any index that is not written or that does not have
    // TPMA_NV_WRITEDEFINE SET.
    if(!IsNv_TPMA_NV_WRITTEN(attributes) || !IsNv_TPMA_NV_WRITEDEFINE(attributes))
        attributes.TPMA_NV_WRITELOCKED = CLEAR;
    return attributes;
}
void
NvEntityStartup(
    STARTUP_TYPE type                       // IN: start up type
)
{
    NV_REF iter = NV_REF_INIT;
    NV_RAM_REF ramIter = NV_RAM_REF_INIT;
    NV_REF currentAddr;                          // offset points to the current entity
    NV_RAM_REF currentRamAddr;
    TPM_HANDLE nvHandle;
    TPMA_NV attributes;
    // Restore RAM index data
    NvRead(s_indexOrderlyRam, NV_INDEX_RAM_DATA, sizeof(s_indexOrderlyRam));
    // Initialize the max NV counter value
    NvSetMaxCount(NvGetMaxCount());
    // If recovering from state save, do nothing else
    if(type == SU_RESUME)
        return;
    // Iterate all the NV Index to clear the locks
    while((currentAddr = NvNextIndex(&nvHandle, &iter)) != 0)
    {
        attributes = NvReadNvIndexAttributes(currentAddr);
        // If this is an orderly index, defer processing until loop below
        if(IsNv_TPMA_NV_ORDERLY(attributes))
            continue;
        // Set the attributes appropriate for this startup type
        attributes = NvSetStartupAttributes(attributes, type);
        NvWriteNvIndexAttributes(currentAddr, attributes);
    }
    // Iterate all the orderly indices to clear the locks and initialize counters
    while((currentRamAddr = NvRamNext(&ramIter, NULL)) != 0)
    {
        attributes = NvReadRamIndexAttributes(currentRamAddr);
        attributes = NvSetStartupAttributes(attributes, type);
        // update attributes in RAM
        NvWriteRamIndexAttributes(currentRamAddr, attributes);
        // Set the lower bits in an orderly counter to 1 for a non-orderly startup
        if(IsNvCounterIndex(attributes)
                && (g_prevOrderlyState == SU_NONE_VALUE))
        {
            UINT64 counter;
            // Read the counter value last saved to NV.
            counter = BYTE_ARRAY_TO_UINT64(currentRamAddr + sizeof(NV_RAM_HEADER));
            // Set the lower bits of counter to 1's
            counter |= MAX_ORDERLY_COUNT;
            // Write back to RAM
            // NOTE: Do not want to force a write to NV here. The counter value will
            // stay in RAM until the next shutdown or rollover.
            UINT64_TO_BYTE_ARRAY(counter, currentRamAddr + sizeof(NV_RAM_HEADER));
        }
    }
    return;
}
UINT32
NvCapGetCounterAvail(
    void
)
{
    UINT32 availNVSpace;
    UINT32 availRAMSpace;
    UINT32 persistentNum = NvCapGetPersistentNumber();
    UINT32 reserved = sizeof(NV_LIST_TERMINATOR);
    // Get the available space in NV storage
    availNVSpace = NvGetFreeBytes();
    if(persistentNum < MIN_EVICT_OBJECTS)
    {
        // Some space has to be reserved for evict object. Adjust availNVSpace.
        reserved += (MIN_EVICT_OBJECTS - persistentNum) * NV_EVICT_OBJECT_SIZE;
        if(reserved > availNVSpace)
            availNVSpace = 0;
        else
            availNVSpace -= reserved;
    }
    // Compute the available space in RAM
    availRAMSpace = RAM_ORDERLY_END - NvRamGetEnd();
    // Return the min of counter number in NV and in RAM
    if(availNVSpace          / NV_INDEX_COUNTER_SIZE
            > availRAMSpace         / NV_RAM_INDEX_COUNTER_SIZE)
        return availRAMSpace                / NV_RAM_INDEX_COUNTER_SIZE;
    else
        return availNVSpace             / NV_INDEX_COUNTER_SIZE;
}
NV_REF
NvFindHandle(
    TPM_HANDLE handle
)
{
    NV_REF addr;
    NV_REF iter = NV_REF_INIT;
    TPM_HANDLE nextHandle;
    while((addr = NvNext(&iter, &nextHandle)) != 0)
    {
        if(nextHandle == handle)
            break;
    }
    return addr;
}
UINT64
NvReadMaxCount(
    void
)
{
    return s_maxCounter;
}
void
NvUpdateMaxCount(
    UINT64 count
)
{
    if(count > s_maxCounter)
        s_maxCounter = count;
}
void
NvSetMaxCount(
    UINT64 value
)
{
    s_maxCounter = value;
}
UINT64
NvGetMaxCount(
    void
)
{
    NV_REF iter = NV_REF_INIT;
    NV_REF currentAddr;
    UINT64 maxCount;
    // Find the end of list marker and initialize the NV Max Counter value.
    while((currentAddr = NvNext(&iter, NULL )) != 0);
    // 'iter' should be pointing at the end of list marker so read in the current
    // value of the s_maxCounter.
    NvRead(&maxCount, iter + sizeof(UINT32), sizeof(maxCount));
    return maxCount;
}
