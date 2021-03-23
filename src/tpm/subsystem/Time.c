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

// 8.10.1 Introduction
// This file contains the functions relating to the TPM's time functions including the
// interface to the
// implementation-specific time functions.
// 8.10.2 Includes
#include "Tpm.h"
#include "PlatformData.h"
void
TimePowerOn(
    void
)
{
    // If the timer was reset or stopped, we need a new epoch
    if(_plat__TimerWasReset())
    {
        g_timeNewEpochNeeded = TRUE;
        // If the timer was reset, need to reset the base time of the TPM. By
        // resetting to zero here, the TPM can capture the time that passed between
        // when the system timer was reset and when the first call is made to
        // _plat__TimeRead().
        g_time = 0;
        // And reset the DA timers
        DAInit();
    }
}
static void
TimeNewEpoch(
    void
)
{
#ifdef CLOCK_STOPS
    CryptRandomGenerate(sizeof(CLOCK_NONCE), (BYTE *)&g_timeEpoch);
#else
    // if the epoch is kept in NV, update it.
    gp.timeEpoch++;
    NV_SYNC_PERSISTENT(timeEpoch);
#endif
    g_timeNewEpochNeeded = FALSE;
    // Clean out any lingering state
    _plat__TimerWasStopped();
}
void
TimeStartup(
    STARTUP_TYPE type                  // IN: start up type
)
{
    NOT_REFERENCED(type);
    // If the previous cycle is orderly shut down, the value of the safe bit
    // the same as previously saved. Otherwise, it is not safe.
    if(!NV_IS_ORDERLY)
        go.clockSafe = NO;
    // Before Startup, the TPM will not do clock updates. At startup, need to
    // do a time update.
    TimeUpdate();
    return;
}

// M e
// TPM_RC_NV_RATE NV cannot be written because it is rate limiting
// TPM_RC_NV_UNAVAILABLE NV cannot be accessed

TPM_RC
TimeClockUpdate(
    UINT64 newTime
)
{
#define CLOCK_UPDATE_MASK ((1ULL << NV_CLOCK_UPDATE_INTERVAL)- 1)
    // Check to see if the update will cause a need for an nvClock update
    if((newTime | CLOCK_UPDATE_MASK) > (go.clock | CLOCK_UPDATE_MASK))
    {
        RETURN_IF_NV_IS_NOT_AVAILABLE;
        // Going to update the NV time state so SET the safe flag
        go.clockSafe = YES;
        // update the time
        go.clock = newTime;
        NvWrite(NV_ORDERLY_DATA, sizeof(go), &go);
    }
    else
        // No NV update needed so just update
        go.clock = newTime;
    return TPM_RC_SUCCESS;
}
void
TimeUpdate(
    void
)
{
    UINT64 elapsed;
//
    if(g_timeNewEpochNeeded)
        TimeNewEpoch();
    // Get the difference between this call and the last time we updated the tick
    // timer.
    elapsed = _plat__TimerRead() - g_time;
    g_time += elapsed;
    // Don't need to check the result because it has to be success because have
    // already checked that NV is available.
    TimeClockUpdate(go.clock + elapsed);
    // Call self healing logic for dictionary attack parameters
    DASelfHeal();
}
void
TimeUpdateToCurrent(
    void
)
{
    UINT64 elapsed;
//
    // Can't update time during the dark interval or when rate limiting so don't
    // make any modifications to the internal clock value
    if(!NV_IS_AVAILABLE)
        return;
    // Make sure that we consume the current _plat__TimerWasStopped() state.
    g_timeNewEpochNeeded |= _plat__TimerWasStopped();
    // If we need a new epoch but the TPM has not started, don't generate the new
    // epoch here because the crypto has not been initialized by TPM2_Startup().
    // Instead, just continue and let TPM2_Startup() processing create the
    // new epoch if needed.
    if(g_timeNewEpochNeeded && TPMIsStarted())
    {
        TimeNewEpoch();
    }
    // Get the difference between this call and the last time we updated the tick
    // timer.
    elapsed = _plat__TimerRead() - g_time;
    g_time += elapsed;
    // Don't need to check the result because it has to be success because have
    // already checked that NV is available.
    TimeClockUpdate(go.clock + elapsed);
    // Call self healing logic for dictionary attack parameters
    DASelfHeal();
    return;
}
void
TimeSetAdjustRate(
    TPM_CLOCK_ADJUST adjust                      // IN: adjust constant
)
{
    switch(adjust)
    {
    case TPM_CLOCK_COARSE_SLOWER:
        _plat__ClockAdjustRate(CLOCK_ADJUST_COARSE);
        break;
    case TPM_CLOCK_COARSE_FASTER:
        _plat__ClockAdjustRate(-CLOCK_ADJUST_COARSE);
        break;
    case TPM_CLOCK_MEDIUM_SLOWER:
        _plat__ClockAdjustRate(CLOCK_ADJUST_MEDIUM);
        break;
    case TPM_CLOCK_MEDIUM_FASTER:
        _plat__ClockAdjustRate(-CLOCK_ADJUST_MEDIUM);
        break;
    case TPM_CLOCK_FINE_SLOWER:
        _plat__ClockAdjustRate(CLOCK_ADJUST_FINE);
        break;
    case TPM_CLOCK_FINE_FASTER:
        _plat__ClockAdjustRate(-CLOCK_ADJUST_FINE);
        break;
    case TPM_CLOCK_NO_CHANGE:
        break;
    default:
        FAIL(FATAL_ERROR_INTERNAL);
        break;
    }
    return;
}
UINT16
TimeGetMarshaled(
    TIME_INFO *dataBuffer          // OUT: result buffer
)
{
    TPMS_TIME_INFO timeInfo;
    // Fill TPMS_TIME_INFO structure
    timeInfo.time = g_time;
    TimeFillInfo(&timeInfo.clockInfo);
    // Marshal TPMS_TIME_INFO to canonical form
    return TPMS_TIME_INFO_Marshal(&timeInfo, (BYTE **)&dataBuffer, NULL);
}
void
TimeFillInfo(
    TPMS_CLOCK_INFO *clockInfo
)
{
    clockInfo->clock = go.clock;
    clockInfo->resetCount = gp.resetCount;
    clockInfo->restartCount = gr.restartCount;
    // If NV is not available, clock stopped advancing and the value reported is
    // not "safe".
    if(NV_IS_AVAILABLE)
        clockInfo->safe = go.clockSafe;
    else
        clockInfo->safe = NO;
    return;
}
