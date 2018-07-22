#include <spos/activesecurenode.h>
#include <checkpoints.h>
#include <governance/governance.h>
#include <validation.h>
#include <spos/securenode-sync.h>
#include <spos/securenode.h>
#include <spos/securenodeman.h>
#include <netfulfilledman.h>
#include <spork.h>
#include <ui_interface.h>
#include <util.h>

class CSecurenodeSync;
CSecurenodeSync securenodeSync;

void CSecurenodeSync::Fail()
{
    nTimeLastFailure = GetTime();
    nRequestedSecurenodeAssets = SECURENODE_SYNC_FAILED;
}

void CSecurenodeSync::Reset()
{
    nRequestedSecurenodeAssets = SECURENODE_SYNC_INITIAL;
    nRequestedSecurenodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastBumped = GetTime();
    nTimeLastFailure = 0;
}

void CSecurenodeSync::BumpAssetLastTime(std::string strFuncName)
{
    if(IsSynced() || IsFailed()) return;
    nTimeLastBumped = GetTime();
    LogPrint(BCLog::MNSYNC, "CSecurenodeSync::BumpAssetLastTime -- %s\n", strFuncName);
}

std::string CSecurenodeSync::GetAssetName()
{
    switch(nRequestedSecurenodeAssets)
    {
        case(SECURENODE_SYNC_INITIAL):      return "SECURENODE_SYNC_INITIAL";
        case(SECURENODE_SYNC_WAITING):      return "SECURENODE_SYNC_WAITING";
        case(SECURENODE_SYNC_LIST):         return "SECURENODE_SYNC_LIST";
        case(SECURENODE_SYNC_FAILED):       return "SECURENODE_SYNC_FAILED";
        case SECURENODE_SYNC_FINISHED:      return "SECURENODE_SYNC_FINISHED";
        default:                            return "UNKNOWN";
    }
}

void CSecurenodeSync::SwitchToNextAsset(CConnman& connman)
{
    switch(nRequestedSecurenodeAssets)
    {
        case(SECURENODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case(SECURENODE_SYNC_INITIAL):
            ClearFulfilledRequests(connman);
            nRequestedSecurenodeAssets = SECURENODE_SYNC_WAITING;
            LogPrintf("CSecurenodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(SECURENODE_SYNC_WAITING):
            ClearFulfilledRequests(connman);
            LogPrintf("CSecurenodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedSecurenodeAssets = SECURENODE_SYNC_LIST;
            LogPrintf("CSecurenodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case(SECURENODE_SYNC_LIST):
            LogPrintf("CSecurenodeSync::SwitchToNextAsset -- Completed %s in %llds\n", GetAssetName(), GetTime() - nTimeAssetSyncStarted);
            nRequestedSecurenodeAssets = SECURENODE_SYNC_FINISHED;
            uiInterface.NotifyAdditionalDataSyncProgressChanged(1);
            //try to activate our masternode if possible
            activeSecurenode.ManageState(connman);

            // TODO: Find out whether we can just use LOCK instead of:
            // TRY_LOCK(cs_vNodes, lockRecv);
            // if(lockRecv) { ... }

            connman.ForEachNode([](CNode* pnode) {
                netfulfilledman.AddFulfilledRequest(pnode->addr, "full-mrnsync");
            });
            LogPrintf("CSecurenodeSync::SwitchToNextAsset -- Sync has finished\n");

            break;
    }
    nRequestedSecurenodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    BumpAssetLastTime("CSecurenodeSync::SwitchToNextAsset");
}

std::string CSecurenodeSync::GetSyncStatus()
{
    switch (securenodeSync.nRequestedSecurenodeAssets) {
        case SECURENODE_SYNC_INITIAL:       return _("Synchroning blockchain...");
        case SECURENODE_SYNC_WAITING:       return _("Synchronization pending...");
        case SECURENODE_SYNC_LIST:          return _("Synchronizing masternodes...");
        case SECURENODE_SYNC_FAILED:        return _("Synchronization failed");
        case SECURENODE_SYNC_FINISHED:      return _("Synchronization finished");
        default:                            return "";
    }
}

void CSecurenodeSync::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == NetMsgType::SECURESYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if(IsSynced() || IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        LogPrint(BCLog::MNSYNC, "SECURESYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->GetId());
    }
}

void CSecurenodeSync::ClearFulfilledRequests(CConnman& connman)
{
    // TODO: Find out whether we can just use LOCK instead of:
    // TRY_LOCK(cs_vNodes, lockRecv);
    // if(!lockRecv) return;

    connman.ForEachNode([](CNode* pnode) {
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "securenode-list-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "full-mrnsync");
    });
}

void CSecurenodeSync::ProcessTick(CConnman& connman)
{
    static int nTick = 0;
    if(nTick++ % SECURENODE_SYNC_TICK_SECONDS != 0) return;

    // reset the sync process if the last call to this function was more than 60 minutes ago (client was in sleep mode)
    static int64_t nTimeLastProcess = GetTime();
    if(GetTime() - nTimeLastProcess > 60*60) {
        LogPrintf("CSecurenodeSync::HasSyncFailures -- WARNING: no actions for too long, restarting sync...\n");
        Reset();
        SwitchToNextAsset(connman);
        nTimeLastProcess = GetTime();
        return;
    }
    nTimeLastProcess = GetTime();

    // reset sync status in case of any other sync failure
    if(IsFailed()) {
        if(nTimeLastFailure + (1*60) < GetTime()) { // 1 minute cooldown after failed sync
            LogPrintf("CSecurenodeSync::HasSyncFailures -- WARNING: failed to sync, trying again...\n");
            Reset();
            SwitchToNextAsset(connman);
        }
        return;
    }

    // gradually request the rest of the votes after sync finished
    if(IsSynced()) {
        std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();
        governance.RequestGovernanceObjectVotes(vNodesCopy, connman);
        connman.ReleaseNodeVector(vNodesCopy);
        return;
    }

    // Calculate "progress" for LOG reporting / GUI notification
    double nSyncProgress = double(nRequestedSecurenodeAttempt + (nRequestedSecurenodeAssets - 1) * 8) / (8*4);
    LogPrint(BCLog::SECURENODE, "CSecurenodeSync::ProcessTick -- nTick %d nRequestedSecurenodeAssets %d nRequestedSecurenodeAttempt %d nSyncProgress %f\n", nTick, nRequestedSecurenodeAssets, nRequestedSecurenodeAttempt, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(nSyncProgress);

    std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();

    for(CNode* pnode : vNodesCopy)
    {
        // Don't try to sync any data from outbound "securenode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "securenode" connection
        // initiated from another node, so skip it too.
        if(pnode->fSecurenode || (fSecureNode && pnode->fInbound)) continue;

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if(netfulfilledman.HasFulfilledRequest(pnode->addr, "full-mrnsync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                LogPrintf("CSecurenodeSync::ProcessTick -- disconnecting from recently synced peer %d\n", pnode->GetId());
                continue;
            }

            // INITIAL TIMEOUT

            if(nRequestedSecurenodeAssets == SECURENODE_SYNC_WAITING) {
                if(GetTime() - nTimeLastBumped > SECURENODE_SYNC_TIMEOUT_SECONDS) {
                    // At this point we know that:
                    // a) there are peers (because we are looping on at least one of them);
                    // b) we waited for at least SECURENODE_SYNC_TIMEOUT_SECONDS since we reached
                    //    the headers tip the last time (i.e. since we switched from
                    //     SECURENODE_SYNC_INITIAL to SECURENODE_SYNC_WAITING and bumped time);
                    // c) there were no blocks (UpdatedBlockTip, NotifyHeaderTip) or headers (AcceptedBlockHeader)
                    //    for at least SECURENODE_SYNC_TIMEOUT_SECONDS.
                    // We must be at the tip already, let's move to the next asset.
                    SwitchToNextAsset(connman);
                }
            }

            // MNLIST : SYNC SECURENODE LIST FROM OTHER CONNECTED CLIENTS

            if(nRequestedSecurenodeAssets == SECURENODE_SYNC_LIST) {
                LogPrint(BCLog::SECURENODE, "CSecurenodeSync::ProcessTick -- nTick %d nRequestedSecurenodeAssets %d nTimeLastBumped %lld GetTime() %lld diff %lld\n", nTick, nRequestedSecurenodeAssets, nTimeLastBumped, GetTime(), GetTime() - nTimeLastBumped);
                // check for timeout first
                if(GetTime() - nTimeLastBumped > SECURENODE_SYNC_TIMEOUT_SECONDS) {
                    LogPrint(BCLog::SECURENODE, "CSecurenodeSync::ProcessTick -- nTick %d nRequestedSecurenodeAssets %d -- timeout\n", nTick, nRequestedSecurenodeAssets);
                    if (nRequestedSecurenodeAttempt == 0) {
                        LogPrintf("CSecurenodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without masternode list, fail here and try later
                        Fail();
                        connman.ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset(connman);
                    connman.ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if(netfulfilledman.HasFulfilledRequest(pnode->addr, "securenode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "securenode-list-sync");

//                if (pnode->nVersion < PROTOCOL_VERSION) continue;
                nRequestedSecurenodeAttempt++;

                securenodeman.DsegUpdate(pnode, connman);

                connman.ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }
        }
    }
    // looped through all nodes, release them
    connman.ReleaseNodeVector(vNodesCopy);
}


void CSecurenodeSync::AcceptedBlockHeader(const CBlockIndex *pindexNew)
{
    LogPrint(BCLog::MNSYNC, "CSecurenodeSync::AcceptedBlockHeader -- pindexNew->nHeight: %d\n", pindexNew->nHeight);

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block header arrives while we are still syncing blockchain
        BumpAssetLastTime("CSecurenodeSync::AcceptedBlockHeader");
    }
}

void CSecurenodeSync::NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint(BCLog::MNSYNC, "CSecurenodeSync::NotifyHeaderTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CSecurenodeSync::NotifyHeaderTip");
    }
}

void CSecurenodeSync::UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman)
{
    LogPrint(BCLog::MNSYNC, "CSecurenodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d fInitialDownload=%d\n", pindexNew->nHeight, fInitialDownload);

    if (IsFailed() || IsSynced() || !pindexBestHeader)
        return;

    if (!IsBlockchainSynced()) {
        // Postpone timeout each time new block arrives while we are still syncing blockchain
        BumpAssetLastTime("CSecurenodeSync::UpdatedBlockTip");
    }

    if (fInitialDownload) {
        // switched too early
        if (IsBlockchainSynced()) {
            Reset();
        }

        // no need to check any further while still in IBD mode
        return;
    }

    // Note: since we sync headers first, it should be ok to use this
    static bool fReachedBestHeader = false;
    bool fReachedBestHeaderNew = pindexNew->GetBlockHash() == pindexBestHeader->GetBlockHash();

    if (fReachedBestHeader && !fReachedBestHeaderNew) {
        // Switching from true to false means that we previousely stuck syncing headers for some reason,
        // probably initial timeout was not enough,
        // because there is no way we can update tip not having best header
        Reset();
        fReachedBestHeader = false;
        return;
    }

    fReachedBestHeader = fReachedBestHeaderNew;

    LogPrint(BCLog::MNSYNC, "CSecurenodeSync::UpdatedBlockTip -- pindexNew->nHeight: %d pindexBestHeader->nHeight: %d fInitialDownload=%d fReachedBestHeader=%d\n",
                pindexNew->nHeight, pindexBestHeader->nHeight, fInitialDownload, fReachedBestHeader);

    if (!IsBlockchainSynced() && fReachedBestHeader) {
        // Reached best header while being in initial mode.
        // We must be at the tip already, let's move to the next asset.
        SwitchToNextAsset(connman);
    }
}
