#ifndef SECURENODE_SYNC_H
#define SECURENODE_SYNC_H

#include <chain.h>
#include <net.h>

class CSecurenodeSync;

static const int SECURENODE_SYNC_FAILED          = -1;
static const int SECURENODE_SYNC_INITIAL         = 0; // sync just started, was reset recently or still in IDB
static const int SECURENODE_SYNC_WAITING         = 1; // waiting after initial to see if we can get more headers/blocks
static const int SECURENODE_SYNC_LIST            = 2;
static const int SECURENODE_SYNC_FINISHED        = 999;

static const int SECURENODE_SYNC_TICK_SECONDS    = 6;
static const int SECURENODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2.5 minutes so 30 seconds should be fine

static const int SECURENODE_SYNC_ENOUGH_PEERS    = 6;

extern CSecurenodeSync securenodeSync;

//
// CSecurenodeSync : Sync masternode assets in stages
//

class CSecurenodeSync
{
private:
    // Keep track of current asset
    int nRequestedSecurenodeAssets;
    // Count peers we've requested the asset from
    int nRequestedSecurenodeAttempt;

    // Time when current masternode asset sync started
    int64_t nTimeAssetSyncStarted;
    // ... last bumped
    int64_t nTimeLastBumped;
    // ... or failed
    int64_t nTimeLastFailure;

    void Fail();
    void ClearFulfilledRequests(CConnman& connman);

public:
    CSecurenodeSync() { Reset(); }


    void SendGovernanceSyncRequest(CNode* pnode, CConnman& connman);

    bool IsFailed() { return nRequestedSecurenodeAssets == SECURENODE_SYNC_FAILED; }
    bool IsBlockchainSynced() { return nRequestedSecurenodeAssets > SECURENODE_SYNC_WAITING; }
    bool IsSecurenodeListSynced() { return nRequestedSecurenodeAssets > SECURENODE_SYNC_LIST; }
    bool IsSynced() { return nRequestedSecurenodeAssets == SECURENODE_SYNC_FINISHED; }

    int GetAssetID() { return nRequestedSecurenodeAssets; }
    int GetAttempt() { return nRequestedSecurenodeAttempt; }
    void BumpAssetLastTime(std::string strFuncName);
    int64_t GetAssetStartTime() { return nTimeAssetSyncStarted; }
    std::string GetAssetName();
    std::string GetSyncStatus();

    void Reset();
    void SwitchToNextAsset(CConnman& connman);

    void ProcessMessage(CNode* pfrom, const std::string &strCommand, CDataStream& vRecv);
    void ProcessTick(CConnman& connman);

    void AcceptedBlockHeader(const CBlockIndex *pindexNew);
    void NotifyHeaderTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
    void UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload, CConnman& connman);
};

#endif
