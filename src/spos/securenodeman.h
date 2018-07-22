#ifndef SECURENODEMAN_H
#define SECURENODEMAN_H

#include <spos/securenode.h>
#include <sync.h>

using namespace std;

class CSecurenodeMan;
class CConnman;

extern CSecurenodeMan securenodeman;

class CSecurenodeMan
{
private:
    static const std::string SERIALIZATION_VERSION_STRING;

    static const int DSEG_UPDATE_SECONDS        = 1 * 30 * 60;

    static const int LAST_PAID_SCAN_BLOCKS      = 100;

    static const int MIN_POSE_PROTO_VERSION     = 70203;
    static const int MAX_POSE_CONNECTIONS       = 10;
    static const int MAX_POSE_RANK              = 10;
    static const int MAX_POSE_BLOCKS            = 10;

    static const int MNB_RECOVERY_QUORUM_TOTAL      = 10;
    static const int MNB_RECOVERY_QUORUM_REQUIRED   = 6;
    static const int MNB_RECOVERY_MAX_ASK_ENTRIES   = 10;
    static const int MNB_RECOVERY_WAIT_SECONDS      = 60;
    static const int MNB_RECOVERY_RETRY_SECONDS     = 1 * 60 * 60;


    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // Keep track of current block height
    int nCachedBlockHeight;

    // map to hold all MNs
    std::map<CPubKey, CSecurenode> mapSecurenodes;
    // who's asked for the Securenode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForSecurenodeList;
    // who we asked for the Securenode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForSecurenodeList;
    // which Securenodes we've asked for
    std::map<CPubKey, std::map<CNetAddr, int64_t> > mWeAskedForSecurenodeListEntry;
    // who we asked for the masternode verification
    std::map<CNetAddr, CSecurenodeVerification> mWeAskedForVerification;

    // these maps are used for masternode recovery from MASTERNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CSecurenodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    int64_t nLastWatchdogVoteTime;

    friend class CSecurenodeSync;
    /// Find an entry
    CSecurenode* Find(const CPubKey &pubKeySecurenode);
public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CSecurenodeBroadcast> > mapSeenSecurenodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CSecurenodePing> mapSeenSecurenodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CSecurenodeVerification> mapSeenSecurenodeVerification;
    // keep track of dsq count to prevent masternodes from gaming darksend queue
    int64_t nDsqCount;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING; 
            READWRITE(strVersion);
        }

        READWRITE(mapSecurenodes);
        READWRITE(mAskedUsForSecurenodeList);
        READWRITE(mWeAskedForSecurenodeList);
        READWRITE(mWeAskedForSecurenodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenSecurenodeBroadcast);
        READWRITE(mapSeenSecurenodePing);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CSecurenodeMan();

    /// Add an entry
    bool Add(CSecurenode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const CPubKey &pubKeySecurenode, CConnman& connman);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    bool PoSeBan(const CPubKey &pubKeySecurenode);

    /// Check all Securenodes
    void Check();

    /// Check all Securenodes and remove inactive
    void CheckAndRemove(CConnman& connman);
    /// This is dummy overload to be used for dumping/loading mncache.dat
    void CheckAndRemove() {}

    /// Clear Securenode vector
    void Clear();

    /// Count Securenodes filtered by nProtocolVersion.
    /// Securenode nProtocolVersion should match or be above the one specified in param here.
    int CountSecurenodes(int nProtocolVersion = -1) const;
    /// Count enabled Securenodes filtered by nProtocolVersion.
    /// Securenode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1) const;

    /// Count Securenodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode, CConnman& connman);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const CKeyID &pubKeyID, CSecurenode& masternodeRet);
    bool Get(const CPubKey &pubKeySecurenode, CSecurenode& securenodeRet);
    bool Has(const CPubKey &pubKeySecurenode);

    bool GetSecurenodeInfo(const CPubKey& pubKeySecurenode, securenode_info_t& mnInfoRet);
    bool GetSecurenodeInfo(const CKeyID& pubKeySecurenode, securenode_info_t& mnInfoRet);
    bool GetSecurenodeInfo(const CScript& payee, securenode_info_t& mnInfoRet);

    std::map<CPubKey, CSecurenode> GetFullSecurenodeMap() { return mapSecurenodes; }

    void ProcessSecurenodeConnections(CConnman& connman);
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, const string &strCommand, CDataStream& vRecv, CConnman& connman);

    void DoFullVerificationStep(CConnman& connman);
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CSecurenode*>& vSortedByAddr, CConnman& connman);
    void SendVerifyReply(CNode* pnode, CSecurenodeVerification& mnv, CConnman& connman);
    void ProcessVerifyReply(CNode* pnode, CSecurenodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CSecurenodeVerification& mnv);

    /// Return the number of (unique) Securenodes
    int size() { return mapSecurenodes.size(); }

    std::string ToString() const;

    /// Update masternode list and maps using provided CSecurenodeBroadcast
    void UpdateSecurenodeList(CSecurenodeBroadcast mnb, CConnman& connman);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateSecurenodeList(CNode* pfrom, CSecurenodeBroadcast mnb, int& nDos, CConnman& connman);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    bool IsWatchdogActive();
    void UpdateWatchdogVoteTime(const CPubKey &pubKeySecurenode, uint64_t nVoteTime = 0);

    void CheckSecurenode(const CPubKey& pubKeySecurenode, bool fForce);

    bool IsSecurenodePingedWithin(const CPubKey &pubKeySecurenode, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetSecurenodeLastPing(const CPubKey &pubKeySecurenode, const CSecurenodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);
};

void ThreadSecurenodeCheck(CConnman& connman);

#endif
