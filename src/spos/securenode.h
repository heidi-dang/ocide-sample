#ifndef SECURENODE_H
#define SECURENODE_H

#include <key.h>
#include <validation.h>
//#include <spork.h>

class CSecurenode;
class CSecurenodeBroadcast;
class CConnman;

static const int SECURENODE_CHECK_SECONDS               = 20;
static const int SECURENODE_MIN_MNB_SECONDS             = 5 * 60;
static const int SECURENODE_MIN_MNP_SECONDS             = 10 * 60;
static const int SECURENODE_EXPIRATION_SECONDS          = 65 * 60;
static const int SECURENODE_WATCHDOG_MAX_SECONDS        = 120 * 60;
static const int SECURENODE_NEW_START_REQUIRED_SECONDS  = 180 * 60;
static const int SECURENODE_POSE_BAN_MAX_SCORE          = 5;

//
// The Securenode Ping Class : Contains a different serialize method for sending pings from securenodes throughout the network
//

// sentinel version before sentinel ping implementation
#define DEFAULT_SENTINEL_VERSION 0x010001

class CSecurenodePing
{
public:
    CPubKey securePubKey{};
    uint256 blockHash{};
    int64_t sigTime{}; //mnb message times
    std::vector<unsigned char> vchSig{};
    bool fSentinelIsCurrent = false; // true if last sentinel ping was actual
    // MSB is always 0, other 3 bits corresponds to x.x.x version scheme
    uint32_t nSentinelVersion{DEFAULT_SENTINEL_VERSION};

    CSecurenodePing() = default;

    CSecurenodePing(const CPubKey& securePubKey);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(securePubKey);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
        if(ser_action.ForRead() && (s.size() == 0))
        {
            fSentinelIsCurrent = false;
            nSentinelVersion = DEFAULT_SENTINEL_VERSION;
            return;
        }
        READWRITE(fSentinelIsCurrent);
        READWRITE(nSentinelVersion);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << securePubKey;
        ss << sigTime;
        return ss.GetHash();
    }

    bool IsExpired() const { return GetAdjustedTime() - sigTime > SECURENODE_NEW_START_REQUIRED_SECONDS; }
    bool Sign(const CKey& keySecurenode, const CPubKey& pubKeySecurenode);
    bool CheckSignature(CPubKey& pubKeySecurenode, int &nDos);
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CSecurenode* pmn, bool fFromNewBroadcast, int& nDos, CConnman& connman);
    void Relay(CConnman& connman);
};

inline bool operator==(const CSecurenodePing& a, const CSecurenodePing& b)
{
    return a.securePubKey == b.securePubKey && a.blockHash == b.blockHash;
}
inline bool operator!=(const CSecurenodePing& a, const CSecurenodePing& b)
{
    return !(a == b);
}

struct securenode_info_t
{
    // Note: all these constructors can be removed once C++14 is enabled.
    // (in C++11 the member initializers wrongly disqualify this as an aggregate)
    securenode_info_t() = default;
    securenode_info_t(securenode_info_t const&) = default;

    securenode_info_t(int activeState, int protoVer, int64_t sTime) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime} {}

    securenode_info_t(int activeState, int protoVer, int64_t sTime,
                        CService const& addr, CPubKey const& pkMN, uint256 const &hashSPoSContractTxNew,
                      int64_t tWatchdogV = 0) :
        nActiveState{activeState}, nProtocolVersion{protoVer}, sigTime{sTime},
        addr{addr}, pubKeySecurenode{pkMN}, hashSPoSContractTx{hashSPoSContractTxNew},
        nTimeLastWatchdogVote{tWatchdogV} {}

    int nActiveState = 0;
    int nProtocolVersion = 0;
    int64_t sigTime = 0; //mnb message time

    CService addr{};
    CPubKey pubKeySecurenode{};
    uint256 hashSPoSContractTx{};
    int64_t nTimeLastWatchdogVote = 0;

    int64_t nLastDsq = 0; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked = 0;
    int64_t nTimeLastPing = 0;
    bool fInfoValid = false;
};

//
// The Securenode Class. For managing the Darksend process. It contains the input of the 1000DRK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CSecurenode : public securenode_info_t
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

public:
    enum state {
        SECURENODE_PRE_ENABLED,
        SECURENODE_ENABLED,
        SECURENODE_EXPIRED,
        SECURENODE_UPDATE_REQUIRED,
        SECURENODE_WATCHDOG_EXPIRED,
        SECURENODE_NEW_START_REQUIRED,
        SECURENODE_POSE_BAN
    };

    CSecurenodePing lastPing{};
    std::vector<unsigned char> vchSig{};

    int nPoSeBanScore{};
    int nPoSeBanHeight{};
    bool fUnitTest = false;

    CSecurenode();
    CSecurenode(const CSecurenode& other);
    CSecurenode(const CSecurenodeBroadcast& mnb);
    CSecurenode(CService addrNew, CPubKey pubKeySecurenodeNew, uint256 hashSPoSContractTxNew, int nProtocolVersionIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        READWRITE(addr);
        READWRITE(pubKeySecurenode);
        READWRITE(hashSPoSContractTx);
        READWRITE(lastPing);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nLastDsq);
        READWRITE(nTimeLastChecked);
        READWRITE(nTimeLastWatchdogVote);
        READWRITE(nActiveState);
        READWRITE(nProtocolVersion);
        READWRITE(nPoSeBanScore);
        READWRITE(nPoSeBanHeight);
        READWRITE(fUnitTest);
    }

    bool UpdateFromNewBroadcast(CSecurenodeBroadcast& mnb, CConnman& connman);

    void Check(bool fForce = false);

    bool IsBroadcastedWithin(int nSeconds) const { return GetAdjustedTime() - sigTime < nSeconds; }

    bool IsPingedWithin(int nSeconds, int64_t nTimeToCheckAt = -1) const
    {
        if(lastPing == CSecurenodePing()) return false;

        if(nTimeToCheckAt == -1) {
            nTimeToCheckAt = GetAdjustedTime();
        }
        return nTimeToCheckAt - lastPing.sigTime < nSeconds;
    }

    bool IsEnabled() const { return nActiveState == SECURENODE_ENABLED; }
    bool IsPreEnabled() const { return nActiveState == SECURENODE_PRE_ENABLED; }
    bool IsPoSeBanned() const { return nActiveState == SECURENODE_POSE_BAN; }
    // NOTE: this one relies on nPoSeBanScore, not on nActiveState as everything else here
    bool IsPoSeVerified() const { return nPoSeBanScore <= -SECURENODE_POSE_BAN_MAX_SCORE; }
    bool IsExpired() const { return nActiveState == SECURENODE_EXPIRED; }
    bool IsUpdateRequired() const { return nActiveState == SECURENODE_UPDATE_REQUIRED; }
    bool IsWatchdogExpired() const { return nActiveState == SECURENODE_WATCHDOG_EXPIRED; }
    bool IsNewStartRequired() const { return nActiveState == SECURENODE_NEW_START_REQUIRED; }

    static bool IsValidStateForAutoStart(int nActiveStateIn)
    {
        return  nActiveStateIn == SECURENODE_ENABLED ||
                nActiveStateIn == SECURENODE_PRE_ENABLED ||
                nActiveStateIn == SECURENODE_EXPIRED ||
                nActiveStateIn == SECURENODE_WATCHDOG_EXPIRED;
    }

    bool IsValidForPayment() const
    {

        if(nActiveState == SECURENODE_ENABLED && !IsPoSeBanned()) {
            return true;
        }

        return false;
    }

    bool IsValidNetAddr() const;
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < SECURENODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -SECURENODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }
    void PoSeBan() { nPoSeBanScore = SECURENODE_POSE_BAN_MAX_SCORE; }

    securenode_info_t GetInfo() const;

    static std::string StateToString(int nStateIn);
    std::string GetStateString() const;
    std::string GetStatus() const;

    void UpdateWatchdogVoteTime(uint64_t nVoteTime = 0);

    CSecurenode& operator=(CSecurenode const& from)
    {
        static_cast<securenode_info_t&>(*this)=from;
        lastPing = from.lastPing;
        vchSig = from.vchSig;
        nPoSeBanScore = from.nPoSeBanScore;
        nPoSeBanHeight = from.nPoSeBanHeight;
        fUnitTest = from.fUnitTest;
        return *this;
    }
};

inline bool operator==(const CSecurenode& a, const CSecurenode& b)
{
    return a.addr == b.addr && a.pubKeySecurenode == b.pubKeySecurenode;
}
inline bool operator!=(const CSecurenode& a, const CSecurenode& b)
{
    return !(a == b);
}


//
// The Securenode Broadcast Class : Contains a different serialize method for sending securenodes through the network
//

class CSecurenodeBroadcast : public CSecurenode
{
public:

    bool fRecovery;

    CSecurenodeBroadcast() : CSecurenode(), fRecovery(false) {}
    CSecurenodeBroadcast(const CSecurenode& mn) : CSecurenode(mn), fRecovery(false) {}
    CSecurenodeBroadcast(CService addrNew, CPubKey pubKeySecurenodeNew, uint256 hashSPoSContractTxNew, int nProtocolVersionIn) :
        CSecurenode(addrNew, pubKeySecurenodeNew, hashSPoSContractTxNew, nProtocolVersionIn), fRecovery(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(addr);
        READWRITE(pubKeySecurenode);
        READWRITE(hashSPoSContractTx);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nProtocolVersion);
        READWRITE(lastPing);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << pubKeySecurenode;
        ss << hashSPoSContractTx;

        ss << sigTime;
        return ss.GetHash();
    }

    /// Create Securenode broadcast, needs to be relayed manually after that
    static bool Create(const CService& service, const CKey& keySecurenodeNew,
                       const CPubKey& pubKeySecurenodeNew, const uint256 &hashSPoSContractTx,
                       std::string &strErrorRet, CSecurenodeBroadcast &mnbRet);

    static bool Create(std::string strService, std::string strSecureAddress,
                       std::string strHashSPoSContractTx, std::string& strErrorRet,
                       CSecurenodeBroadcast &mnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CSecurenode* pmn, int& nDos, CConnman& connman);
    bool CheckSecurenode(int &nDos);

    bool Sign(const CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos);
    void Relay(CConnman& connman);
};

class CSecurenodeVerification
{
public:
    CPubKey pubKeySecurenode1{};
    CPubKey pubKeySecurenode2{};
    CService addr{};
    int nonce{};
    int nBlockHeight{};
    std::vector<unsigned char> vchSig1{};
    std::vector<unsigned char> vchSig2{};

    CSecurenodeVerification() = default;

    CSecurenodeVerification(CService addr, int nonce, int nBlockHeight) :
        addr(addr),
        nonce(nonce),
        nBlockHeight(nBlockHeight)
    {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(pubKeySecurenode1);
        READWRITE(pubKeySecurenode2);
        READWRITE(addr);
        READWRITE(nonce);
        READWRITE(nBlockHeight);
        READWRITE(vchSig1);
        READWRITE(vchSig2);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << pubKeySecurenode1;
        ss << pubKeySecurenode2;
        ss << addr;
        ss << nonce;
        ss << nBlockHeight;
        return ss.GetHash();
    }

    void Relay() const;
};

#endif
