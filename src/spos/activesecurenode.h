#ifndef ACTIVESECURENODE_H
#define ACTIVESECURENODE_H

#include <chainparams.h>
#include <key.h>
#include <net.h>
#include <primitives/transaction.h>

class CActiveSecurenode;

static const int ACTIVE_SECURENODE_INITIAL          = 0; // initial state
static const int ACTIVE_SECURENODE_SYNC_IN_PROCESS  = 1;
static const int ACTIVE_SECURENODE_INPUT_TOO_NEW    = 2;
static const int ACTIVE_SECURENODE_NOT_CAPABLE      = 3;
static const int ACTIVE_SECURENODE_STARTED          = 4;

extern CActiveSecurenode activeSecurenode;

// Responsible for activating the Securenode and pinging the network
class CActiveSecurenode
{
public:
    enum masternode_type_enum_t {
        SECURENODE_UNKNOWN = 0,
        SECURENODE_REMOTE  = 1
    };

private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    masternode_type_enum_t eType;

    bool fPingerEnabled;

    /// Ping Securenode
    bool SendSecurenodePing(CConnman &connman);

    //  sentinel ping data
    int64_t nSentinelPingTime;
    uint32_t nSentinelVersion;

public:
    // Keys for the active Securenode
    CPubKey pubKeySecurenode;
    CKey keySecurenode;

    // Initialized while registering Securenode
    CService service;

    int nState; // should be one of ACTIVE_SECURENODE_XXXX
    std::string strNotCapableReason;


    CActiveSecurenode()
        : eType(SECURENODE_UNKNOWN),
          fPingerEnabled(false),
          pubKeySecurenode(),
          keySecurenode(),
          service(),
          nState(ACTIVE_SECURENODE_INITIAL)
    {}

    /// Manage state of active Securenode
    void ManageState(CConnman &connman);

    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string GetTypeString() const;

    bool UpdateSentinelPing(int version);

private:
    void ManageStateInitial(CConnman& connman);
    void ManageStateRemote();
};

#endif
