#include <spos/activesecurenode.h>
#include <spos/securenode.h>
#include <spos/securenode-sync.h>
#include <spos/securenodeman.h>
#include <protocol.h>
#include <utilstrencodings.h>

// Keep track of the active Securenode
CActiveSecurenode activeSecurenode;

void CActiveSecurenode::ManageState(CConnman& connman)
{
    LogPrint(BCLog::SECURENODE, "CActiveSecurenode::ManageState -- Start\n");
    if(!fSecureNode) {
        LogPrint(BCLog::SECURENODE, "CActiveSecurenode::ManageState -- Not a masternode, returning\n");
        return;
    }

    if(Params().NetworkIDString() != CBaseChainParams::REGTEST && !securenodeSync.IsBlockchainSynced()) {
        nState = ACTIVE_SECURENODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveSecurenode::ManageState -- %s: %s\n", GetStateString(), GetStatus());
        return;
    }

    if(nState == ACTIVE_SECURENODE_SYNC_IN_PROCESS) {
        nState = ACTIVE_SECURENODE_INITIAL;
    }

    LogPrint(BCLog::SECURENODE, "CActiveSecurenode::ManageState -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    if(eType == SECURENODE_UNKNOWN) {
        ManageStateInitial(connman);
    }

    if(eType == SECURENODE_REMOTE) {
        ManageStateRemote();
    }

    SendSecurenodePing(connman);
}

std::string CActiveSecurenode::GetStateString() const
{
    switch (nState) {
        case ACTIVE_SECURENODE_INITIAL:         return "INITIAL";
        case ACTIVE_SECURENODE_SYNC_IN_PROCESS: return "SYNC_IN_PROCESS";
        case ACTIVE_SECURENODE_INPUT_TOO_NEW:   return "INPUT_TOO_NEW";
        case ACTIVE_SECURENODE_NOT_CAPABLE:     return "NOT_CAPABLE";
        case ACTIVE_SECURENODE_STARTED:         return "STARTED";
        default:                                return "UNKNOWN";
    }
}

std::string CActiveSecurenode::GetStatus() const
{
    switch (nState) {
        case ACTIVE_SECURENODE_INITIAL:         return "Node just started, not yet activated";
        case ACTIVE_SECURENODE_SYNC_IN_PROCESS: return "Sync in progress. Must wait until sync is complete to start Securenode";
        case ACTIVE_SECURENODE_INPUT_TOO_NEW:   return strprintf("Securenode input must have at least %d confirmations", Params().GetConsensus().nSecurenodeMinimumConfirmations);
        case ACTIVE_SECURENODE_NOT_CAPABLE:     return "Not capable securenode: " + strNotCapableReason;
        case ACTIVE_SECURENODE_STARTED:         return "Securenode successfully started";
        default:                                return "Unknown";
    }
}

std::string CActiveSecurenode::GetTypeString() const
{
    std::string strType;
    switch(eType) {
    case SECURENODE_REMOTE:
        strType = "REMOTE";
        break;
    default:
        strType = "UNKNOWN";
        break;
    }
    return strType;
}

bool CActiveSecurenode::SendSecurenodePing(CConnman& connman)
{
    if(!fPingerEnabled) {
        LogPrint(BCLog::SECURENODE, "CActiveSecurenode::SendSecurenodePing -- %s: masternode ping service is disabled, skipping...\n", GetStateString());
        return false;
    }

    if(!securenodeman.Has(pubKeySecurenode)) {
        strNotCapableReason = "Securenode not in masternode list";
        nState = ACTIVE_SECURENODE_NOT_CAPABLE;
        LogPrintf("CActiveSecurenode::SendSecurenodePing -- %s: %s\n", GetStateString(), strNotCapableReason);
        return false;
    }

    CSecurenodePing mnp(pubKeySecurenode);
    mnp.nSentinelVersion = nSentinelVersion;
    mnp.fSentinelIsCurrent =
            (abs(GetAdjustedTime() - nSentinelPingTime) < SECURENODE_WATCHDOG_MAX_SECONDS);
    if(!mnp.Sign(keySecurenode, pubKeySecurenode)) {
        LogPrintf("CActiveSecurenode::SendSecurenodePing -- ERROR: Couldn't sign Securenode Ping\n");
        return false;
    }

    // Update lastPing for our masternode in Securenode list
    if(securenodeman.IsSecurenodePingedWithin(pubKeySecurenode, SECURENODE_MIN_MNP_SECONDS, mnp.sigTime)) {
        LogPrintf("CActiveSecurenode::SendSecurenodePing -- Too early to send Securenode Ping\n");
        return false;
    }

    securenodeman.SetSecurenodeLastPing(pubKeySecurenode, mnp);

    LogPrintf("%s -- Relaying ping, collateral=%s\n", __func__, HexStr(pubKeySecurenode.GetID().ToString()));
    mnp.Relay(connman);

    return true;
}

bool CActiveSecurenode::UpdateSentinelPing(int version)
{
    nSentinelVersion = version;
    nSentinelPingTime = GetAdjustedTime();

    return true;
}

void CActiveSecurenode::ManageStateInitial(CConnman& connman)
{
    LogPrint(BCLog::SECURENODE, "CActiveSecurenode::ManageStateInitial -- status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        nState = ACTIVE_SECURENODE_NOT_CAPABLE;
        strNotCapableReason = "Securenode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("CActiveSecurenode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // First try to find whatever local address is specified by externalip option
    bool fFoundLocal = GetLocal(service) && CSecurenode::IsValidNetAddr(service);
    if(!fFoundLocal) {
        bool empty = true;
        // If we have some peers, let's try to find our local address from one of them
        connman.ForEachNode([&fFoundLocal, &empty, this](CNode* pnode) {
            empty = false;
            if (!fFoundLocal && pnode->addr.IsIPv4())
                fFoundLocal = GetLocal(service, &pnode->addr) && CSecurenode::IsValidNetAddr(service);
        });
        // nothing and no live connections, can't do anything for now
        if (empty) {
            nState = ACTIVE_SECURENODE_NOT_CAPABLE;
            strNotCapableReason = "Can't detect valid external address. Will retry when there are some connections available.";
            LogPrintf("CActiveSecurenode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    }

    if(!fFoundLocal) {
        nState = ACTIVE_SECURENODE_NOT_CAPABLE;
        strNotCapableReason = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        LogPrintf("CActiveSecurenode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    auto mainChainParams = CreateChainParams(CBaseChainParams::MAIN);
    int mainnetDefaultPort = mainChainParams->GetDefaultPort();
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(service.GetPort() != mainnetDefaultPort) {
            nState = ACTIVE_SECURENODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Invalid port: %u - only %d is supported on mainnet.", service.GetPort(), mainnetDefaultPort);
            LogPrintf("CActiveSecurenode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    } else if(service.GetPort() == mainnetDefaultPort) {
        nState = ACTIVE_SECURENODE_NOT_CAPABLE;
        strNotCapableReason = strprintf("Invalid port: %u - %d is only supported on mainnet.", service.GetPort(), mainnetDefaultPort);
        LogPrintf("CActiveSecurenode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    LogPrintf("CActiveSecurenode::ManageStateInitial -- Checking inbound connection to '%s'\n", service.ToString());

    if(!connman.OpenSecurenodeConnection(CAddress(service, NODE_NETWORK))) {
        nState = ACTIVE_SECURENODE_NOT_CAPABLE;
        strNotCapableReason = "Could not connect to " + service.ToString();
        LogPrintf("CActiveSecurenode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Default to REMOTE
    eType = SECURENODE_REMOTE;

    LogPrint(BCLog::SECURENODE, "CActiveSecurenode::ManageStateInitial -- End status = %s, type = %s, pinger enabled = %d\n", GetStatus(), GetTypeString(), fPingerEnabled);
}

void CActiveSecurenode::ManageStateRemote()
{
    LogPrint(BCLog::SECURENODE, "CActiveSecurenode::ManageStateRemote -- Start status = %s, type = %s, pinger enabled = %d, pubKeySecurenode.GetID() = %s\n",
             GetStatus(), GetTypeString(), fPingerEnabled, pubKeySecurenode.GetID().ToString());

    securenodeman.CheckSecurenode(pubKeySecurenode, true);
    securenode_info_t infoMn;
    if(securenodeman.GetSecurenodeInfo(pubKeySecurenode, infoMn)) {
        if(infoMn.nProtocolVersion != PROTOCOL_VERSION) {
            nState = ACTIVE_SECURENODE_NOT_CAPABLE;
            strNotCapableReason = "Invalid protocol version";
            LogPrintf("CActiveSecurenode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(service != infoMn.addr) {
            nState = ACTIVE_SECURENODE_NOT_CAPABLE;
            strNotCapableReason = "Broadcasted IP doesn't match our external address. Make sure you issued a new broadcast if IP of this masternode changed recently.";
            LogPrintf("CActiveSecurenode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(!CSecurenode::IsValidStateForAutoStart(infoMn.nActiveState)) {
            nState = ACTIVE_SECURENODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Securenode in %s state", CSecurenode::StateToString(infoMn.nActiveState));
            LogPrintf("CActiveSecurenode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if(nState != ACTIVE_SECURENODE_STARTED) {
            LogPrintf("CActiveSecurenode::ManageStateRemote -- STARTED!\n");
            pubKeySecurenode = infoMn.pubKeySecurenode;
            service = infoMn.addr;
            fPingerEnabled = true;
            nState = ACTIVE_SECURENODE_STARTED;
        }
    }
    else {
        nState = ACTIVE_SECURENODE_NOT_CAPABLE;
        strNotCapableReason = "Securenode not in masternode list";
        LogPrintf("CActiveSecurenode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
    }
}
