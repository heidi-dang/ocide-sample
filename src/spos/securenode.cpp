#include <spos/activesecurenode.h>
#include <key_io.h>
#include <init.h>
#include <netbase.h>
#include <spos/securenode.h>
#include <spos/securenodeman.h>
#include <spos/securenode-sync.h>
#include <messagesigner.h>
#include <script/standard.h>
#include <util.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif // ENABLE_WALLET

#include <boost/lexical_cast.hpp>


CSecurenode::CSecurenode() :
    securenode_info_t{ SECURENODE_ENABLED, PROTOCOL_VERSION, GetAdjustedTime()}
{}

CSecurenode::CSecurenode(CService addr, CPubKey pubKeySecurenode, uint256 hashSPoSContractTxNew, int nProtocolVersionIn) :
    securenode_info_t{ SECURENODE_ENABLED, nProtocolVersionIn, GetAdjustedTime(), addr, pubKeySecurenode, hashSPoSContractTxNew }
{}

CSecurenode::CSecurenode(const CSecurenode& other) :
    securenode_info_t{other},
    lastPing(other.lastPing),
    vchSig(other.vchSig),
    nPoSeBanScore(other.nPoSeBanScore),
    nPoSeBanHeight(other.nPoSeBanHeight),
    fUnitTest(other.fUnitTest)
{}

CSecurenode::CSecurenode(const CSecurenodeBroadcast& mnb) :
    securenode_info_t{ mnb.nActiveState, mnb.nProtocolVersion,
                         mnb.sigTime, mnb.addr,
                         mnb.pubKeySecurenode,
                         mnb.hashSPoSContractTx,
                         mnb.sigTime /*nTimeLastWatchdogVote*/},
    lastPing(mnb.lastPing),
    vchSig(mnb.vchSig)
{}

//
// When a new securenode broadcast is sent, update our information
//
bool CSecurenode::UpdateFromNewBroadcast(CSecurenodeBroadcast& mnb, CConnman& connman)
{
    if(mnb.sigTime <= sigTime && !mnb.fRecovery) return false;

    pubKeySecurenode = mnb.pubKeySecurenode;
    hashSPoSContractTx = mnb.hashSPoSContractTx;
    sigTime = mnb.sigTime;
    vchSig = mnb.vchSig;
    nProtocolVersion = mnb.nProtocolVersion;
    addr = mnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if(mnb.lastPing == CSecurenodePing() || (mnb.lastPing != CSecurenodePing() && mnb.lastPing.CheckAndUpdate(this, true, nDos, connman))) {
        lastPing = mnb.lastPing;
        securenodeman.mapSeenSecurenodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Securenode privkey...
    if(fSecureNode && pubKeySecurenode == activeSecurenode.pubKeySecurenode) {
        nPoSeBanScore = -SECURENODE_POSE_BAN_MAX_SCORE;
        if(nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeSecurenode.ManageState(connman);
        } else {
            // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
            // but also do not ban the node we get this message from
            LogPrintf("CSecurenode::UpdateFromNewBroadcast -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", nProtocolVersion, PROTOCOL_VERSION);
            return false;
        }
    }
    return true;
}

void CSecurenode::Check(bool fForce)
{
    LOCK2(cs_main, cs);

    if(ShutdownRequested()) return;

    if(!fForce && (GetTime() - nTimeLastChecked < SECURENODE_CHECK_SECONDS)) return;
    nTimeLastChecked = GetTime();

    LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state\n", pubKeySecurenode.GetID().ToString(), GetStateString());

    int nHeight = 0;
    if(!fUnitTest) {
        nHeight = chainActive.Height();
    }

    if(IsPoSeBanned()) {
        if(nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Securenode still will be on the edge and can be banned back easily if it keeps ignoring mnverify
        // or connect attempts. Will require few mnverify messages to strengthen its position in mn list.
        LogPrintf("CSecurenode::Check -- Securenode %s is unbanned and back in list now\n",
                  pubKeySecurenode.GetID().ToString());
        DecreasePoSeBanScore();
    } else if(nPoSeBanScore >= SECURENODE_POSE_BAN_MAX_SCORE) {
        nActiveState = SECURENODE_POSE_BAN;
        // ban for the whole payment cycle
        nPoSeBanHeight = 60;
        LogPrintf("CSecurenode::Check -- Securenode %s is banned till block %d now\n",
                  pubKeySecurenode.GetID().ToString(), nPoSeBanHeight);
        return;
    }

    int nActiveStatePrev = nActiveState;
    bool fOurSecurenode = fSecureNode && activeSecurenode.pubKeySecurenode == pubKeySecurenode;

    // securenode doesn't meet payment protocol requirements ...
    bool fRequireUpdate =
            // or it's our own node and we just updated it to the new protocol but we are still waiting for activation ...
            (fOurSecurenode && nProtocolVersion < PROTOCOL_VERSION);

    if(fRequireUpdate) {
        nActiveState = SECURENODE_UPDATE_REQUIRED;
        if(nActiveStatePrev != nActiveState) {
            LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state now\n",
                     pubKeySecurenode.GetID().ToString(), GetStateString());
        }
        return;
    }

    // keep old securenodes on start, give them a chance to receive updates...
    bool fWaitForPing = !securenodeSync.IsSecurenodeListSynced() && !IsPingedWithin(SECURENODE_MIN_MNP_SECONDS);

    if(fWaitForPing && !fOurSecurenode) {
        // ...but if it was already expired before the initial check - return right away
        if(IsExpired() || IsWatchdogExpired() || IsNewStartRequired()) {
            LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state, waiting for ping\n",
                     pubKeySecurenode.GetID().ToString(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own securenode
    if(!fWaitForPing || fOurSecurenode) {

        if(!IsPingedWithin(SECURENODE_NEW_START_REQUIRED_SECONDS)) {
            nActiveState = SECURENODE_NEW_START_REQUIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state now\n",
                         pubKeySecurenode.GetID().ToString(), GetStateString());
            }
            return;
        }

        bool fWatchdogActive = securenodeSync.IsSynced() && securenodeman.IsWatchdogActive();
        bool fWatchdogExpired = (fWatchdogActive && ((GetAdjustedTime() - nTimeLastWatchdogVote) > SECURENODE_WATCHDOG_MAX_SECONDS));

        LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- outpoint=%s, nTimeLastWatchdogVote=%d, GetAdjustedTime()=%d, fWatchdogExpired=%d\n",
                 pubKeySecurenode.GetID().ToString(), nTimeLastWatchdogVote, GetAdjustedTime(), fWatchdogExpired);

        if(fWatchdogExpired) {
            nActiveState = SECURENODE_WATCHDOG_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state now\n",
                         pubKeySecurenode.GetID().ToString(), GetStateString());
            }
            return;
        }

        if(!IsPingedWithin(SECURENODE_EXPIRATION_SECONDS)) {
            nActiveState = SECURENODE_EXPIRED;
            if(nActiveStatePrev != nActiveState) {
                LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state now\n",
                         pubKeySecurenode.GetID().ToString(), GetStateString());
            }
            return;
        }
    }

    if(lastPing.sigTime - sigTime < SECURENODE_MIN_MNP_SECONDS) {
        nActiveState = SECURENODE_PRE_ENABLED;
        if(nActiveStatePrev != nActiveState) {
            LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state now\n",
                     pubKeySecurenode.GetID().ToString(), GetStateString());
        }
        return;
    }

    nActiveState = SECURENODE_ENABLED; // OK
    if(nActiveStatePrev != nActiveState) {
        LogPrint(BCLog::SECURENODE, "CSecurenode::Check -- Securenode %s is in %s state now\n",
                 pubKeySecurenode.GetID().ToString(), GetStateString());
    }
}

bool CSecurenode::IsValidNetAddr() const
{
    return IsValidNetAddr(addr);
}

bool CSecurenode::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
            (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

securenode_info_t CSecurenode::GetInfo() const
{
    securenode_info_t info{*this};
    info.nTimeLastPing = lastPing.sigTime;
    info.fInfoValid = true;
    return info;
}

std::string CSecurenode::StateToString(int nStateIn)
{
    switch(nStateIn) {
    case SECURENODE_PRE_ENABLED:            return "PRE_ENABLED";
    case SECURENODE_ENABLED:                return "ENABLED";
    case SECURENODE_EXPIRED:                return "EXPIRED";
    case SECURENODE_UPDATE_REQUIRED:        return "UPDATE_REQUIRED";
    case SECURENODE_WATCHDOG_EXPIRED:       return "WATCHDOG_EXPIRED";
    case SECURENODE_NEW_START_REQUIRED:     return "NEW_START_REQUIRED";
    case SECURENODE_POSE_BAN:               return "POSE_BAN";
    default:                                return "UNKNOWN";
    }
}

std::string CSecurenode::GetStateString() const
{
    return StateToString(nActiveState);
}

std::string CSecurenode::GetStatus() const
{
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

#ifdef ENABLE_WALLET
bool CSecurenodeBroadcast::Create(std::string strService, std::string strSecurePrivKey,
                                    std::string strHashSPoSContractTx, std::string& strErrorRet,
                                    CSecurenodeBroadcast &mnbRet, bool fOffline)
{
    CPubKey pubKeySecurenodeNew;
    CKey keySecurenodeNew;

    auto Log = [&strErrorRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CSecurenodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    };

    //need correct blocks to send ping
    if (!fOffline && !securenodeSync.IsBlockchainSynced())
        return Log("Sync in progress. Must wait until sync is complete to start Securenode");

    if (!CMessageSigner::GetKeysFromSecret(strSecurePrivKey, keySecurenodeNew, pubKeySecurenodeNew))
        return Log(strprintf("Invalid securenode key %s", strSecurePrivKey));

    CService service;
    if (!Lookup(strService.c_str(), service, 0, false))
        return Log(strprintf("Invalid address %s for securenode.", strService));
    int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort)
            return Log(strprintf("Invalid port %u for securenode %s, only %d is supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));
    } else if (service.GetPort() == mainnetDefaultPort)
        return Log(strprintf("Invalid port %u for securenode %s, %d is the only supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort));

    return Create(service, keySecurenodeNew, pubKeySecurenodeNew, uint256S(strHashSPoSContractTx), strErrorRet, mnbRet);
}

bool CSecurenodeBroadcast::Create(const CService& service, const CKey& keySecurenodeNew,
                                    const CPubKey& pubKeySecurenodeNew, const uint256 &hashSPoSContractTx,
                                    std::string &strErrorRet, CSecurenodeBroadcast &mnbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint(BCLog::SECURENODE, "CSecurenodeBroadcast::Create -- pubKeySecurenodeNew.GetID() = %s\n",
             pubKeySecurenodeNew.GetID().ToString());

    auto Log = [&strErrorRet,&mnbRet](std::string sErr)->bool
    {
        strErrorRet = sErr;
        LogPrintf("CSecurenodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CSecurenodeBroadcast();
        return false;
    };

    CSecurenodePing mnp(pubKeySecurenodeNew);
    if (!mnp.Sign(keySecurenodeNew, pubKeySecurenodeNew))
        return Log(strprintf("Failed to sign ping, securenode=%s",
                             pubKeySecurenodeNew.GetID().ToString()));

    mnbRet = CSecurenodeBroadcast(service, pubKeySecurenodeNew, hashSPoSContractTx, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr())
        return Log(strprintf("Invalid IP address, securenode=%s",
                             pubKeySecurenodeNew.GetID().ToString()));

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keySecurenodeNew))
        return Log(strprintf("Failed to sign broadcast, securenode=%s",
                             pubKeySecurenodeNew.GetID().ToString()));

    return true;
}
#endif // ENABLE_WALLET

bool CSecurenodeBroadcast::SimpleCheck(int& nDos)
{
    nDos = 0;

    // make sure addr is valid
    if(!IsValidNetAddr()) {
        LogPrintf("CSecurenodeBroadcast::SimpleCheck -- Invalid addr, rejected: securenode=%s  addr=%s\n",
                  pubKeySecurenode.GetID().ToString(), addr.ToString());
        return false;
    }

    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CSecurenodeBroadcast::SimpleCheck -- Signature rejected, too far into the future: securenode=%s\n",
                  pubKeySecurenode.GetID().ToString());
        nDos = 1;
        return false;
    }

    // empty ping or incorrect sigTime/unknown blockhash
    if(lastPing == CSecurenodePing() || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = SECURENODE_EXPIRED;
    }

    if(nProtocolVersion < PRESEGWIT_PROTO_VERSION) {
        LogPrintf("CSecurenodeBroadcast::SimpleCheck -- ignoring outdated Securenode: securenode=%s  nProtocolVersion=%d\n",
                  pubKeySecurenode.GetID().ToString(), nProtocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeySecurenode.GetID());

    if(pubkeyScript.size() != 25) {
        LogPrintf("CSecurenodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(addr.GetPort() != mainnetDefaultPort) return false;
    } else if(addr.GetPort() == mainnetDefaultPort) return false;

    return true;
}

bool CSecurenodeBroadcast::Update(CSecurenode* pmn, int& nDos, CConnman& connman)
{
    nDos = 0;

    if(pmn->sigTime == sigTime && !fRecovery) {
        // mapSeenSecurenodeBroadcast in CSecurenodeMan::CheckMnbAndUpdateSecurenodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if(pmn->sigTime > sigTime) {
        LogPrintf("CSecurenodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Securenode %s %s\n",
                  sigTime, pmn->sigTime, pubKeySecurenode.GetID().ToString(), addr.ToString());
        return false;
    }

    pmn->Check();

    // securenode is banned by PoSe
    if(pmn->IsPoSeBanned()) {
        LogPrintf("CSecurenodeBroadcast::Update -- Banned by PoSe, securenode=%s\n",
                  pubKeySecurenode.GetID().ToString());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if(pmn->pubKeySecurenode != pubKeySecurenode) {
        LogPrintf("CSecurenodeBroadcast::Update -- Got mismatched pubKeySecurenode");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CSecurenodeBroadcast::Update -- CheckSignature() failed, securenode=%s\n",
                  pubKeySecurenode.GetID().ToString());
        return false;
    }

    // if ther was no securenode broadcast recently or if it matches our Securenode privkey...
    if(!pmn->IsBroadcastedWithin(SECURENODE_MIN_MNB_SECONDS) || (fSecureNode && pubKeySecurenode == activeSecurenode.pubKeySecurenode)) {
        // take the newest entry
        LogPrintf("CSecurenodeBroadcast::Update -- Got UPDATED Securenode entry: addr=%s\n", addr.ToString());
        if(pmn->UpdateFromNewBroadcast(*this, connman)) {
            pmn->Check();
            Relay(connman);
        }
        securenodeSync.BumpAssetLastTime("CSecurenodeBroadcast::Update");
    }

    return true;
}

bool CSecurenodeBroadcast::CheckSecurenode(int &nDos)
{
    nDos = 0;
    return CheckSignature(nDos);
}

bool CSecurenodeBroadcast::Sign(const CKey& keyCollateralAddress)
{
    std::string strError;
    std::string strMessage;

    sigTime = GetAdjustedTime();

    strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
            pubKeySecurenode.GetID().ToString() +
            boost::lexical_cast<std::string>(nProtocolVersion);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keyCollateralAddress, CPubKey::InputScriptType::SPENDP2PKH)) {
        LogPrintf("CSecurenodeBroadcast::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeySecurenode.GetID(), vchSig, strMessage, strError)) {
        LogPrintf("CSecurenodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSecurenodeBroadcast::CheckSignature(int& nDos)
{
    std::string strMessage;
    std::string strError = "";
    nDos = 0;

    strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
            pubKeySecurenode.GetID().ToString() +
            boost::lexical_cast<std::string>(nProtocolVersion);

    LogPrint(BCLog::SECURENODE, "CSecurenodeBroadcast::CheckSignature -- strMessage: %s  pubKeySecurenode address: %s  sig: %s\n", strMessage, CBitcoinAddress(pubKeySecurenode.GetID()).ToString(), EncodeBase64(&vchSig[0], vchSig.size()));

    if(!CMessageSigner::VerifyMessage(pubKeySecurenode.GetID(), vchSig, strMessage, strError)){
        LogPrintf("CSecurenodeBroadcast::CheckSignature -- Got bad Securenode announce signature, error: %s\n", strError);
        nDos = 100;
        return false;
    }

    return true;
}

void CSecurenodeBroadcast::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!securenodeSync.IsSynced()) {
        LogPrint(BCLog::SECURENODE, "CSecurenodeBroadcast::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_SECURENODE_ANNOUNCE, GetHash());
    connman.ForEachNode([&inv](CNode* pnode)
    {
        pnode->PushInventory(inv);
    });
}

CSecurenodePing::CSecurenodePing(const CPubKey &securePubKey)
{
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    this->securePubKey = securePubKey;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
}

bool CSecurenodePing::Sign(const CKey& keySecurenode, const CPubKey& pubKeySecurenode)
{
    std::string strError;
    std::string strMasterNodeSignMessage;

    // TODO: add sentinel data
    sigTime = GetAdjustedTime();
    std::string strMessage = securePubKey.GetID().ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keySecurenode, CPubKey::InputScriptType::SPENDP2PKH)) {
        LogPrintf("CSecurenodePing::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeySecurenode.GetID(), vchSig, strMessage, strError)) {
        LogPrintf("CSecurenodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CSecurenodePing::CheckSignature(CPubKey& pubKeySecurenode, int &nDos)
{
    // TODO: add sentinel data
    std::string strMessage = securePubKey.GetID().ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string strError = "";
    nDos = 0;

    if(!CMessageSigner::VerifyMessage(pubKeySecurenode.GetID(), vchSig, strMessage, strError)) {
        LogPrintf("CSecurenodePing::CheckSignature -- Got bad Securenode ping signature, securenode=%s, error: %s\n",
                  securePubKey.GetID().ToString(), strError);
        nDos = 33;
        return false;
    }
    return true;
}

bool CSecurenodePing::SimpleCheck(int& nDos)
{
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CSecurenodePing::SimpleCheck -- Signature rejected, too far into the future, securenode=%s\n",
                  securePubKey.GetID().ToString());
        nDos = 1;
        return false;
    }

    {
        AssertLockHeld(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if (mi == mapBlockIndex.end()) {
            LogPrint(BCLog::SECURENODE, "CSecurenodePing::SimpleCheck -- Securenode ping is invalid, unknown block hash: securenode=%s blockHash=%s\n",
                     securePubKey.GetID().ToString(), blockHash.ToString());
            // maybe we stuck or forked so we shouldn't ban this node, just fail to accept this ping
            // TODO: or should we also request this block?
            return false;
        }
    }
    LogPrint(BCLog::SECURENODE, "CSecurenodePing::SimpleCheck -- Securenode ping verified: securenode=%s  blockHash=%s  sigTime=%d\n",
             securePubKey.GetID().ToString(), blockHash.ToString(), sigTime);
    return true;
}

bool CSecurenodePing::CheckAndUpdate(CSecurenode* pmn, bool fFromNewBroadcast, int& nDos, CConnman& connman)
{
    // don't ban by default
    nDos = 0;

    {
        LOCK(cs_main);
        if (!SimpleCheck(nDos)) {
            return false;
        }
    }

    if (pmn == NULL) {
        LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- Couldn't find Securenode entry, securenode=%s\n",
                 securePubKey.GetID().ToString());
        return false;
    }

    if(!fFromNewBroadcast) {
        if (pmn->IsUpdateRequired()) {
            LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- securenode protocol is outdated, securenode=%s\n",
                     securePubKey.GetID().ToString());
            return false;
        }

        if (pmn->IsNewStartRequired()) {
            LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- securenode is completely expired, new start is required, securenode=%s\n",
                     securePubKey.GetID().ToString());
            return false;
        }
    }

    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if ((*mi).second && (*mi).second->nHeight < chainActive.Height() - 24) {
            LogPrintf("CSecurenodePing::CheckAndUpdate -- Securenode ping is invalid, block hash is too old: securenode=%s  blockHash=%s\n",
                      securePubKey.GetID().ToString(), blockHash.ToString());
            // nDos = 1;
            return false;
        }
    }

    LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- New ping: securenode=%s  blockHash=%s  sigTime=%d\n",
             securePubKey.GetID().ToString(), blockHash.ToString(), sigTime);

    // LogPrintf("mnping - Found corresponding mn for vin: %s\n", HexStr(pubKeySecurenode.Raw()));
    // update only if there is no known ping for this securenode or
    // last ping was more then SECURENODE_MIN_MNP_SECONDS-60 ago comparing to this one
    if (pmn->IsPingedWithin(SECURENODE_MIN_MNP_SECONDS - 60, sigTime)) {
        LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- Securenode ping arrived too early, securenode=%s\n",
                 securePubKey.GetID().ToString());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }

    if (!CheckSignature(pmn->pubKeySecurenode, nDos)) return false;

    // so, ping seems to be ok

    // if we are still syncing and there was no known ping for this mn for quite a while
    // (NOTE: assuming that SECURENODE_EXPIRATION_SECONDS/2 should be enough to finish mn list sync)
    if(!securenodeSync.IsSecurenodeListSynced() && !pmn->IsPingedWithin(SECURENODE_EXPIRATION_SECONDS/2)) {
        // let's bump sync timeout
        LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- bumping sync timeout, securenode=%s\n",
                 securePubKey.GetID().ToString());
        securenodeSync.BumpAssetLastTime("CSecurenodePing::CheckAndUpdate");
    }

    // let's store this ping as the last one
    LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- Securenode ping accepted, securenode=%s\n",
             securePubKey.GetID().ToString());
    pmn->lastPing = *this;

    // and update securenodeman.mapSeenSecurenodeBroadcast.lastPing which is probably outdated
    CSecurenodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if (securenodeman.mapSeenSecurenodeBroadcast.count(hash)) {
        securenodeman.mapSeenSecurenodeBroadcast[hash].second.lastPing = *this;
    }

    // force update, ignoring cache
    pmn->Check(true);
    // relay ping for nodes in ENABLED/EXPIRED/WATCHDOG_EXPIRED state only, skip everyone else
    if (!pmn->IsEnabled() && !pmn->IsExpired() && !pmn->IsWatchdogExpired()) return false;

    LogPrint(BCLog::SECURENODE, "CSecurenodePing::CheckAndUpdate -- Securenode ping acceepted and relayed, securenode=%s\n",
             securePubKey.GetID().ToString());
    Relay(connman);

    return true;
}

void CSecurenodePing::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!securenodeSync.IsSynced()) {
        LogPrint(BCLog::SECURENODE, "CSecurenodePing::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_SECURENODE_PING, GetHash());
    connman.ForEachNode([&inv](CNode* pnode)
    {
        pnode->PushInventory(inv);
    });
}

void CSecurenode::UpdateWatchdogVoteTime(uint64_t nVoteTime)
{
    LOCK(cs);
    nTimeLastWatchdogVote = (nVoteTime == 0) ? GetAdjustedTime() : nVoteTime;
}

void CSecurenodeVerification::Relay() const
{
    CInv inv(MSG_SECURENODE_VERIFY, GetHash());
    g_connman->ForEachNode([&inv](CNode* pnode)
    {
        pnode->PushInventory(inv);
    });
}
