#include <spos/activesecurenode.h>
#include <addrman.h>
#include <spos/securenode-sync.h>
#include <spos/securenodeman.h>
#include <spos/securenode.h>
#include <netfulfilledman.h>
#include <net_processing.h>
#include <script/standard.h>
#include <messagesigner.h>
#include <utilstrencodings.h>
#include <util.h>
#include <init.h>
#include <netmessagemaker.h>

/** Securenode manager */
CSecurenodeMan securenodeman;

const std::string CSecurenodeMan::SERIALIZATION_VERSION_STRING = "CSecurenodeMan-Version-7";

static bool GetBlockHash(uint256 &hash, int nBlockHeight)
{
    if(auto index = chainActive[nBlockHeight])
    {
        hash = index->GetBlockHash();
        return true;
    }
    return false;
}

struct CompareByAddr

{
    bool operator()(const CSecurenode* t1,
                    const CSecurenode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

CSecurenodeMan::CSecurenodeMan()
    : cs(),
      mapSecurenodes(),
      mAskedUsForSecurenodeList(),
      mWeAskedForSecurenodeList(),
      mWeAskedForSecurenodeListEntry(),
      mWeAskedForVerification(),
      mMnbRecoveryRequests(),
      mMnbRecoveryGoodReplies(),
      listScheduledMnbRequestConnections(),
      nLastWatchdogVoteTime(0),
      mapSeenSecurenodeBroadcast(),
      mapSeenSecurenodePing(),
      nDsqCount(0)
{}

bool CSecurenodeMan::Add(CSecurenode &mn)
{
    LOCK(cs);

    if (Has(mn.pubKeySecurenode)) return false;

    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::Add -- Adding new Securenode: addr=%s, %i now\n", mn.addr.ToString(), size() + 1);
    mapSecurenodes[mn.pubKeySecurenode] = mn;

    return true;
}

void CSecurenodeMan::AskForMN(CNode* pnode, const CPubKey &pubKeySecurenode, CConnman& connman)
{
    if(!pnode) return;

    LOCK(cs);

    auto it1 = mWeAskedForSecurenodeListEntry.find(pubKeySecurenode);
    if (it1 != mWeAskedForSecurenodeListEntry.end()) {
        std::map<CNetAddr, int64_t>::iterator it2 = it1->second.find(pnode->addr);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            LogPrintf("CSecurenodeMan::AskForMN -- Asking same peer %s for missing securenode entry again: %s\n", pnode->addr.ToString(), pubKeySecurenode.GetID().ToString());
        } else {
            // we already asked for this outpoint but not this node
            LogPrintf("CSecurenodeMan::AskForMN -- Asking new peer %s for missing securenode entry: %s\n", pnode->addr.ToString(), pubKeySecurenode.GetID().ToString());
        }
    } else {
        // we never asked any node for this outpoint
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::AskForMN -- Asking peer %s for missing securenode entry for the first time: %s\n", pnode->addr.ToString(), pubKeySecurenode.GetID().ToString());
    }
    mWeAskedForSecurenodeListEntry[pubKeySecurenode][pnode->addr] = GetTime() + DSEG_UPDATE_SECONDS;

    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SECURENODESEG, pubKeySecurenode));
}

bool CSecurenodeMan::PoSeBan(const CPubKey &pubKeySecurenode)
{
    LOCK(cs);
    CSecurenode* pmn = Find(pubKeySecurenode);
    if (!pmn) {
        return false;
    }
    pmn->PoSeBan();

    return true;
}

void CSecurenodeMan::Check()
{
    // we need to lock in this order because function that called us uses same order, bad practice, but no other choice because of recursive mutexes.
    LOCK2(cs_main, cs);

    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::Check -- nLastWatchdogVoteTime=%d, IsWatchdogActive()=%d\n", nLastWatchdogVoteTime, IsWatchdogActive());

    for (auto& mnpair : mapSecurenodes) {
        mnpair.second.Check();
    }
}

void CSecurenodeMan::CheckAndRemove(CConnman& connman)
{
    if(!securenodeSync.IsSecurenodeListSynced()) return;

    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove\n");
    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckMnbAndUpdateSecurenodeList()
        LOCK2(cs_main, cs);

        Check();



        // Remove spent securenodes, prepare structures and make requests to reasure the state of inactive ones
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES securenode entries at a time
        int nAskForMnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        auto it = mapSecurenodes.begin();
        while (it != mapSecurenodes.end()) {
            CSecurenodeBroadcast mnb = CSecurenodeBroadcast(it->second);
            uint256 hash = mnb.GetHash();
            // If collateral was spent ...
            if (it->second.IsNewStartRequired()) {
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove -- Removing Securenode: %s  addr=%s  %i now\n", it->second.GetStateString(), it->second.addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenSecurenodeBroadcast.erase(hash);
                mWeAskedForSecurenodeListEntry.erase(it->first);

                // and finally remove it from the list
                mapSecurenodes.erase(it++);
            } else {
                bool fAsk = (nAskForMnbRecovery > 0) &&
                        securenodeSync.IsSynced() &&
                        !IsMnbRecoveryRequested(hash);
                if(fAsk) {
                    // this mn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CNetAddr> setRequested;
                    // wait for mnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mMnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for SECURENODE_NEW_START_REQUIRED securenodes
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove -- mMnbRecoveryGoodReplies size=%d\n", (int)mMnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CSecurenodeBroadcast> >::iterator itMnbReplies = mMnbRecoveryGoodReplies.begin();
        while(itMnbReplies != mMnbRecoveryGoodReplies.end()){
            if(mMnbRecoveryRequests[itMnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if(itMnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this mn doesn't require new mnb, reprocess one of new mnbs
                    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove -- reprocessing mnb, securenode=%s\n", itMnbReplies->second[0].pubKeySecurenode.GetID().ToString());
                    // mapSeenSecurenodeBroadcast.erase(itMnbReplies->first);
                    int nDos;
                    itMnbReplies->second[0].fRecovery = true;
                    CheckMnbAndUpdateSecurenodeList(NULL, itMnbReplies->second[0], nDos, connman);
                }
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove -- removing mnb recovery reply, securenode=%s, size=%d\n", itMnbReplies->second[0].pubKeySecurenode.GetID().ToString(), (int)itMnbReplies->second.size());
                mMnbRecoveryGoodReplies.erase(itMnbReplies++);
            } else {
                ++itMnbReplies;
            }
        }
    }
    {
        // no need for cm_main below
        LOCK(cs);

        std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > >::iterator itMnbRequest = mMnbRecoveryRequests.begin();
        while(itMnbRequest != mMnbRecoveryRequests.end()){
            // Allow this mnb to be re-verified again after MNB_RECOVERY_RETRY_SECONDS seconds
            // if mn is still in SECURENODE_NEW_START_REQUIRED state.
            if(GetTime() - itMnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mMnbRecoveryRequests.erase(itMnbRequest++);
            } else {
                ++itMnbRequest;
            }
        }

        // check who's asked for the Securenode list
        std::map<CNetAddr, int64_t>::iterator it1 = mAskedUsForSecurenodeList.begin();
        while(it1 != mAskedUsForSecurenodeList.end()){
            if((*it1).second < GetTime()) {
                mAskedUsForSecurenodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Securenode list
        it1 = mWeAskedForSecurenodeList.begin();
        while(it1 != mWeAskedForSecurenodeList.end()){
            if((*it1).second < GetTime()){
                mWeAskedForSecurenodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Securenodes we've asked for
        auto it2 = mWeAskedForSecurenodeListEntry.begin();
        while(it2 != mWeAskedForSecurenodeListEntry.end()){
            std::map<CNetAddr, int64_t>::iterator it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if(it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if(it2->second.empty()) {
                mWeAskedForSecurenodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        std::map<CNetAddr, CSecurenodeVerification>::iterator it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if(it3->second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenSecurenodeBroadcast entries here, clean them on mnb updates!

        // remove expired mapSeenSecurenodePing
        std::map<uint256, CSecurenodePing>::iterator it4 = mapSeenSecurenodePing.begin();
        while(it4 != mapSeenSecurenodePing.end()){
            if((*it4).second.IsExpired()) {
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove -- Removing expired Securenode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenSecurenodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenSecurenodeVerification
        std::map<uint256, CSecurenodeVerification>::iterator itv2 = mapSeenSecurenodeVerification.begin();
        while(itv2 != mapSeenSecurenodeVerification.end()){
            if((*itv2).second.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS){
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove -- Removing expired Securenode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenSecurenodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckAndRemove -- %s\n", ToString());
    }
}

void CSecurenodeMan::Clear()
{
    LOCK(cs);
    mapSecurenodes.clear();
    mAskedUsForSecurenodeList.clear();
    mWeAskedForSecurenodeList.clear();
    mWeAskedForSecurenodeListEntry.clear();
    mapSeenSecurenodeBroadcast.clear();
    mapSeenSecurenodePing.clear();
    nDsqCount = 0;
    nLastWatchdogVoteTime = 0;
}

int CSecurenodeMan::CountSecurenodes(int nProtocolVersion) const
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = PROTOCOL_VERSION;

    for (auto& mnpair : mapSecurenodes) {
        if(mnpair.second.nProtocolVersion < nProtocolVersion) continue;
        nCount++;
    }

    return nCount;
}

int CSecurenodeMan::CountEnabled(int nProtocolVersion) const
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = PROTOCOL_VERSION;

    for (auto& mnpair : mapSecurenodes) {
        if(mnpair.second.nProtocolVersion < nProtocolVersion || !mnpair.second.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

/* Only IPv4 securenodes are allowed in 12.1, saving this for later
int CSecurenodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    for (auto& mnpair : mapSecurenodes)
        if ((nNetworkType == NET_IPV4 && mnpair.second.addr.IsIPv4()) ||
            (nNetworkType == NET_TOR  && mnpair.second.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && mnpair.second.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}
*/

void CSecurenodeMan::DsegUpdate(CNode* pnode, CConnman& connman)
{
    LOCK(cs);

    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForSecurenodeList.find(pnode->addr);
            if(it != mWeAskedForSecurenodeList.end() && GetTime() < (*it).second) {
                LogPrintf("CSecurenodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", pnode->addr.ToString());
                return;
            }
        }
    }

    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SECURENODESEG, CPubKey()));
    int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
    mWeAskedForSecurenodeList[pnode->addr] = askAgain;

    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CSecurenode* CSecurenodeMan::Find(const CPubKey &pubKeySecurenode)
{
    LOCK(cs);
    auto it = mapSecurenodes.find(pubKeySecurenode);
    return it == mapSecurenodes.end() ? NULL : &(it->second);
}

bool CSecurenodeMan::Get(const CKeyID &pubKeyID, CSecurenode& securenodeRet)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    for (auto& mnpair : mapSecurenodes) {
        CKeyID keyID = mnpair.second.pubKeySecurenode.GetID();
        if (keyID == pubKeyID) {
            securenodeRet = mnpair.second;
            return true;
        }
    }
    return false;
}

bool CSecurenodeMan::Get(const CPubKey &pubKeySecurenode, CSecurenode &securenodeRet)
{
    LOCK(cs);
    auto it = mapSecurenodes.find(pubKeySecurenode);
    if (it == mapSecurenodes.end()) {
        return false;
    }

    securenodeRet = it->second;
    return true;
}

bool CSecurenodeMan::GetSecurenodeInfo(const CPubKey& pubKeySecurenode, securenode_info_t& mnInfoRet)
{
    LOCK(cs);
    auto it = mapSecurenodes.find(pubKeySecurenode);
    if (it == mapSecurenodes.end()) {
        return false;
    }
    mnInfoRet = it->second.GetInfo();
    return true;
}

bool CSecurenodeMan::GetSecurenodeInfo(const CKeyID &pubKeySecurenode, securenode_info_t &mnInfoRet)
{
    LOCK(cs);
    for (auto& mnpair : mapSecurenodes) {
        CKeyID keyID = mnpair.second.pubKeySecurenode.GetID();
        if (keyID == pubKeySecurenode) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CSecurenodeMan::GetSecurenodeInfo(const CScript& payee, securenode_info_t& mnInfoRet)
{
    LOCK(cs);
    for (auto& mnpair : mapSecurenodes) {
        CScript scriptCollateralAddress = GetScriptForDestination(mnpair.second.pubKeySecurenode.GetID());
        if (scriptCollateralAddress == payee) {
            mnInfoRet = mnpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CSecurenodeMan::Has(const CPubKey &pubKeySecurenode)
{
    LOCK(cs);
    return mapSecurenodes.find(pubKeySecurenode) != mapSecurenodes.end();
}

void CSecurenodeMan::ProcessSecurenodeConnections(CConnman& connman)
{
    //we don't care about this for regtest
    if(Params().NetworkIDString() == CBaseChainParams::REGTEST) return;

    connman.ForEachNode([](CNode* pnode) {
        if(pnode->fSecurenode) {
            LogPrintf("Closing Securenode connection: peer=%d, addr=%s\n", pnode->GetId(), pnode->addr.ToString());
            pnode->fDisconnect = true;
        }
    });
}

std::pair<CService, std::set<uint256> > CSecurenodeMan::PopScheduledMnbRequestConnection()
{
    LOCK(cs);
    if(listScheduledMnbRequestConnections.empty()) {
        return std::make_pair(CService(), std::set<uint256>());
    }

    std::set<uint256> setResult;

    listScheduledMnbRequestConnections.sort();
    std::pair<CService, uint256> pairFront = listScheduledMnbRequestConnections.front();

    // squash hashes from requests with the same CService as the first one into setResult
    std::list< std::pair<CService, uint256> >::iterator it = listScheduledMnbRequestConnections.begin();
    while(it != listScheduledMnbRequestConnections.end()) {
        if(pairFront.first == it->first) {
            setResult.insert(it->second);
            it = listScheduledMnbRequestConnections.erase(it);
        } else {
            // since list is sorted now, we can be sure that there is no more hashes left
            // to ask for from this addr
            break;
        }
    }
    return std::make_pair(pairFront.first, setResult);
}


void CSecurenodeMan::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all OCIDE specific functionality

    if (strCommand == NetMsgType::SECURENODEANNOUNCE) { //Securenode Broadcast

        CSecurenodeBroadcast mnb;
        vRecv >> mnb;

        pfrom->setAskFor.erase(mnb.GetHash());

        if(!securenodeSync.IsBlockchainSynced()) return;

        LogPrint(BCLog::SECURENODE, "SECURENODEANNOUNCE -- Securenode announce, securenode=%s\n", mnb.pubKeySecurenode.GetID().ToString());

        int nDos = 0;

        if (CheckMnbAndUpdateSecurenodeList(pfrom, mnb, nDos, connman)) {
            // use announced Securenode as a peer
            connman.AddNewAddresses({CAddress(mnb.addr, NODE_NETWORK)}, pfrom->addr, 2*60*60);
        } else if(nDos > 0) {
            Misbehaving(pfrom->GetId(), nDos);
        }

    } else if (strCommand == NetMsgType::SECURENODEPING) { //Securenode Ping

        CSecurenodePing mnp;
        vRecv >> mnp;

        uint256 nHash = mnp.GetHash();

        pfrom->setAskFor.erase(nHash);

        if(!securenodeSync.IsBlockchainSynced()) return;

        LogPrint(BCLog::SECURENODE, "SECURENODEPING -- Securenode ping, securenode=%s\n", mnp.securePubKey.GetID().ToString());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if(mapSeenSecurenodePing.count(nHash)) return; //seen
        mapSeenSecurenodePing.insert(std::make_pair(nHash, mnp));

        LogPrint(BCLog::SECURENODE, "SECURENODEPING -- Securenode ping, securenode=%s new\n", mnp.securePubKey.GetID().ToString());

        // see if we have this Securenode
        CSecurenode* pmn = Find(mnp.securePubKey);

        // if securenode uses sentinel ping instead of watchdog
        // we shoud update nTimeLastWatchdogVote here if sentinel
        // ping flag is actual
        if(pmn && mnp.fSentinelIsCurrent)
            UpdateWatchdogVoteTime(mnp.securePubKey, mnp.sigTime);

        // too late, new SECURENODEANNOUNCE is required
        if(pmn && pmn->IsExpired()) return;

        int nDos = 0;
        if(mnp.CheckAndUpdate(pmn, false, nDos, connman)) return;

        if(nDos > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDos);
        } else if(pmn != NULL) {
            // nothing significant failed, mn is a known one too
            return;
        }

        // something significant is broken or mn is unknown,
        // we might have to ask for a securenode entry once
        AskForMN(pfrom, mnp.securePubKey, connman);

    } else if (strCommand == NetMsgType::SECURENODESEG) { //Get Securenode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after securenode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!securenodeSync.IsSynced()) return;

        CPubKey pubKeySecurenode;
        vRecv >> pubKeySecurenode;

        LogPrint(BCLog::SECURENODE, "SECURENODESEG -- Securenode list, securenode=%s\n", pubKeySecurenode.GetID().ToString());

        LOCK(cs);

        if(!pubKeySecurenode.IsValid()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if(!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator it = mAskedUsForSecurenodeList.find(pfrom->addr);
                if (it != mAskedUsForSecurenodeList.end() && it->second > GetTime()) {
                    Misbehaving(pfrom->GetId(), 34);
                    LogPrintf("SECURENODESEG -- peer already asked me for the list, peer=%d\n", pfrom->GetId());
                    return;
                }
                int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
                mAskedUsForSecurenodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok

        int nInvCount = 0;

        for (auto& mnpair : mapSecurenodes) {
            if (pubKeySecurenode.IsValid() && pubKeySecurenode != mnpair.second.pubKeySecurenode) continue; // asked for specific vin but we are not there yet
            if (mnpair.second.addr.IsRFC1918() || mnpair.second.addr.IsLocal()) continue; // do not send local network securenode
            if (mnpair.second.IsUpdateRequired()) continue; // do not send outdated securenodes

            CSecurenodeBroadcast mnb = CSecurenodeBroadcast(mnpair.second);
            LogPrint(BCLog::SECURENODE, "SECURENODESEG -- Sending Securenode entry: securenode=%s  addr=%s\n",
                     mnb.pubKeySecurenode.GetID().ToString(), mnb.addr.ToString());
            CSecurenodePing mnp = mnpair.second.lastPing;
            uint256 hashMNB = mnb.GetHash();
            uint256 hashMNP = mnp.GetHash();
            pfrom->PushInventory(CInv(MSG_SECURENODE_ANNOUNCE, hashMNB));
            pfrom->PushInventory(CInv(MSG_SECURENODE_PING, hashMNP));
            nInvCount++;

            mapSeenSecurenodeBroadcast.insert(std::make_pair(hashMNB, std::make_pair(GetTime(), mnb)));
            mapSeenSecurenodePing.insert(std::make_pair(hashMNP, mnp));

            if (pubKeySecurenode == mnpair.first) {
                LogPrintf("SECURENODESEG -- Sent 1 Securenode inv to peer %d\n", pfrom->GetId());
                return;
            }
        }

        if(!pubKeySecurenode.IsValid()) {
            connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(
                                    NetMsgType::SECURESYNCSTATUSCOUNT, SECURENODE_SYNC_LIST, nInvCount));
            LogPrintf("SECURENODESEG -- Sent %d Securenode invs to peer %d\n", nInvCount, pfrom->GetId());
            return;
        }
        // smth weird happen - someone asked us for vin we have no idea about?
        LogPrint(BCLog::SECURENODE, "SECURENODESEG -- No invs sent to peer %d\n", pfrom->GetId());

    } else if (strCommand == NetMsgType::SECURENODEVERIFY) { // Securenode Verify

        // Need LOCK2 here to ensure consistent locking order because the all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CSecurenodeVerification mnv;
        vRecv >> mnv;

        pfrom->setAskFor.erase(mnv.GetHash());

        if(!securenodeSync.IsSecurenodeListSynced()) return;

        if(mnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, mnv, connman);
        } else if (mnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some securenode
            ProcessVerifyReply(pfrom, mnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some securenode which verified another one
            ProcessVerifyBroadcast(pfrom, mnv);
        }
    }
}

// Verification of securenodes via unique direct requests.

void CSecurenodeMan::DoFullVerificationStep(CConnman& connman)
{
    if(!activeSecurenode.pubKeySecurenode.IsValid()) return;
    if(!securenodeSync.IsSynced()) return;

#if 0
    // Need LOCK2 here to ensure consistent locking order because the SendVerifyRequest call below locks cs_main
    // through GetHeight() signal in ConnectNode
    LOCK2(cs_main, cs);

    int nCount = 0;

    // send verify requests only if we are in top MAX_POSE_RANK
    std::vector<std::pair<int, CSecurenode> >::iterator it = vecSecurenodeRanks.begin();
    while(it != vecSecurenodeRanks.end()) {
        if(it->first > MAX_POSE_RANK) {
            LogPrint(BCLog::SECURENODE, "CSecurenodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                     (int)MAX_POSE_RANK);
            return;
        }
        if(it->second.vin.prevout == activeSecurenode.outpoint) {
            nMyRank = it->first;
            LogPrint(BCLog::SECURENODE, "CSecurenodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d securenodes\n",
                     nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
        ++it;
    }

    // edge case: list is too short and this securenode is not enabled
    if(nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS securenodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if(nOffset >= (int)vecSecurenodeRanks.size()) return;

    std::vector<CSecurenode*> vSortedByAddr;
    for (auto& mnpair : mapSecurenodes) {
        vSortedByAddr.push_back(&mnpair.second);
    }

    sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    it = vecSecurenodeRanks.begin() + nOffset;
    while(it != vecSecurenodeRanks.end()) {
        if(it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            LogPrint(BCLog::SECURENODE, "CSecurenodeMan::DoFullVerificationStep -- Already %s%s%s securenode %s address %s, skipping...\n",
                     it->second.IsPoSeVerified() ? "verified" : "",
                     it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
                     it->second.IsPoSeBanned() ? "banned" : "",
                     it->second.vin.prevout.ToStringShort(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if(nOffset >= (int)vecSecurenodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::DoFullVerificationStep -- Verifying securenode %s rank %d/%d address %s\n",
                 it->second.vin.prevout.ToStringShort(), it->first, nRanksTotal, it->second.addr.ToString());
        if(SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr, connman)) {
            nCount++;
            if(nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if(nOffset >= (int)vecSecurenodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }


    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::DoFullVerificationStep -- Sent verification requests to %d securenodes\n", nCount);
#endif
}

// This function tries to find securenodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CSecurenodeMan::CheckSameAddr()
{
    if(!securenodeSync.IsSynced() || mapSecurenodes.empty()) return;

    std::vector<CSecurenode*> vBan;
    std::vector<CSecurenode*> vSortedByAddr;

    {
        LOCK(cs);

        CSecurenode* pprevSecurenode = NULL;
        CSecurenode* pverifiedSecurenode = NULL;

        for (auto& mnpair : mapSecurenodes) {
            vSortedByAddr.push_back(&mnpair.second);
        }

        sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        for(CSecurenode* pmn : vSortedByAddr) {
            // check only (pre)enabled securenodes
            if(!pmn->IsEnabled() && !pmn->IsPreEnabled()) continue;
            // initial step
            if(!pprevSecurenode) {
                pprevSecurenode = pmn;
                pverifiedSecurenode = pmn->IsPoSeVerified() ? pmn : NULL;
                continue;
            }
            // second+ step
            if(pmn->addr == pprevSecurenode->addr) {
                if(pverifiedSecurenode) {
                    // another securenode with the same ip is verified, ban this one
                    vBan.push_back(pmn);
                } else if(pmn->IsPoSeVerified()) {
                    // this securenode with the same ip is verified, ban previous one
                    vBan.push_back(pprevSecurenode);
                    // and keep a reference to be able to ban following securenodes with the same ip
                    pverifiedSecurenode = pmn;
                }
            } else {
                pverifiedSecurenode = pmn->IsPoSeVerified() ? pmn : NULL;
            }
            pprevSecurenode = pmn;
        }
    }

    // ban duplicates
    for(CSecurenode* pmn : vBan) {
        LogPrintf("CSecurenodeMan::CheckSameAddr -- increasing PoSe ban score for securenode %s\n",
                  pmn->pubKeySecurenode.GetID().ToString());
        pmn->IncreasePoSeBanScore();
    }
}

bool CSecurenodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<CSecurenode*>& vSortedByAddr, CConnman& connman)
{
    if(netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::SECURENODEVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    CNode* pnode = connman.OpenSecurenodeConnection(addr);
    if(!pnode) {
        LogPrintf("CSecurenodeMan::SendVerifyRequest -- can't connect to node to verify it, addr=%s\n", addr.ToString());
        return false;
    }

    netfulfilledman.AddFulfilledRequest(addr, strprintf("%s", NetMsgType::SECURENODEVERIFY)+"-request");
    // use random nonce, store it and require node to reply with correct one later
    CSecurenodeVerification mnv(addr, GetRandInt(999999), nCachedBlockHeight - 1);
    mWeAskedForVerification[addr] = mnv;
    LogPrintf("CSecurenodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", mnv.nonce, addr.ToString());
    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SECURENODEVERIFY, mnv));

    return true;
}

void CSecurenodeMan::SendVerifyReply(CNode* pnode, CSecurenodeVerification& mnv, CConnman& connman)
{
    // only securenodes can sign this, why would someone ask regular node?
    if(!fSecureNode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::SECURENODEVERIFY)+"-reply")) {
        // peer should not ask us that often
        LogPrintf("SecurenodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        LogPrintf("SecurenodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    std::string strMessage = strprintf("%s%d%s", activeSecurenode.service.ToString(false), mnv.nonce, blockHash.ToString());

    if(!CMessageSigner::SignMessage(strMessage, mnv.vchSig1, activeSecurenode.keySecurenode, CPubKey::InputScriptType::SPENDP2PKH)) {
        LogPrintf("SecurenodeMan::SendVerifyReply -- SignMessage() failed\n");
        return;
    }

    std::string strError;

    if(!CMessageSigner::VerifyMessage(activeSecurenode.pubKeySecurenode.GetID(), mnv.vchSig1, strMessage, strError)) {
        LogPrintf("SecurenodeMan::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
        return;
    }

    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SECURENODEVERIFY, mnv));
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::SECURENODEVERIFY)+"-reply");
}

void CSecurenodeMan::ProcessVerifyReply(CNode* pnode, CSecurenodeVerification& mnv)
{
    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if(!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::SECURENODEVERIFY)+"-request")) {
        LogPrintf("CSecurenodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    // Received nonce for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nonce != mnv.nonce) {
        LogPrintf("CSecurenodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                  mWeAskedForVerification[pnode->addr].nonce, mnv.nonce, pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nBlockHeight != mnv.nBlockHeight) {
        LogPrintf("CSecurenodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                  mWeAskedForVerification[pnode->addr].nBlockHeight, mnv.nBlockHeight, pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }



    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("SecurenodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    // we already verified this address, why node is spamming?
    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::SECURENODEVERIFY)+"-done")) {
        LogPrintf("CSecurenodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    {
        LOCK(cs);

        CSecurenode* prealSecurenode = NULL;
        std::vector<CSecurenode*> vpSecurenodesToBan;
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(false), mnv.nonce, blockHash.ToString());
        for (auto& mnpair : mapSecurenodes) {
            if(CAddress(mnpair.second.addr, NODE_NETWORK) == pnode->addr) {
                if(CMessageSigner::VerifyMessage(mnpair.second.pubKeySecurenode.GetID(), mnv.vchSig1, strMessage1, strError)) {
                    // found it!
                    prealSecurenode = &mnpair.second;
                    if(!mnpair.second.IsPoSeVerified()) {
                        mnpair.second.DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::SECURENODEVERIFY)+"-done");

                    // we can only broadcast it if we are an activated securenode
                    if(!activeSecurenode.pubKeySecurenode.IsValid()) continue;
                    // update ...
                    mnv.addr = mnpair.second.addr;
                    mnv.pubKeySecurenode1 = mnpair.second.pubKeySecurenode;
                    mnv.pubKeySecurenode2 = activeSecurenode.pubKeySecurenode;
                    std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(false), mnv.nonce, blockHash.ToString(),
                                                        HexStr(mnv.pubKeySecurenode1.Raw()), HexStr(mnv.pubKeySecurenode2.Raw()));
                    // ... and sign it
                    if(!CMessageSigner::SignMessage(strMessage2, mnv.vchSig2, activeSecurenode.keySecurenode, CPubKey::InputScriptType::SPENDP2PKH)) {
                        LogPrintf("SecurenodeMan::ProcessVerifyReply -- SignMessage() failed\n");
                        return;
                    }

                    std::string strError;

                    if(!CMessageSigner::VerifyMessage(activeSecurenode.pubKeySecurenode.GetID(), mnv.vchSig2, strMessage2, strError)) {
                        LogPrintf("SecurenodeMan::ProcessVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
                        return;
                    }

                    mWeAskedForVerification[pnode->addr] = mnv;
                    mapSeenSecurenodeVerification.insert(std::make_pair(mnv.GetHash(), mnv));
                    mnv.Relay();

                } else {
                    vpSecurenodesToBan.push_back(&mnpair.second);
                }
            }
        }
        // no real securenode found?...
        if(!prealSecurenode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            LogPrintf("CSecurenodeMan::ProcessVerifyReply -- ERROR: no real securenode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->GetId(), 20);
            return;
        }
        LogPrintf("CSecurenodeMan::ProcessVerifyReply -- verified real securenode %s for addr %s\n",
                  prealSecurenode->pubKeySecurenode.GetID().ToString(), pnode->addr.ToString());
        // increase ban score for everyone else
        for(CSecurenode* pmn : vpSecurenodesToBan) {
            pmn->IncreasePoSeBanScore();
            LogPrint(BCLog::SECURENODE, "CSecurenodeMan::ProcessVerifyReply -- increased PoSe ban score for %s addr %s, new score %d\n",
                     prealSecurenode->pubKeySecurenode.GetID().ToString(), pnode->addr.ToString(), pmn->nPoSeBanScore);
        }
        if(!vpSecurenodesToBan.empty())
            LogPrintf("CSecurenodeMan::ProcessVerifyReply -- PoSe score increased for %d fake securenodes, addr %s\n",
                      (int)vpSecurenodesToBan.size(), pnode->addr.ToString());
    }
}

void CSecurenodeMan::ProcessVerifyBroadcast(CNode* pnode, const CSecurenodeVerification& mnv)
{
    std::string strError;

    if(mapSeenSecurenodeVerification.find(mnv.GetHash()) != mapSeenSecurenodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenSecurenodeVerification[mnv.GetHash()] = mnv;

    // we don't care about history
    if(mnv.nBlockHeight < nCachedBlockHeight - MAX_POSE_BLOCKS) {
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                 nCachedBlockHeight, mnv.nBlockHeight, pnode->GetId());
        return;
    }

    if(mnv.pubKeySecurenode1 == mnv.pubKeySecurenode2) {
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::ProcessVerifyBroadcast -- ERROR: same vins %s, peer=%d\n",
                 mnv.pubKeySecurenode1.GetID().ToString(), pnode->GetId());
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->GetId(), 100);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    int nRank;

#if 0
    if (!GetSecurenodeRank(mnv.vin2.prevout, nRank, mnv.nBlockHeight, MIN_POSE_PROTO_VERSION)) {
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::ProcessVerifyBroadcast -- Can't calculate rank for securenode %s\n",
                 mnv.vin2.prevout.ToStringShort());
        return;
    }
#endif

    if(nRank > MAX_POSE_RANK) {
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::ProcessVerifyBroadcast -- Securenode %s is not in top %d, current rank %d, peer=%d\n",
                 mnv.pubKeySecurenode2.GetID().ToString(), (int)MAX_POSE_RANK, nRank, pnode->GetId());
        return;
    }

    {
        LOCK(cs);

        std::string strMessage1 = strprintf("%s%d%s", mnv.addr.ToString(false), mnv.nonce, blockHash.ToString());
        std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(false), mnv.nonce, blockHash.ToString(),
                                            HexStr(mnv.pubKeySecurenode1.Raw()), HexStr(mnv.pubKeySecurenode2.Raw()));

        CSecurenode* pmn1 = Find(mnv.pubKeySecurenode1);
        if(!pmn1) {
            LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- can't find securenode1 %s\n",
                      mnv.pubKeySecurenode1.GetID().ToString());
            return;
        }

        CSecurenode* pmn2 = Find(mnv.pubKeySecurenode2);
        if(!pmn2) {
            LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- can't find securenode2 %s\n",
                      mnv.pubKeySecurenode2.GetID().ToString());
            return;
        }

        if(pmn1->addr != mnv.addr) {
            LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- addr %s does not match %s\n", mnv.addr.ToString(), pmn1->addr.ToString());
            return;
        }

        if(!CMessageSigner::VerifyMessage(pmn1->pubKeySecurenode.GetID(), mnv.vchSig1, strMessage1, strError)) {
            LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- VerifyMessage() for securenode1 failed, error: %s\n", strError);
            return;
        }

        if(!CMessageSigner::VerifyMessage(pmn2->pubKeySecurenode.GetID(), mnv.vchSig2, strMessage2, strError)) {
            LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- VerifyMessage() for securenode2 failed, error: %s\n", strError);
            return;
        }

        if(!pmn1->IsPoSeVerified()) {
            pmn1->DecreasePoSeBanScore();
        }
        mnv.Relay();

        LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- verified securenode %s for addr %s\n",
                  pmn1->pubKeySecurenode.GetID().ToString(), pmn1->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        for (auto& mnpair : mapSecurenodes) {
            if(mnpair.second.addr != mnv.addr || mnpair.first == mnv.pubKeySecurenode1) continue;
            mnpair.second.IncreasePoSeBanScore();
            nCount++;
            LogPrint(BCLog::SECURENODE, "CSecurenodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                     mnpair.first.GetID().ToString(), mnpair.second.addr.ToString(), mnpair.second.nPoSeBanScore);
        }
        if(nCount)
            LogPrintf("CSecurenodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake securenodes, addr %s\n",
                      nCount, pmn1->addr.ToString());
    }
}

std::string CSecurenodeMan::ToString() const
{
    std::ostringstream info;

    info << "Securenodes: " << (int)mapSecurenodes.size() <<
            ", peers who asked us for Securenode list: " << (int)mAskedUsForSecurenodeList.size() <<
            ", peers we asked for Securenode list: " << (int)mWeAskedForSecurenodeList.size() <<
            ", entries in Securenode list we asked for: " << (int)mWeAskedForSecurenodeListEntry.size() <<
            ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}

void CSecurenodeMan::UpdateSecurenodeList(CSecurenodeBroadcast mnb, CConnman& connman)
{
    LOCK2(cs_main, cs);
    mapSeenSecurenodePing.insert(std::make_pair(mnb.lastPing.GetHash(), mnb.lastPing));
    mapSeenSecurenodeBroadcast.insert(std::make_pair(mnb.GetHash(), std::make_pair(GetTime(), mnb)));

    LogPrintf("CSecurenodeMan::UpdateSecurenodeList -- securenode=%s  addr=%s\n", mnb.pubKeySecurenode.GetID().ToString(), mnb.addr.ToString());

    CSecurenode* pmn = Find(mnb.pubKeySecurenode);
    if(pmn == NULL) {

        if(Add(mnb)) {
            securenodeSync.BumpAssetLastTime("CSecurenodeMan::UpdateSecurenodeList - new");
        }
    } else {
        CSecurenodeBroadcast mnbOld = mapSeenSecurenodeBroadcast[CSecurenodeBroadcast(*pmn).GetHash()].second;
        if(pmn->UpdateFromNewBroadcast(mnb, connman)) {
            securenodeSync.BumpAssetLastTime("CSecurenodeMan::UpdateSecurenodeList - seen");
            mapSeenSecurenodeBroadcast.erase(mnbOld.GetHash());
        }
    }
}

bool CSecurenodeMan::CheckMnbAndUpdateSecurenodeList(CNode* pfrom, CSecurenodeBroadcast mnb, int& nDos, CConnman& connman)
{
    {
        // we need to lock in this order because function that called us uses same order, bad practice, but no other choice because of recursive mutexes.
        LOCK2(cs_main, cs);
        nDos = 0;
        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- securenode=%s\n", mnb.pubKeySecurenode.GetID().ToString());

        uint256 hash = mnb.GetHash();
        if(mapSeenSecurenodeBroadcast.count(hash) && !mnb.fRecovery) { //seen
            LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- securenode=%s seen\n",
                     mnb.pubKeySecurenode.GetID().ToString());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if(GetTime() - mapSeenSecurenodeBroadcast[hash].first > SECURENODE_NEW_START_REQUIRED_SECONDS - SECURENODE_MIN_MNP_SECONDS * 2) {
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- securenode=%s seen update\n",
                         mnb.pubKeySecurenode.GetID().ToString());
                mapSeenSecurenodeBroadcast[hash].first = GetTime();
                securenodeSync.BumpAssetLastTime("CSecurenodeMan::CheckMnbAndUpdateSecurenodeList - seen");
            }
            // did we ask this node for it?
            if(pfrom && IsMnbRecoveryRequested(hash) && GetTime() < mMnbRecoveryRequests[hash].first) {
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- mnb=%s seen request\n", hash.ToString());
                if(mMnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- mnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same mnb multiple times in recovery mode
                    mMnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if(mnb.lastPing.sigTime > mapSeenSecurenodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CSecurenode mnTemp = CSecurenode(mnb);
                        mnTemp.Check();
                        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- mnb=%s seen request, addr=%s, better lastPing: %d min ago, projected mn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetAdjustedTime() - mnb.lastPing.sigTime)/60, mnTemp.GetStateString());
                        if(mnTemp.IsValidStateForAutoStart(mnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- securenode=%s seen good\n",
                                     mnb.pubKeySecurenode.GetID().ToString());
                            mMnbRecoveryGoodReplies[hash].push_back(mnb);
                        }
                    }
                }
            }
            return true;
        }
        mapSeenSecurenodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));

        LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- securenode=%s new\n",
                 mnb.pubKeySecurenode.GetID().ToString());

        {
            // Need to lock cs_main here to ensure consistent locking order because the SimpleCheck call below locks cs_main
//            LOCK(cs_main);
            if(!mnb.SimpleCheck(nDos)) {
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- SimpleCheck() failed, securenode=%s\n",
                         mnb.pubKeySecurenode.GetID().ToString());
                return false;
            }
        }

        // search Securenode list
        CSecurenode* pmn = Find(mnb.pubKeySecurenode);
        if(pmn) {
            CSecurenodeBroadcast mnbOld = mapSeenSecurenodeBroadcast[CSecurenodeBroadcast(*pmn).GetHash()].second;
            if(!mnb.Update(pmn, nDos, connman)) {
                LogPrint(BCLog::SECURENODE, "CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- Update() failed, securenode=%s\n",
                         mnb.pubKeySecurenode.GetID().ToString());
                return false;
            }
            if(hash != mnbOld.GetHash()) {
                mapSeenSecurenodeBroadcast.erase(mnbOld.GetHash());
            }
            return true;
        }
    }

    if(mnb.CheckSecurenode(nDos)) {

        Add(mnb);
        securenodeSync.BumpAssetLastTime("CSecurenodeMan::CheckMnbAndUpdateSecurenodeList - new");
        // if it matches our Securenode privkey...
        if(fSecureNode && mnb.pubKeySecurenode == activeSecurenode.pubKeySecurenode) {
            mnb.nPoSeBanScore = -SECURENODE_POSE_BAN_MAX_SCORE;
            if(mnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                LogPrintf("CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- Got NEW Securenode entry: securenode=%s  sigTime=%lld  addr=%s\n",
                          mnb.pubKeySecurenode.GetID().ToString(), mnb.sigTime, mnb.addr.ToString());
                activeSecurenode.ManageState(connman);
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                LogPrintf("CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", mnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        mnb.Relay(connman);
    } else {
        LogPrintf("CSecurenodeMan::CheckMnbAndUpdateSecurenodeList -- Rejected Securenode entry: %s  addr=%s\n",
                  mnb.pubKeySecurenode.GetID().ToString(), mnb.addr.ToString());
        return false;
    }

    return true;
}

void CSecurenodeMan::UpdateWatchdogVoteTime(const CPubKey &pubKeySecurenode, uint64_t nVoteTime)
{
    LOCK(cs);
    CSecurenode* pmn = Find(pubKeySecurenode);
    if(!pmn) {
        return;
    }
    pmn->UpdateWatchdogVoteTime(nVoteTime);
    nLastWatchdogVoteTime = GetTime();
}

bool CSecurenodeMan::IsWatchdogActive()
{
    LOCK(cs);
    // Check if any securenodes have voted recently, otherwise return false
    return (GetTime() - nLastWatchdogVoteTime) <= SECURENODE_WATCHDOG_MAX_SECONDS;
}

void CSecurenodeMan::CheckSecurenode(const CPubKey& pubKeySecurenode, bool fForce)
{
    LOCK2(cs_main, cs);
    for (auto& mnpair : mapSecurenodes) {
        if (mnpair.second.pubKeySecurenode == pubKeySecurenode) {
            mnpair.second.Check(fForce);
            return;
        }
    }
}

bool CSecurenodeMan::IsSecurenodePingedWithin(const CPubKey &pubKeySecurenode, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CSecurenode* pmn = Find(pubKeySecurenode);
    return pmn ? pmn->IsPingedWithin(nSeconds, nTimeToCheckAt) : false;
}

void CSecurenodeMan::SetSecurenodeLastPing(const CPubKey &pubKeySecurenode, const CSecurenodePing& mnp)
{
    LOCK(cs);
    CSecurenode* pmn = Find(pubKeySecurenode);
    if(!pmn) {
        return;
    }
    pmn->lastPing = mnp;
    // if securenode uses sentinel ping instead of watchdog
    // we shoud update nTimeLastWatchdogVote here if sentinel
    // ping flag is actual
    if(mnp.fSentinelIsCurrent) {
        UpdateWatchdogVoteTime(mnp.securePubKey, mnp.sigTime);
    }
    mapSeenSecurenodePing.insert(std::make_pair(mnp.GetHash(), mnp));

    CSecurenodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if(mapSeenSecurenodeBroadcast.count(hash)) {
        mapSeenSecurenodeBroadcast[hash].second.lastPing = mnp;
    }
}

void CSecurenodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    nCachedBlockHeight = pindex->nHeight;
    LogPrint(BCLog::SECURENODE, "CSecurenodeMan::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    CheckSameAddr();
}

void ThreadSecurenodeCheck(CConnman &connman)
{
    if(fLiteMode) return; // disable all OCIDE specific functionality

    static bool fOneThread;
    if(fOneThread) return;
    fOneThread = true;

    RenameThread("ocide-spos");

    unsigned int nTick = 0;

    while (true)
    {
        MilliSleep(1000);

        // try to sync from all available nodes, one step at a time
        securenodeSync.ProcessTick(connman);

        if(securenodeSync.IsBlockchainSynced() && !ShutdownRequested()) {

            nTick++;

            // make sure to check all securenodes first
            securenodeman.Check();

            // check if we should activate or ping every few minutes,
            // slightly postpone first run to give net thread a chance to connect to some peers
            if(nTick % SECURENODE_MIN_MNP_SECONDS == 15)
                activeSecurenode.ManageState(connman);

            if(nTick % 60 == 0) {
                securenodeman.ProcessSecurenodeConnections(connman);
                securenodeman.CheckAndRemove(connman);
            }
            if(fSecureNode && (nTick % (60 * 5) == 0)) {
                securenodeman.DoFullVerificationStep(connman);
            }
        }
    }

}
