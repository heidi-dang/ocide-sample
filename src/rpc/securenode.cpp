// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <spos/activesecurenode.h>
#include <key_io.h>
#include <init.h>
#include <netbase.h>
#include <validation.h>
#include <spos/securenode-sync.h>
#include <spos/securenodeman.h>
#include <spos/securenode.h>
#include <spos/securenodeconfig.h>
#include <rpc/server.h>
#include <util.h>
#include <utilmoneystr.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif
#include <core_io.h>
#include <key_io.h>

#include <fstream>
#include <iomanip>
#include <univalue.h>

static UniValue securesync(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
                "securesync [status|next|reset]\n"
                "Returns the sync status, updates to the next step or resets it entirely.\n"
                );

    std::string strMode = request.params[0].get_str();

    if(strMode == "status") {
        UniValue objStatus(UniValue::VOBJ);
        objStatus.push_back(Pair("AssetID", securenodeSync.GetAssetID()));
        objStatus.push_back(Pair("AssetName", securenodeSync.GetAssetName()));
        objStatus.push_back(Pair("AssetStartTime", securenodeSync.GetAssetStartTime()));
        objStatus.push_back(Pair("Attempt", securenodeSync.GetAttempt()));
        objStatus.push_back(Pair("IsBlockchainSynced", securenodeSync.IsBlockchainSynced()));
        objStatus.push_back(Pair("IsMasternodeListSynced", securenodeSync.IsSecurenodeListSynced()));
        objStatus.push_back(Pair("IsSynced", securenodeSync.IsSynced()));
        objStatus.push_back(Pair("IsFailed", securenodeSync.IsFailed()));
        return objStatus;
    }

    if(strMode == "next")
    {
        securenodeSync.SwitchToNextAsset(*g_connman);
        return "sync updated to " + securenodeSync.GetAssetName();
    }

    if(strMode == "reset")
    {
        securenodeSync.Reset();
        securenodeSync.SwitchToNextAsset(*g_connman);
        return "success";
    }
    return "failure";
}


static UniValue ListOfSecureNodes(const UniValue& params, std::set<CService> mySecureNodesIps, bool showOnlyMine)
{
    std::string strMode = "status";
    std::string strFilter = "";

    if (params.size() >= 1) strMode = params[0].get_str();
    if (params.size() == 2) strFilter = params[1].get_str();

    UniValue obj(UniValue::VOBJ);

    auto mapSecurenodes = securenodeman.GetFullSecurenodeMap();
    for (auto& mnpair : mapSecurenodes) {

        if(showOnlyMine && mySecureNodesIps.count(mnpair.second.addr) == 0) {
            continue;
        }

        CSecurenode mn = mnpair.second;
        std::string strOutpoint = HexStr(mnpair.first.GetID().ToString());
        if (strMode == "activeseconds") {
            if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, (int64_t)(mn.lastPing.sigTime - mn.sigTime)));
        } else if (strMode == "addr") {
            std::string strAddress = mn.addr.ToString();
            if (strFilter !="" && strAddress.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, strAddress));
        } else if (strMode == "full") {
            std::ostringstream streamFull;
            streamFull << std::setw(18) <<
                          mn.GetStatus() << " " <<
                          mn.nProtocolVersion << " " <<
                          CBitcoinAddress(mn.pubKeySecurenode.GetID()).ToString() << " " <<
                          mn.hashSPoSContractTx.ToString() << " " <<
                          (int64_t)mn.lastPing.sigTime << " " << std::setw(8) <<
                          (int64_t)(mn.lastPing.sigTime - mn.sigTime) << " " << std::setw(10) <<
                          mn.addr.ToString();
            std::string strFull = streamFull.str();
            if (strFilter !="" && strFull.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, strFull));
        } else if (strMode == "info") {
            std::ostringstream streamInfo;
            streamInfo << std::setw(18) <<
                          mn.GetStatus() << " " <<
                          mn.nProtocolVersion << " " <<
                          CBitcoinAddress(mn.pubKeySecurenode.GetID()).ToString() << " " <<
                          (int64_t)mn.lastPing.sigTime << " " << std::setw(8) <<
                          (int64_t)(mn.lastPing.sigTime - mn.sigTime) << " " <<
                          (mn.lastPing.fSentinelIsCurrent ? "current" : "expired") << " " <<
                          mn.addr.ToString();
            std::string strInfo = streamInfo.str();
            if (strFilter !="" && strInfo.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, strInfo));
        } else if (strMode == "lastseen") {
            if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, (int64_t)mn.lastPing.sigTime));
        } else if (strMode == "payee") {
            CBitcoinAddress address(mn.pubKeySecurenode.GetID());
            std::string strPayee = address.ToString();
            if (strFilter !="" && strPayee.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, strPayee));
        } else if (strMode == "protocol") {
            if (strFilter !="" && strFilter != strprintf("%d", mn.nProtocolVersion) &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, (int64_t)mn.nProtocolVersion));
        } else if (strMode == "pubkey") {
            if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, HexStr(mn.pubKeySecurenode)));
        } else if (strMode == "status") {
            std::string strStatus = mn.GetStatus();
            if (strFilter !="" && strStatus.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, strStatus));
        }
    }

    return obj;
}

static UniValue securenodelist(const JSONRPCRequest& request)
{
    std::string strMode = "status";
    std::string strFilter = "";

    if (request.params.size() >= 1) strMode = request.params[0].get_str();
    if (request.params.size() == 2) strFilter = request.params[1].get_str();

    if (request.fHelp || (
                strMode != "activeseconds" && strMode != "addr" && strMode != "full" && strMode != "info" &&
                strMode != "lastseen" && strMode != "lastpaidtime" && strMode != "lastpaidblock" &&
                strMode != "protocol" && strMode != "payee" && strMode != "pubkey" &&
                strMode != "rank" && strMode != "status"))
    {
        throw std::runtime_error(
                    "securenodelist ( \"mode\" \"filter\" )\n"
                    "Get a list of securenodes in different modes\n"
                    "\nArguments:\n"
                    "1. \"mode\"      (string, optional/required to use filter, defaults = status) The mode to run list in\n"
                    "2. \"filter\"    (string, optional) Filter results. Partial match by outpoint by default in all modes,\n"
                    "                                    additional matches in some modes are also available\n"
                    "\nAvailable modes:\n"
                    "  activeseconds  - Print number of seconds securenode recognized by the network as enabled\n"
                    "                   (since latest issued \"securenode start/start-many/start-alias\")\n"
                    "  addr           - Print ip address associated with a securenode (can be additionally filtered, partial match)\n"
                    "  full           - Print info in format 'status protocol payee lastseen activeseconds lastpaidtime lastpaidblock IP'\n"
                    "                   (can be additionally filtered, partial match)\n"
                    "  info           - Print info in format 'status protocol payee lastseen activeseconds sentinelversion sentinelstate IP'\n"
                    "                   (can be additionally filtered, partial match)\n"
                    "  lastpaidblock  - Print the last block height a node was paid on the network\n"
                    "  lastpaidtime   - Print the last time a node was paid on the network\n"
                    "  lastseen       - Print timestamp of when a securenode was last seen on the network\n"
                    "  payee          - Print OCIDE address associated with a securenode (can be additionally filtered,\n"
                    "                   partial match)\n"
                    "  protocol       - Print protocol of a securenode (can be additionally filtered, exact match)\n"
                    "  pubkey         - Print the securenode (not collateral) public key\n"
                    "  rank           - Print rank of a securenode based on current block\n"
                    "  status         - Print securenode status: PRE_ENABLED / ENABLED / EXPIRED / WATCHDOG_EXPIRED / NEW_START_REQUIRED /\n"
                    "                   UPDATE_REQUIRED / POSE_BAN / OUTPOINT_SPENT (can be additionally filtered, partial match)\n"
                    );
    }

    if (strMode == "full" || strMode == "lastpaidtime" || strMode == "lastpaidblock") {
        CBlockIndex* pindex = NULL;
        {
            LOCK(cs_main);
            pindex = chainActive.Tip();
        }
    }

    std::set<CService> mySecureNodesIps;
    return  ListOfSecureNodes(request.params, mySecureNodesIps, false);
}

static UniValue securenode(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    auto pwallet = GetWalletForJSONRPCRequest(request);
#endif
    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

#ifdef ENABLE_WALLET
    if (strCommand == "start-many")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "DEPRECATED, please use start-all instead");
#endif // ENABLE_WALLET

    if (request.fHelp  ||
            (
            #ifdef ENABLE_WALLET
                strCommand != "start-alias" && strCommand != "start-all" && strCommand != "start-missing" &&
                strCommand != "start-disabled" && strCommand != "outputs" &&
            #endif // ENABLE_WALLET
                strCommand != "list" && strCommand != "list-conf" && strCommand != "list-mine" && strCommand != "count" &&
                strCommand != "debug" && strCommand != "current" && strCommand != "winner" && strCommand != "winners" && strCommand != "genkey" &&
                strCommand != "connect" && strCommand != "status"))
        throw std::runtime_error(
                "securenode \"command\"...\n"
                "Set of commands to execute securenode related actions\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "\nAvailable commands:\n"
                "  count        - Print number of all known securenodes (optional: 'ps', 'enabled', 'all', 'qualify')\n"
                "  current      - Print info on current securenode winner to be paid the next block (calculated locally)\n"
                "  genkey       - Generate new securenodeprivkey\n"
            #ifdef ENABLE_WALLET
                "  outputs      - Print securenode compatible outputs\n"
                "  start-alias  - Start single remote securenode by assigned alias configured in securenode.conf\n"
                "  start-<mode> - Start remote securenodes configured in securenode.conf (<mode>: 'all', 'missing', 'disabled')\n"
            #endif // ENABLE_WALLET
                "  status       - Print securenode status information\n"
                "  list         - Print list of all known securenodes (see securenodelist for more info)\n"
                "  list-conf    - Print securenode.conf in JSON format\n"
                "  list-mine    - Print own nodes"
                "  winner       - Print info on next securenode winner to vote for\n"
                "  winners      - Print list of securenode winners\n"
                );

    if (strCommand == "list")
    {
        UniValue newParams(UniValue::VARR);
        // forward request.params but skip "list"
        for (unsigned int i = 1; i < request.params.size(); i++) {
            newParams.push_back(request.params[i]);
        }

        auto newRequest = request;
        newRequest.params = newParams;

        return securenodelist(newRequest);
    }

    if(strCommand == "list-mine")
    {
        UniValue newParams(UniValue::VARR);
        // forward request.params but skip "list-mine"
        for (unsigned int i = 1; i < request.params.size(); i++) {
            newParams.push_back(request.params[i]);
        }

        std::set<CService> mySecureNodesIps;
        for(auto &&mne : securenodeConfig.getEntries())
        {
            CService service;
            Lookup(mne.getIp().c_str(), service, 0, false);

            mySecureNodesIps.insert(service);
        }

        return  ListOfSecureNodes(newParams, mySecureNodesIps, true);
    }

    if (strCommand == "list-conf")
    {
        UniValue resultObj(UniValue::VARR);

        for(auto &&mne : securenodeConfig.getEntries())
        {
            CSecurenode mn;
            CKey privKey = DecodeSecret(mne.getSecurePrivKey());
            CPubKey pubKey = privKey.GetPubKey();
            bool fFound = securenodeman.Get(pubKey, mn);

            std::string strStatus = fFound ? mn.GetStatus() : "MISSING";

            UniValue mnObj(UniValue::VOBJ);
            mnObj.push_back(Pair("alias", mne.getAlias()));
            mnObj.push_back(Pair("address", mne.getIp()));
            mnObj.push_back(Pair("privateKey", mne.getSecurePrivKey()));
            mnObj.push_back(Pair("status", strStatus));
            resultObj.push_back(mnObj);
        }

        return resultObj;
    }

    if(strCommand == "connect")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Securenode address required");

        std::string strAddress = request.params[1].get_str();

        CService addr;
        if (!Lookup(strAddress.c_str(), addr, 0, false))
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Incorrect securenode address %s", strAddress));

        // TODO: Pass CConnman instance somehow and don't use global variable.
        CNode *pnode = g_connman->OpenMasternodeConnection(CAddress(addr, NODE_NETWORK));
        if(!pnode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Couldn't connect to securenode %s", strAddress));

        return "successfully connected";
    }

    if (strCommand == "count")
    {
        if (request.params.size() > 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters");

        if (request.params.size() == 1)
            return securenodeman.size();

        std::string strMode = request.params[1].get_str();

        if (strMode == "ps")
            return securenodeman.CountEnabled();

        if (strMode == "enabled")
            return securenodeman.CountEnabled();


        if (strMode == "all")
            return strprintf("Total: %d (PS Compatible: %d / Enabled: %d)",
                             securenodeman.size(), securenodeman.CountEnabled(),
                             securenodeman.CountEnabled());
    }
#ifdef ENABLE_WALLET
    if (strCommand == "start-alias")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify an alias");

        {
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
        }

        std::string strAlias = request.params[1].get_str();

        bool fFound = false;

        UniValue statusObj(UniValue::VOBJ);
        statusObj.push_back(Pair("alias", strAlias));

        for(auto && mrne : securenodeConfig.getEntries()) {
            if(mrne.getAlias() == strAlias) {
                fFound = true;
                std::string strError;
                CSecurenodeBroadcast mnb;

                bool fResult = CSecurenodeBroadcast::Create(mrne.getIp(), mrne.getSecurePrivKey(),
                                                              mrne.getContractTxID(), strError, mnb);

                statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));
                if(fResult) {
                    securenodeman.UpdateSecurenodeList(mnb, *g_connman);
                    mnb.Relay(*g_connman);
                } else {
                    statusObj.push_back(Pair("errorMessage", strError));
                }

                break;
            }
        }

        if(!fFound) {
            statusObj.push_back(Pair("result", "failed"));
            statusObj.push_back(Pair("errorMessage", "Could not find alias in config. Verify with list-conf."));
        }

        return statusObj;
    }
#endif

    if (strCommand == "status")
    {
        if (!fSecureNode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not a securenode");

        UniValue mnObj(UniValue::VOBJ);

        mnObj.push_back(Pair("pubkey", activeSecurenode.pubKeySecurenode.GetID().ToString()));
        mnObj.push_back(Pair("service", activeSecurenode.service.ToString()));

        CSecurenode mn;
        auto pubKey = activeSecurenode.pubKeySecurenode;
        if(securenodeman.Get(pubKey, mn)) {
            mnObj.push_back(Pair("secureAddress", CBitcoinAddress(pubKey.GetID()).ToString()));
        }

        mnObj.push_back(Pair("status", activeSecurenode.GetStatus()));
        return mnObj;
    }

    return NullUniValue;
}

static bool DecodeHexVecMnb(std::vector<CSecurenodeBroadcast>& vecMnb, std::string strHexMnb) {

    if (!IsHex(strHexMnb))
        return false;

    std::vector<unsigned char> mnbData(ParseHex(strHexMnb));
    CDataStream ssData(mnbData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> vecMnb;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

UniValue securesentinelping(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
                    "sentinelping version\n"
                    "\nSentinel ping.\n"
                    "\nArguments:\n"
                    "1. version           (string, required) Sentinel version in the form \"x.x.x\"\n"
                    "\nResult:\n"
                    "state                (boolean) Ping result\n"
                    "\nExamples:\n"
                    + HelpExampleCli("sentinelping", "1.0.2")
                    + HelpExampleRpc("sentinelping", "1.0.2")
                    );
    }

    //    activeSecurenode.UpdateSentinelPing(StringVersionToInt(request.params[0].get_str()));
    return true;
}

#ifdef ENABLE_WALLET
UniValue sposcontract(const JSONRPCRequest& request)
{
    auto pwallet = GetWalletForJSONRPCRequest(request);
    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

    if (request.fHelp  || (strCommand != "list" && strCommand != "create" && strCommand != "refresh"))
        throw std::runtime_error(
                "sposcontract \"command\"...\n"
                "Set of commands to execute securenode related actions\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "\nAvailable commands:\n"
                "  create           - Create spos transaction\n"
                "  list             - Print list of all spos contracts that you are owner or secure\n"
                "  refresh          - Refresh spos contract for secure to fetch all coins from blockchain.\n"
                );


    if (strCommand == "list")
    {
        UniValue result(UniValue::VOBJ);
        UniValue secureArray(UniValue::VARR);
        UniValue ownerArray(UniValue::VARR);

        auto parseContract = [](const SPoSContract &contract) {
            UniValue object(UniValue::VOBJ);

            object.push_back(Pair("txid", contract.rawTx->GetHash().ToString()));
            object.push_back(Pair("sposAddress", contract.sposAddress.ToString()));
            object.push_back(Pair("secureAddress", contract.secureAddress.ToString()));
            object.push_back(Pair("commission", 100 - contract.stakePercentage)); // show secure commission
            if(contract.vchSignature.empty())
                object.push_back(Pair("deprecated", true));

            return object;
        };

        for(auto &&it : pwallet->sposSecureContracts)
        {
            secureArray.push_back(parseContract(it.second));
        }

        for(auto &&it : pwallet->sposOwnerContracts)
        {
            ownerArray.push_back(parseContract(it.second));
        }

        result.push_back(Pair("as_secure", secureArray));
        result.push_back(Pair("as_owner", ownerArray));

        return result;
    }
    else if(strCommand == "create")
    {
        if (request.params.size() < 4)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Expected format: sposcontract create spos_address secure_address commission");

        CBitcoinAddress sposAddress(request.params[1].get_str());
        CBitcoinAddress secureAddress(request.params[2].get_str());
        int commission = std::stoi(request.params[3].get_str());

        if(!sposAddress.IsValid())
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "spos address is not valid, won't continue");

        if(!secureAddress.IsValid())
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "secure address is not valid, won't continue");

        CReserveKey reserveKey(pwallet);

        std::string strError;
        auto transaction = MakeTransactionRef();

        if(SPoSUtils::CreateSPoSTransaction(pwallet, transaction,
                                            reserveKey, sposAddress,
                                            secureAddress, commission, strError))
        {
            return EncodeHexTx(*transaction);
        }
        else
        {
            return "Failed to create spos transaction, reason: " + strError;
        }
    }
    else if(strCommand == "refresh")
    {
        if(request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Expected format: sposcontract refres sposcontract_id");

        auto sposContractHashID = ParseHashV(request.params[1], "sposcontractid");

        auto it = pwallet->sposSecureContracts.find(sposContractHashID);
        if(it == std::end(pwallet->sposSecureContracts))
            return "No secure spos contract found";

        WalletRescanReserver reserver(pwallet);
        pwallet->ScanForWalletTransactions(chainActive.Genesis(), chainActive.Tip(), reserver, true);
        pwallet->ReacceptWalletTransactions();
    }
    else if(strCommand == "cleanup")
    {
        if(request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Expected format: sposcontract refres sposcontract_id");

        auto sposContractHashID = ParseHashV(request.params[1], "sposcontractid");

        auto it = pwallet->sposSecureContracts.find(sposContractHashID);
        if(it == std::end(pwallet->sposSecureContracts))
            return "No secure spos contract found";

    }

    return NullUniValue;
}

#endif

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
  { "securenode",            "securenode",            &securenode,            {"command"} }, /* uses wallet if enabled */
  { "securenode",            "securenodelist",        &securenodelist,        {"mode", "filter"} },
  #ifdef ENABLE_WALLET
  { "securenode",            "sposcontract",            &sposcontract,            {"command"} },
  #endif
  { "securenode",            "securesync",            &securesync,            {"command"} },
};

void RegisterSecurenodeCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

