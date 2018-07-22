#include <spos/sposutils.h>

#include <wallet/wallet.h>
#include <utilmoneystr.h>
#include <policy/policy.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <spos/securenode-sync.h>
#include <spos/securenodeman.h>
#include <spos/activesecurenode.h>
#include <consensus/validation.h>
#include <messagesigner.h>
#include <spork.h>
#include <sstream>
#include <numeric>

static const std::string SPOSEXPORTHEADER("SPOSOWNERINFO");
static const int SPOSEXPORTHEADERWIDTH = 40;

static const int SPOS_CONTRACT_COLATERAL = 1 * COIN;

std::string ParseAddressFromMetadata(std::string str)
{
    auto sposAddressRaw = ParseHex(str);
    std::string addressAsStr(sposAddressRaw.size(), '0');

    for(size_t i = 0; i < sposAddressRaw.size(); ++i)
        addressAsStr[i] = static_cast<char>(sposAddressRaw[i]);

    return addressAsStr;
}

bool SPoSUtils::IsSPoSContract(const CTransactionRef &tx)
{
    return SPoSContract::FromSPoSContractTx(tx).IsValid();
}

#ifdef ENABLE_WALLET

bool SPoSUtils::GetSPoSPayments(const CWallet *wallet,
                                const CTransactionRef &tx,
                                CAmount &stakeAmount,
                                CAmount &commissionAmount,
                                CTxDestination &sposAddress,
                                CTxDestination &secureAddress)
{
    if(!tx->IsCoinStake())
        return false;

    CAmount nCredit = wallet->GetCredit(*tx, ISMINE_ALL);
    CAmount nDebit = wallet->GetDebit(*tx, ISMINE_ALL);
    CAmount nNet = nCredit - nDebit;

    std::vector<SPoSContract> sposContracts;

    for(auto &&pair : wallet->sposOwnerContracts)
        sposContracts.emplace_back(pair.second);

    for(auto &&pair : wallet->sposSecureContracts)
        sposContracts.emplace_back(pair.second);

    CTxDestination address;
    auto scriptKernel = tx->vout.at(1).scriptPubKey;
    commissionAmount = stakeAmount = 0;
    if(ExtractDestination(scriptKernel, address))
    {
        CBitcoinAddress tmpAddress(address);

        auto it = std::find_if(std::begin(sposContracts), std::end(sposContracts), [tmpAddress](const SPoSContract &entry) {
            return entry.sposAddress == tmpAddress;
        });

        if(it != std::end(sposContracts))
        {
            auto secureScript = GetScriptForDestination(it->secureAddress.Get());
            auto commissionIt = std::find_if(std::begin(tx->vout), std::end(tx->vout), [secureScript](const CTxOut &txOut) {
                return txOut.scriptPubKey == secureScript;
            });

            if(commissionIt != tx->vout.end())
            {
                stakeAmount = nNet;
                commissionAmount = commissionIt->nValue;
                sposAddress = tmpAddress.Get();
                secureAddress = it->secureAddress.Get();

                return true;
            }
        }
    }

    return false;

}

bool SPoSUtils::IsSPoSSecureContract(CWallet *wallet, const CTransactionRef &tx)
{
    SPoSContract contract = SPoSContract::FromSPoSContractTx(tx);

    bool isSecureNode = GetScriptForDestination(contract.secureAddress.Get()) ==
            GetScriptForDestination(activeSecurenode.pubKeySecurenode.GetID());

    return contract.IsValid() && (isSecureNode ||
                                  IsMine(*wallet, contract.secureAddress.Get()) == ISMINE_SPENDABLE);
}

bool SPoSUtils::IsSPoSOwnerContract(CWallet *wallet, const CTransactionRef &tx)
{
    SPoSContract contract = SPoSContract::FromSPoSContractTx(tx);

    return contract.IsValid() &&
            IsMine(*wallet, contract.sposAddress.Get()) == ISMINE_SPENDABLE;
}

bool SPoSUtils::CreateSPoSTransaction(CWallet *wallet,
                                      CTransactionRef &transactionOut,
                                      CReserveKey& reservekey,
                                      const CBitcoinAddress &sposAddress,
                                      const CBitcoinAddress &secureAddress,
                                      int secureCommission,
                                      std::string &strError)
{
    auto sposAddressAsStr = sposAddress.ToString();
    auto secureAddressAsStr = secureAddress.ToString();

    CScript metadataScriptPubKey;
    metadataScriptPubKey << OP_RETURN
                         << std::vector<unsigned char>(sposAddressAsStr.begin(), sposAddressAsStr.end())
                         << std::vector<unsigned char>(secureAddressAsStr.begin(), secureAddressAsStr.end())
                         << (100 - secureCommission);


    if(wallet->IsLocked())
    {
        strError = "Error: Wallet is locked";
        return false;
    }

    CKey key;
    CKeyID keyID;
    if(!sposAddress.GetKeyID(keyID))
    {
        strError = "Error: SPoS Address is not P2PKH";
        return false;
    }
    if (!wallet->GetKey(keyID, key))
    {
        strError = "Error: Failed to get private key associated with SPoS address";
        return false;
    }
    std::vector<unsigned char> vchSignature;
    key.SignCompact(SerializeHash(COutPoint()), vchSignature);
    metadataScriptPubKey << vchSignature;

    std::vector<CRecipient> vecSend {
        { metadataScriptPubKey, 0, false },
        { GetScriptForDestination(sposAddress.Get()), SPOS_CONTRACT_COLATERAL, false }
    };


    CAmount nFeeRequired;

    // this delegate will be executed right before signing. This will allow us to tweak transaction and do
    // some spos specific thing, like signing contract.
    auto txModifier = [&strError, &key](CMutableTransaction &tx, std::vector<unsigned char> vchSignature) {
        auto firstInput = tx.vin.front().prevout;

        auto it = std::find_if(tx.vout.begin(), tx.vout.end(), [](const CTxOut &txOut) {
            return txOut.scriptPubKey.IsUnspendable();
        });

        auto vchSignatureCopy = vchSignature;
        vchSignature.clear();
        auto hashMessage = SerializeHash(firstInput);
        if(!key.SignCompact(hashMessage, vchSignature))
        {
            strError = "Error: Failed to sign spos contract";
        }
        it->scriptPubKey.FindAndDelete(CScript(vchSignatureCopy));
        it->scriptPubKey << vchSignature;
    };

    auto txModifierBinded = std::bind(txModifier, std::placeholders::_1, vchSignature);

    int nChangePos = -1;
    if (!wallet->CreateTransaction(vecSend, transactionOut, reservekey, nFeeRequired, nChangePos, strError, {}, true, txModifierBinded))
    {
        if (SPOS_CONTRACT_COLATERAL + nFeeRequired > wallet->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        LogPrintf("Error() : %s\n", strError);
        return false;
    }

    if(!strError.empty())
        return false;

    std::string reason;
    if(!IsStandardTx(*transactionOut, reason))
    {
        strError = strprintf("Error: Not standard tx: %s\n", reason.c_str());
        LogPrintf(strError.c_str());
        return false;
    }

    return true;
}

bool SPoSUtils::CreateCancelContractTransaction(CWallet *wallet, CTransactionRef &txOut, CReserveKey &reserveKey, const SPoSContract &contract, string &strError)
{
    if(wallet->IsLocked())
    {
        strError = "Error: Wallet is locked";
        return false;
    }

    COutPoint prevOutpoint = GetContractCollateralOutpoint(contract);
    if(prevOutpoint.IsNull())
    {
        strError = "Error: Contract collateral is invalid";
        return false;
    }

    Coin coin;
    if(!pcoinsTip->GetCoin(prevOutpoint, coin) || coin.IsSpent())
    {
        strError = "Error: Collateral is already spent";
        return false;
    }

    auto &prevOutput = contract.rawTx->vout.at(prevOutpoint.n);

    CAmount nFeeRet;
    int nChangePosRet;
    CCoinControl coinControl;
    //    coinControl.fUsePrivateSend = false;
    coinControl.nCoinType = ONLY_SECURENODE_COLLATERAL;
    coinControl.Select(prevOutpoint);
    if(!wallet->CreateTransaction({ { prevOutput.scriptPubKey, prevOutput.nValue, true } }, txOut,
                                  reserveKey, nFeeRet, nChangePosRet,
                                  strError, coinControl, true))
    {
        LogPrintf("Error() : %s\n", strError.c_str());
        return false;
    }

    return true;
}

COutPoint SPoSUtils::GetContractCollateralOutpoint(const SPoSContract &contract)
{
    COutPoint result;
    if(!contract.rawTx)
    {
        return result;
    }


    const auto &vout = contract.rawTx->vout;
    for(size_t i = 0; i < vout.size(); ++i)
    {
        if(vout[i].scriptPubKey == GetScriptForDestination(contract.sposAddress.Get()) &&
                vout[i].nValue == SPOS_CONTRACT_COLATERAL)
        {
            result = COutPoint(contract.rawTx->GetHash(), i);
            break;
        }
    }

    return result;
}

bool SPoSUtils::CheckContract(const uint256 &hashContractTx, SPoSContract &contract, bool fCheckSignature, bool fCheckContractOutpoint)
{
    CTransactionRef tx;
    uint256 hashBlock;
    if(!GetTransaction(hashContractTx, tx, Params().GetConsensus(), hashBlock, true))
    {
        return error("CheckContract() : failed to get transaction for spos contract %s",
                     hashContractTx.ToString());
    }

    SPoSContract tmpContract = SPoSContract::FromSPoSContractTx(tx);

    if(!tmpContract.IsValid())
        return error("CheckContract() : invalid transaction for spos contract");

    if(fCheckSignature)
    {
        auto hashMessage = SerializeHash(tmpContract.rawTx->vin.front().prevout);
        std::string strError;
        if(!CHashSigner::VerifyHash(hashMessage, tmpContract.sposAddress.Get(), tmpContract.vchSignature, strError))
        {
            return error("CheckContract() : SPoS contract signature is invalid %s", strError);
        }
    }

    if(fCheckContractOutpoint)
    {
        auto sposContractOutpoint = SPoSUtils::GetContractCollateralOutpoint(tmpContract);
        Coin coin;
        if(!pcoinsTip->GetCoin(sposContractOutpoint, coin) || coin.IsSpent())
            return error("CheckContract() : spos contract invalid, collateral is spent");
    }

    contract = tmpContract;

    return true;
}

bool SPoSUtils::IsSecurePaymentValid(CValidationState &state, const CBlock &block, int nBlockHeight, CAmount expectedReward, CAmount actualReward)
{
    auto contract = SPoSContract::FromSPoSContractTx(block.txSPoSContract);
    CBitcoinAddress secureAddress = contract.secureAddress;
    CScript scriptSecurePubKey = GetScriptForDestination(secureAddress.Get());

    const auto &coinstake = block.vtx[1];

    if(coinstake->vout[1].scriptPubKey != GetScriptForDestination(contract.sposAddress.Get()))
    {
        CTxDestination dest;
        if(!ExtractDestination(coinstake->vout[1].scriptPubKey, dest))
            return state.DoS(100, error("IsSecurePaymentValid -- ERROR: coinstake extract destination failed"), REJECT_INVALID, "bad-secure-payee");


        return state.DoS(100, error("IsSecurePaymentValid -- ERROR: coinstake is invalid expected: %s, actual %s\n",
                                    contract.sposAddress.ToString().c_str(), CBitcoinAddress(dest).ToString().c_str()), REJECT_INVALID, "bad-secure-payee");
    }

    CAmount securePayment = 0;
    securePayment = std::accumulate(std::begin(coinstake->vout) + 2, std::end(coinstake->vout), CAmount(0), [scriptSecurePubKey](CAmount accum, const CTxOut &txOut) {
            return txOut.scriptPubKey == scriptSecurePubKey ? accum + txOut.nValue : accum;
});

    if(securePayment > 0)
    {
        auto maxAllowedValue = (expectedReward / 100) * (100 - contract.stakePercentage);
        // ban, we know fur sure that secure tries to get more than he is allowed
        if(securePayment > maxAllowedValue)
            return state.DoS(100, error("IsSecurePaymentValid -- ERROR: secure was paid more than allowed: %s\n", contract.secureAddress.ToString().c_str()),
                             REJECT_INVALID, "bad-secure-payee");
    }
    else
    {
        LogPrintf("IsSecurePaymentValid -- WARNING: secure wasn't paid, this is weird, but totally acceptable. Shouldn't happen.\n");
    }

    if(!securenodeSync.IsSynced())
    {
        //there is no secure node info to check anything, let's just accept the longest chain
        //        if(fDebug)
        LogPrintf("IsSecurePaymentValid -- WARNING: Client not synced, skipping block payee checks\n");

        return true;
    }

    if(!sporkManager.IsSporkActive(Spork::SPORK_15_SPOS_ENABLED))
    {
        return state.DoS(0, error("IsBlockPayeeValid -- ERROR: Invalid securenode payment detected at height %d\n", nBlockHeight),
                         REJECT_INVALID, "bad-secure-payee", true);
    }

    CKeyID coinstakeKeyID;
    if(!secureAddress.GetKeyID(coinstakeKeyID))
        return state.DoS(0, error("IsSecurePaymentValid -- ERROR: coin stake was paid to invalid address\n"),
                         REJECT_INVALID, "bad-secure-payee", true);

    CSecurenode secureNode;
    if(!securenodeman.Get(coinstakeKeyID, secureNode))
    {
        return state.DoS(0, error("IsSecurePaymentValid -- ERROR: failed to find securenode with address: %s\n", secureAddress.ToString().c_str()),
                         REJECT_INVALID, "bad-secure-payee", true);
    }

    if(secureNode.hashSPoSContractTx != block.hashSPoSContractTx)
    {
        return state.DoS(100, error("IsSecurePaymentValid -- ERROR: securenode contract is invalid expected: %s, actual %s\n",
                                    block.hashSPoSContractTx.ToString().c_str(), secureNode.hashSPoSContractTx.ToString().c_str()),
                         REJECT_INVALID, "bad-secure-payee");
    }

    if(!secureNode.IsValidForPayment())
    {
        return state.DoS(0, error("IsSecurePaymentValid -- ERROR: securenode with address: %s is not valid for payment\n", secureAddress.ToString().c_str()),
                         REJECT_INVALID, "bad-secure-payee", true);
    }

    return true;
}

#endif

SPoSContract::SPoSContract(CTransactionRef tx, CBitcoinAddress secureAddress, CBitcoinAddress sposAddress, short stakePercentage, std::vector<unsigned char> vchSignature)
{
    this->rawTx = tx;
    this->secureAddress = secureAddress;
    this->sposAddress = sposAddress;
    this->vchSignature = vchSignature;
    this->stakePercentage = stakePercentage;
}

bool SPoSContract::IsValid() const
{
    return rawTx && !rawTx->IsNull() && secureAddress.IsValid() && sposAddress.IsValid() &&
            stakePercentage > 0 && stakePercentage < 100;
}

SPoSContract SPoSContract::FromSPoSContractTx(const CTransactionRef tx)
{
    try
    {
        if(tx->vout.size() >= 2 && tx->vout.size() <= 3 )
        {
            const CTxOut *metadataOutPtr = nullptr;
            bool colateralFound = false;
            for(const CTxOut &txOut : tx->vout)
            {
                if(txOut.scriptPubKey.IsUnspendable())
                {
                    metadataOutPtr = &txOut;
                }
                else if(txOut.nValue == SPOS_CONTRACT_COLATERAL)
                {
                    colateralFound = true;
                }
            }

            if(metadataOutPtr && colateralFound)
            {
                const auto &metadataOut = *metadataOutPtr;
                std::vector<std::vector<unsigned char>> vSolutions;
                txnouttype whichType;
                if (Solver(metadataOut.scriptPubKey, whichType, vSolutions) && whichType == TX_NULL_DATA)
                {
                    // Here we can have a chance that it is transaction which is a spos contract
                    std::stringstream stringStream(metadataOut.scriptPubKey.ToString());

                    std::string tokens[5];
                    for(auto &token : tokens)
                    {
                        stringStream >> token;
                    }

                    CBitcoinAddress sposAddress(ParseAddressFromMetadata(tokens[1]));
                    CBitcoinAddress secureAddress(ParseAddressFromMetadata(tokens[2]));
                    int commission = std::stoi(tokens[3]);
                    std::vector<unsigned char> vchSignature = ParseHex(tokens[4]);
                    if(tokens[0] == GetOpName(OP_RETURN) && sposAddress.IsValid() && secureAddress.IsValid() &&
                            commission > 0 && commission < 100)
                    {

                        // if we get to this point, it means that we have found spos contract that was created for us to act as secure.
                        return SPoSContract(tx, secureAddress, sposAddress, commission, vchSignature);
                    }
                }
            }
        }
    }
    catch(std::exception &ex)
    {
        LogPrintf("Failed to parse spos which had to be spos, %s\n", ex.what());
    }

    return SPoSContract();
}
