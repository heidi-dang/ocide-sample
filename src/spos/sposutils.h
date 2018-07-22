#ifndef SPOSUTILS_H
#define SPOSUTILS_H

#include <string>
#include <memory>
#include <amount.h>
#include <script/standard.h>
#include <pubkey.h>
#include <key_io.h>

class CWallet;
class CWalletTx;
class CMutableTransaction;
class CReserveKey;
class CValidationState;

struct SPoSContract
{
    SPoSContract() = default;
    SPoSContract(CTransactionRef tx,
                 CBitcoinAddress secureAddress,
                 CBitcoinAddress sposAddress,
                 short stakePercentage,
                 std::vector<unsigned char> vchSignature);

    bool IsValid() const;

    static SPoSContract FromSPoSContractTx(const CTransactionRef tx);

    CTransactionRef rawTx;
    CBitcoinAddress secureAddress;
    CBitcoinAddress sposAddress;
    std::vector<unsigned char> vchSignature;
    int stakePercentage = 0;
};

class SPoSUtils
{
public:
    SPoSUtils() = delete;
    ~SPoSUtils() = delete;

    static std::string PrepareSPoSExportBlock(std::string content);
    static std::string ParseSPoSExportBlock(std::string block);

    static bool IsSPoSContract(const CTransactionRef &tx);

#ifdef ENABLE_WALLET
    static bool GetSPoSPayments(const CWallet *wallet,
                                const CTransactionRef &tx,
                                CAmount &stakeAmount,
                                CAmount &commissionAmount,
                                CTxDestination &sposAddress, CTxDestination &secureAddress);

    static bool IsSPoSOwnerContract(CWallet *wallet, const CTransactionRef &tx);
    static bool IsSPoSSecureContract(CWallet *wallet, const CTransactionRef &tx);

    static bool CreateSPoSTransaction(CWallet *wallet,
                                      CTransactionRef &transactionOut,
                                      CReserveKey &reserveKey,
                                      const CBitcoinAddress &sposAddress,
                                      const CBitcoinAddress &secureAddress,
                                      int secureCommission,
                                      std::string &strError);

    static bool CreateCancelContractTransaction(CWallet *wallet,
                                                CTransactionRef &txOut,
                                                CReserveKey &reserveKey,
                                                const SPoSContract &contract,
                                                std::string &strError);

    static COutPoint GetContractCollateralOutpoint(const SPoSContract &contract);
    static bool CheckContract(const uint256 &hashContractTx, SPoSContract &contract, bool fCheckSignature, bool fCheckContractOutpoint);
    static bool IsSecurePaymentValid(CValidationState &state, const CBlock &block, int nBlockHeight, CAmount expectedReward, CAmount actualReward);

#endif

};

#endif // SPOSUTILS_H
