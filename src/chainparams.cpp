// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>
#include "arith_uint256.h"

#include <assert.h>

#include <chainparamsseeds.h>

static CBlock
CreateGenesisBlock(const char *pszTimestamp, const CScript &genesisOutputScript, uint32_t nTime, uint32_t nNonce,
                   uint32_t nBits, int32_t nVersion, const CAmount &genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4)
                                       << std::vector<unsigned char>
                                       ((const unsigned char *) pszTimestamp,
                                       (const unsigned char *) pszTimestamp +
                                       strlen(pszTimestamp));

    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock
CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward) {
    const char *pszTimestamp = "August 2018 OCide is on it own testnet";
    const CScript genesisOutputScript = CScript() << ParseHex("0") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymensPos d, int64_t nStartTime, int64_t nTimeout) {
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nFirstBlocksEmpty = 20000;
        consensus.nSubsidyHalvingInterval = 43200; // Note: actual number of blocks per calendar year with DGW v3
        consensus.nMasternodePaymentsStartBlock = 20100; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // actual historical value
        consensus.nMasternodePaymentsIncreasePeriod = 576 * 30; // 17280 - actual historical value
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 0; // actual historical value
        consensus.nBudgetPaymentsCycleBlocks = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60 * 60 * 24;
        consensus.nSuperblockCycle = 43200; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nSuperblockStartBlock = consensus.nSuperblockCycle; // The block at which 12.1 goes live (end of final 12.0 budget cycle)
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.BIP34Height = consensus.nLastPoWBlock;
        consensus.BIP34Hash = uint256S("0");
        consensus.BIP65Height = consensus.nLastPoWBlock;
        consensus.BIP66Height = consensus.nLastPoWBlock;
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // OCIDE: 1 day
        consensus.nPowTargetSpacing = 2 * 60; // OCIDE: 2 minutes
        consensus.nPosTargetSpacing = 2 * 60; // OCIDE: 2 minutes
        consensus.nPosTargetTimespan = 60 * 40;
        consensus.nSecurenodeMinimumConfirmations = 1;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24; // one day
        consensus.nCoinbaseMaturity = 20;
        consensus.nSPoSContractSignatureDeploymentTime = 1532267514;
        consensus.nLastPoWBlock = 10000000;
        consensus.nPowKGWHeight = 100000;
        consensus.nPowDGWHeight = 500;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1080; // 75% of 2016
        consensus.nMinerConfirmationWindow = 1440; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0");

        pchMessageStart[0] = 0xb1;
        pchMessageStart[1] = 0x2c;
        pchMessageStart[2] = 0x7b;
        pchMessageStart[3] = 0xb9;
        nDefaultPort = 16969;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1535794699, 966363, 0x1e0ffff0, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();


        //LogPrintf("consensus.hashGenesisBlock=%s\n", consensus.hashGenesisBlock.GetHex());
        //LogPrintf("genesis.hashMerkleRoot=%s\n", genesis.hashMerkleRoot.GetHex())

        assert(consensus.hashGenesisBlock == uint256S("0x000005807f2a217e8a8e55e7a4c0d8406a994c270fb743db9eb5030938aae1df"));
        assert(genesis.hashMerkleRoot == uint256S("0x33a6139354910d974797e5abdfc4260847ca91fb697fe32a972e0242b1e83909"));

        //vBootstrapSeeds.emplace_back("");
        //vSeeds.emplace_back("");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 56);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 26);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 104);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x05, 0x86, 0xB3, 0x2E};
        base58Prefixes[EXT_SECRET_KEY] = {0x03, 0x81, 0x1D, 0xE5};

        bech32_hrp = "oc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60 * 60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "0";

        checkpointData = {
                {
                        {0, uint256S("0")},

                }
        };

        chainTxData = ChainTxData{
                // Data as of block 0 (height 0).
                0, // * UNIX timestamp of last known number of transactions
                0,  // * total number of transactions between genesis and that timestamp
                //   (the tx=... number in the SetBestChain debug.log lines)
                0         // * estimated number of transactions per second after that timestamp
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 10000;
        consensus.nFirstBlocksEmpty = 20;
        consensus.nMasternodePaymentsStartBlock = 4010; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 4030;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60 * 20;
        consensus.nSuperblockStartBlock = 1010; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.BIP34Height = consensus.nLastPoWBlock;
        consensus.BIP34Hash = uint256S("0");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // OCIDE: 1 day
        consensus.nPowTargetSpacing = 1 * 60; // OCIDE: 1 minutes
        consensus.nPosTargetSpacing = 1 * 60; // SPoS: 1 minutes
        consensus.nPosTargetTimespan = 60 * 40;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nSecurenodeMinimumConfirmations = 1;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 4001; // nPowKGWHeight >= nPowDGWHeight means "no KGW"
        consensus.nPowDGWHeight = 4001;
        consensus.nLastPoWBlock = 75;
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24; // one day
        consensus.nCoinbaseMaturity = 20;
        consensus.nSPoSContractSignatureDeploymentTime = 1522782000;
        consensus.nRuleChangeActivationThreshold = 30; // 75% for testchains
        consensus.nMinerConfirmationWindow = 40; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

//        // Deployment of BIP68, BIP112, and BIP113.
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1560284399;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT; // May 1st, 2017

//        // Deployment of SegWit (BIP141, BIP143, and BIP147)
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0");

        pchMessageStart[0] = 0x4e;
        pchMessageStart[1] = 0x82;
        pchMessageStart[2] = 0x7a;
        pchMessageStart[3] = 0x68;
        nDefaultPort = 29999;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(1532267514, 0, 0x1e0ffff0, 1, 3000000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();


        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 145);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 15);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 219);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0x75, 0x84, 0x1F};
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0x45, 0x82, 0x14};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5 * 60; // fulfilled requests expire in 5 minutes
        strSporkPubKey = "0";

        checkpointData = {
                {
                        {0, uint256S("0")},
                }
        };

        chainTxData = ChainTxData{
                // Data as of block 0 (height 0)
                0,
                0,
                0
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 4010; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 4030;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60 * 20;
        consensus.nSuperblockStartBlock = 1010; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // OCIDE: 1 day
        consensus.nPowTargetSpacing = 1 * 60; // OCIDE: 1 minutes
        consensus.nPosTargetSpacing = 1 * 60; // SPoS: 1 minutes
        consensus.nPosTargetTimespan = 60 * 40;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nPowKGWHeight = 4001; // nPowKGWHeight >= nPowDGWHeight means "no KGW"
        consensus.nPowDGWHeight = 4001;
        consensus.nLastPoWBlock = 75;
        consensus.nStakeMinAge = 60 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24; // one day
        consensus.nCoinbaseMaturity = 20;
        consensus.nFirstBlocksEmpty = 0;
        consensus.nSPoSContractSignatureDeploymentTime = 1522782000;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0");

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xb1;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd2;
        nDefaultPort = 29999;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(1532267514, 0, 0x1e0ffff0, 1, 3000000 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();


        //vBootstrapSeeds.emplace_back("");
        //vSeeds.emplace_back("");
        vFixedSeeds.clear();
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        nFulfilledRequestExpireTime = 5 * 60; // fulfilled requests expire in 5 minutes

        checkpointData = {
                {
                        {0, uint256S("0")},
                }
        };

        chainTxData = ChainTxData{
                0,
                0,
                0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 110);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 12);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 219);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x02, 0x45, 0x84, 0x1F};
        base58Prefixes[EXT_SECRET_KEY] = {0x02, 0x36, 0x87, 0x14};

        bech32_hrp = "rgt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr <CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr <CChainParams> CreateChainParams(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymensPos d, int64_t nStartTime, int64_t nTimeout) {
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
