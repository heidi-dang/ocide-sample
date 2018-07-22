#ifndef BLOCKSIGNER_H
#define BLOCKSIGNER_H

class CBlock;
class SPoSContract;
class CPubKey;
class CKey;
class CKeyStore;

struct CBlockSigner {

    CBlockSigner(CBlock &block, const CKeyStore *keystore, const SPoSContract &contract);

    bool SignBlock();
    bool CheckBlockSignature() const;

    CBlock &refBlock;
    const CKeyStore *refKeystore;
    const SPoSContract &refContract;
};
#endif // BLOCKSIGNER_H
