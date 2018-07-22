#include "sposaddressestablemodel.h"
#include <amount.h>
#include <init.h>
#include <optionsmodel.h>
#include <bitcoinunits.h>
#include <spos/sposutils.h>
#include <validation.h>
#include <walletmodel.h>
#include <interfaces/wallet.h>
#include <interfaces/handler.h>
#include <numeric>
#include <QFile>

static QString GetCommisionAmountColumnTitle(int unit)
{
    QString amountTitle = QObject::tr("Commission");
    if (BitcoinUnits::valid(unit)) {
        amountTitle += " (" + BitcoinUnits::longName(unit) + ")";
    }
    return amountTitle;
}

static QString GetStakeAmountColumnTitle(int unit)
{
    QString amountTitle = QObject::tr("Reward");
    if (BitcoinUnits::valid(unit)) {
        amountTitle += " (" + BitcoinUnits::longName(unit) + ")";
    }
    return amountTitle;
}

static QString FormatAmount(int displayUnit, CAmount amount, BitcoinUnits::SeparatorStyle separators)
{
    return BitcoinUnits::format(displayUnit,
                                amount,
                                false,
                                separators);
}

SPoSAddressesTableModel::SPoSAddressesTableModel(WalletModel *parent, OptionsModel *optionsModel)
    : QAbstractTableModel(parent),
      walletModel(parent),
      optionsModel(optionsModel),
      sposContracts(walletModel->wallet().getOwnerContracts())

{
    auto displayUnit = optionsModel->getDisplayUnit();
    columns << tr("SPoS Address")
            << BitcoinUnits::getAmountColumnTitle(displayUnit)
            << GetStakeAmountColumnTitle(displayUnit)
            << GetCommisionAmountColumnTitle(displayUnit);

    connect(optionsModel, &OptionsModel::displayUnitChanged,
            this, &SPoSAddressesTableModel::updateDisplayUnit);
    refreshModel();

    transactionChangedHandler = walletModel->wallet().handleTransactionChanged(
                std::bind(&SPoSAddressesTableModel::NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
}

SPoSAddressesTableModel::~SPoSAddressesTableModel()
{
    transactionChangedHandler->disconnect();
}

QVariant SPoSAddressesTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal) {
        if (role == Qt::DisplayRole && section < columns.size()) {
            return columns[section];
        }
    }
    return QVariant();
}

int SPoSAddressesTableModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;

    return sposContracts.size();
}

int SPoSAddressesTableModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;

    return columns.size();
}

QVariant SPoSAddressesTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || role != Qt::DisplayRole ||
            index.row() >= sposContracts.size())
        return QVariant();

    auto entryIt = std::next(sposContracts.begin(), index.row());
    CBitcoinAddress address = entryIt->second.sposAddress;
    auto it = amountsMap.find(address);

    switch(index.column())
    {
    case Address: return QString::fromStdString(address.ToString());
    case Amount: return it != std::end(amountsMap) ? formatAmount(it->second.totalAmount) : QString();
    case AmountStaked: return it != std::end(amountsMap) ? formatAmount(it->second.stakeAmount) : QString();
    case CommissionPaid: return it != std::end(amountsMap) ? formatCommissionAmount(it->second.commissionAmount, entryIt->second.stakePercentage) : QString();
    default:
        break;
    }

    return QVariant();
}

const SPoSContract &SPoSAddressesTableModel::contractByIndex(int index) const
{
    auto entryIt = std::next(sposContracts.begin(), index);
    return entryIt->second;
}

void SPoSAddressesTableModel::updateModel()
{
    beginResetModel();
    refreshModel();
    endResetModel();
}

void SPoSAddressesTableModel::updateAmount(int row)
{
    auto entryIt = std::next(sposContracts.begin(), row);
    CBitcoinAddress address = entryIt->second.sposAddress;
    amountsMap[address] = GetAmountForAddress(address);
    Q_EMIT dataChanged(index(row, Amount), index(row, CommissionPaid));
}

void SPoSAddressesTableModel::updateDisplayUnit()
{
    // Q_EMIT dataChanged to update Amount column with the current unit
    updateAmountColumnTitle();
    Q_EMIT dataChanged(index(0, Amount), index(rowCount() - 1, CommissionPaid));
}

void SPoSAddressesTableModel::refreshModel()
{
    amountsMap.clear();
    for(auto &&contract : sposContracts)
    {
        amountsMap[contract.second.sposAddress] = GetAmountForAddress(contract.second.sposAddress);
    }
}

/** Updates the column title to "Amount (DisplayUnit)" and Q_EMITs headerDataChanged() signal for table headers to react. */
void SPoSAddressesTableModel::updateAmountColumnTitle()
{
    columns[Amount] = BitcoinUnits::getAmountColumnTitle(optionsModel->getDisplayUnit());
    Q_EMIT headerDataChanged(Qt::Horizontal, Amount, Amount);
}

void SPoSAddressesTableModel::NotifyTransactionChanged(const uint256& hash, ChangeType status)
{
    // this needs work
    return;
    auto maybeUpdate = [this](uint256 txid) {
        auto it = sposContracts.find(txid);
        if(it != std::end(sposContracts))
        {
            updateAmount(std::distance(sposContracts.begin(), it));
        }
    };

    // Find transaction in wallet
    // Determine whether to show transaction or not (determine this here so that no relocking is needed in GUI thread)
    if(auto transaction = walletModel->wallet().getTx(hash))
    {
        maybeUpdate(transaction->GetHash());
    }
}

QString SPoSAddressesTableModel::formatCommissionAmount(CAmount commissionAmount, int percentage) const
{
    return QString("%1 (%2 %)").arg(formatAmount(commissionAmount)).arg(100 - percentage);
}

SPoSAddressesTableModel::Entry SPoSAddressesTableModel::GetAmountForAddress(CBitcoinAddress address)
{
    Entry result = { 0, 0, 0 };

    // ocide address
    if (!address.IsValid())
        return result;

    auto &walletInterface = walletModel->wallet();

    CScript scriptPubKey = GetScriptForDestination(address.Get());

    // this loop can be optimized
    for (auto &&walletTx : walletInterface.getWalletTxs())
    {
        const auto& tx = *walletTx.tx;
        if (tx.IsCoinBase() || !CheckFinalTx(tx))
            continue;

        for(size_t i = 0; i < tx.vout.size(); ++i)
        {
            const CTxOut& txout = tx.vout[i];
            if (txout.scriptPubKey == scriptPubKey)
            {
                if (!walletInterface.txoutIsSpent(tx.GetHash(), i))
                {
                    result.totalAmount += txout.nValue;
                }
            }
        }

        if(tx.IsCoinStake())
        {
            CAmount stakeAmount = 0;
            CAmount commissionAmount = 0;
            CTxDestination sposAddress;
            CTxDestination secureAddress;
            if(walletInterface.getSPoSPayments(walletTx.tx, stakeAmount, commissionAmount, sposAddress, secureAddress) &&
                    sposAddress == address.Get())
            {
                // at this moment nNet contains net stake reward
                // commission was sent to secure address, so it was base of tx
                result.commissionAmount += commissionAmount;
                // stake amount is just what was sent to spos address
                result.stakeAmount += stakeAmount;
            }
        }
    }

    return result;
}

QString SPoSAddressesTableModel::formatAmount(CAmount amount) const
{
    return FormatAmount(optionsModel->getDisplayUnit(),
                        amount,
                        BitcoinUnits::separatorAlways);
}
