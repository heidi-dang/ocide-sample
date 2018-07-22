#ifndef SPOSADDRESSESTABLEMODEL_HPP
#define SPOSADDRESSESTABLEMODEL_HPP

#include <QAbstractTableModel>
#include <vector>
#include <QString>
#include <string>
#include <amount.h>
#include <ui_interface.h>
#include <base58.h>
#include <key_io.h>

class OptionsModel;
class SPoSContract;
class WalletModel;

namespace interfaces {
class Handler;
class Wallet;
}

class SPoSAddressesTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit SPoSAddressesTableModel(WalletModel *parent,
                                     OptionsModel *optionsModel);

    ~SPoSAddressesTableModel();

    enum ColumnIndex {
        Address = 0, /**< SPoS address */
        Amount, /** < Total amount */
        AmountStaked,
        CommissionPaid
    };

    // Header:
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    // Basic functionality:
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    const SPoSContract &contractByIndex(int index) const;

    void updateModel();
    void updateAmount(int row);

private Q_SLOTS:
    void updateDisplayUnit();

private:
    struct Entry {
        CAmount totalAmount;
        CAmount stakeAmount;
        CAmount commissionAmount;
    };

private:
    void refreshModel();
    void updateAmountColumnTitle();
    void NotifyTransactionChanged(const uint256& hash, ChangeType status);
    QString formatCommissionAmount(CAmount commissionAmount, int percentage) const;
    QString formatAmount(CAmount amountAsStr) const;
    Entry GetAmountForAddress(CBitcoinAddress address);

private:
    std::unique_ptr<interfaces::Handler> transactionChangedHandler;
    WalletModel *walletModel;
    OptionsModel *optionsModel;
    const std::map<uint256, SPoSContract> &sposContracts;
    std::map<CBitcoinAddress, Entry> amountsMap;
    QStringList columns;
};

#endif // SPOSADDRESSESTABLEMODEL_HPP
