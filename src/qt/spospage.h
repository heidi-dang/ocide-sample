#ifndef SPOSPAGE_H
#define SPOSPAGE_H

#include <QWidget>
#include <tuple>
#include <functional>
#include <QPointer>
#include "primitives/transaction.h"
#include "interfaces/wallet.h"


class WalletModel;
class CBitcoinAddress;
class SPoSAddressesTableModel;

namespace Ui {
class SPoSPage;
}

namespace GUIUtil {
class TableViewLastColumnResizingFixer;
}

class SPoSPage : public QWidget
{
    Q_OBJECT

public:
    explicit SPoSPage(QWidget *parent = 0);
    ~SPoSPage();

    void setWalletModel(WalletModel* model);
    void refresh();

protected:
    virtual void resizeEvent(QResizeEvent *event) override;

private Q_SLOTS:
    void onStakeClicked();
    void onClearClicked();
    void onCancelClicked();
    void onThemeChanged();
    void onShowRequestClicked();

private:
    void init();
    void connectSignals();
    void onStakeError();
    void SendToAddress(const CTxDestination &address, CAmount nValue, int splitCount);
    void sendToSPoSAddress(const CBitcoinAddress &sposAddress);
    CBitcoinAddress GetNewAddress();

    std::unique_ptr<interfaces::PendingWalletTx> CreateContractTransaction(QWidget *widget,
                                          const CBitcoinAddress &sposAddress,
                                          const CBitcoinAddress &secureAddress,
                                          int secureCommission);

    std::unique_ptr<interfaces::PendingWalletTx> CreateCancelContractTransaction(QWidget *widget,
                                                const SPoSContract &contract);



private:
    Ui::SPoSPage *ui;
    WalletModel *_walletModel = nullptr;
    GUIUtil::TableViewLastColumnResizingFixer* _columnResizingFixer = nullptr;
    QPointer<SPoSAddressesTableModel> _addressesTableModel;
};

#endif // SPOSPAGE_H
