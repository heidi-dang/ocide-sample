#include "spospage.h"
#include "forms/ui_spospage.h"
#include "util.h"
#include "base58.h"
#include "utilstrencodings.h"
#include "spos/sposutils.h"
#include "init.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include "sposaddressestablemodel.h"
#include "guiutil.h"
#include "script/sign.h"
#include "guiutil.h"
#include "net.h"
#include "utilmoneystr.h"
#include <interfaces/wallet.h>
#include <wallet/coincontrol.h>

#include <boost/optional.hpp>
#include <QPushButton>
#include <QString>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMessageBox>
#include <QItemSelectionModel>
#include <QFile>
#include <fstream>

namespace ColumnWidths {
enum Values {
    MINIMUM_COLUMN_WIDTH = 120,
    ADDRESS_COLUMN_WIDTH = 240,
    AMOUNT_MINIMUM_COLUMN_WIDTH = 200,
};
}

static QString PrepareCreateContractQuestionString(const CBitcoinAddress &sposAddress,
                                                   const CBitcoinAddress &secureAddress,
                                                   int commission)
{
    QString questionString = QObject::tr("Are you sure you want to setup spos contract?");
    questionString.append("<br /><br />");

    // Show total amount + all alternative units
    questionString.append(QObject::tr("SPoS Address = <b>%1</b><br />Secure address = <b>%2</b> <br />Secure commission = <b>%3</b>")
                          .arg(QString::fromStdString(sposAddress.ToString()))
                          .arg(QString::fromStdString(secureAddress.ToString()))
                          .arg(commission));


    return questionString;
}

std::unique_ptr<interfaces::PendingWalletTx> SPoSPage::CreateContractTransaction(QWidget *widget,
                                                                                 const CBitcoinAddress &sposAddress,
                                                                                 const CBitcoinAddress &secureAddress,
                                                                                 int secureCommission)
{
    std::string strError;
    auto questionString = PrepareCreateContractQuestionString(sposAddress, secureAddress, secureCommission);
    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(widget, QObject::tr("Confirm creating spos contract"),
                                                               questionString,
                                                               QMessageBox::Yes | QMessageBox::Cancel,
                                                               QMessageBox::Cancel);
    if(retval != QMessageBox::Yes)
    {
        return {};
    }
    if(auto walletTx =  _walletModel->wallet().createSPoSContractTransaction(sposAddress.Get(), secureAddress.Get(), secureCommission, strError))  {
        return walletTx;
    }

    throw std::runtime_error(QString("Failed to create spos transaction: %1").arg(QString::fromStdString(strError)).toStdString());
}

std::unique_ptr<interfaces::PendingWalletTx> SPoSPage::CreateCancelContractTransaction(QWidget *widget,
                                                                                       const SPoSContract &contract)
{
    std::string strError;
    auto questionString = QString("Are you sure you want to cancel contract with address: <b>%1</b>").arg(contract.sposAddress.ToString().c_str());
    // Display message box
    QMessageBox::StandardButton retval = QMessageBox::question(widget, QObject::tr("Confirm canceling spos contract"),
                                                               questionString,
                                                               QMessageBox::Yes | QMessageBox::Cancel,
                                                               QMessageBox::Cancel);
    if(retval != QMessageBox::Yes)
    {
        return {};
    }

    if(auto walletTx = _walletModel->wallet().createCancelContractTransaction(contract, strError))
    {
        return walletTx;
    }

    throw std::runtime_error(QString("Failed to create spos transaction: %1").arg(QString::fromStdString(strError)).toStdString());
}

static void SendPendingTransaction(interfaces::PendingWalletTx *pendingTx)
{
    std::string rejectReason;
    if (!pendingTx->commit({}, {}, {}, rejectReason))
        throw std::runtime_error(rejectReason);
}

void SPoSPage::SendToAddress(const CTxDestination &address, CAmount nValue, int splitCount)
{
    CAmount curBalance = _walletModel->wallet().getBalance();

    // Check amount
    if (nValue <= 0)
        throw std::runtime_error("Invalid amount");

    if (nValue > curBalance)
        throw std::runtime_error("Insufficient funds");

    if (!g_connman)
        std::runtime_error("Error: Peer-to-peer functionality missing or disabled");

    // Parse OCIDE address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    //    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;

    for (int i = 0; i < splitCount; ++i)
    {
        if (i == splitCount - 1)
        {
            uint64_t nRemainder = nValue % splitCount;
            vecSend.push_back({scriptPubKey, static_cast<CAmount>(nValue / splitCount + nRemainder), false});
        }
        else
        {
            vecSend.push_back({scriptPubKey, static_cast<CAmount>(nValue / splitCount), false});
        }
    }

    auto penWalletTx = _walletModel->wallet().createTransaction(vecSend, {}, true, nChangePosRet, nFeeRequired, strError);
    if(!penWalletTx)
    {
        if (nValue + nFeeRequired > _walletModel->wallet().getBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw std::runtime_error(strError);
    }
    SendPendingTransaction(penWalletTx.get());
}

CBitcoinAddress SPoSPage::GetNewAddress()
{
    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!_walletModel->wallet().getKeyFromPool(false, newKey))
        throw std::runtime_error("Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();


    _walletModel->wallet().setAddressBook(keyID, std::string(), "spos address");
    //pwalletMain->SetAddressBook(keyID, std::string(), "spos address");

    return CBitcoinAddress(keyID);
}

SPoSPage::SPoSPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SPoSPage)
{
    ui->setupUi(this);
    init();
}

SPoSPage::~SPoSPage()
{
    delete ui;
}

void SPoSPage::setWalletModel(WalletModel *model)
{
    _addressesTableModel = model->getSPoSAddressModel();
    _walletModel = model;
    ui->stakingAddressesView->setModel(_addressesTableModel);

    using namespace ColumnWidths;
    _columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(ui->stakingAddressesView, AMOUNT_MINIMUM_COLUMN_WIDTH, MINIMUM_COLUMN_WIDTH, this);

    ui->stakingAddressesView->setColumnWidth(SPoSAddressesTableModel::Address, ADDRESS_COLUMN_WIDTH);
    ui->stakingAddressesView->setColumnWidth(SPoSAddressesTableModel::AmountStaked, MINIMUM_COLUMN_WIDTH);
    ui->stakingAddressesView->setColumnWidth(SPoSAddressesTableModel::CommissionPaid, MINIMUM_COLUMN_WIDTH);
    ui->stakingAddressesView->setColumnWidth(SPoSAddressesTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);
}

void SPoSPage::refresh()
{
    _addressesTableModel->updateModel();
}

void SPoSPage::onStakeClicked()
{
    try
    {
        auto worker = [this]() {
            //            CReserveKey reserveKey(pwalletMain);
            CBitcoinAddress sposAddress = GetNewAddress();
            if(!sposAddress.IsValid())
            {
                throw std::runtime_error("Critical error, SPoS address is empty");
            }
            CBitcoinAddress secureAddress(ui->secureAddress->text().toStdString());
            if(!secureAddress.IsValid())
            {
                throw std::runtime_error("Critical error, secure address is empty");
            }
            auto secureCommission = ui->secureCut->value();
            if(auto penWalletTx = CreateContractTransaction(this, sposAddress, secureAddress, secureCommission))
            {
                SendPendingTransaction(penWalletTx.get());
                sendToSPoSAddress(sposAddress);
            }
        };

        if (_walletModel->getEncryptionStatus() == WalletModel::Locked)
        {
            WalletModel::UnlockContext ctx(_walletModel->requestUnlock());
            if (!ctx.isValid())
            {
                //unlock was cancelled
                throw std::runtime_error("Wallet is locked and user declined to unlock. Can't redeem from SPoS address.");
            }

            worker();
        }
        else
        {
            worker();
        }
    }
    catch(std::exception &ex)
    {
        QMessageBox::warning(this, "SPoS", ex.what());
    }
}

void SPoSPage::onClearClicked()
{

}

void SPoSPage::onCancelClicked()
{
    auto selectedIndexes = ui->stakingAddressesView->selectionModel()->selectedRows();

    if(selectedIndexes.empty())
        return;

    auto worker = [this, &selectedIndexes] {
        //CReserveKey reserveKey(pwalletMain);
        auto contract = _addressesTableModel->contractByIndex(selectedIndexes.first().row());
        //CWalletTx wtxNew;
        if(auto penWalletTx = CreateCancelContractTransaction(this, contract))
        {
            SendPendingTransaction(penWalletTx.get());
        }
    };

    try
    {
        if (_walletModel->getEncryptionStatus() == WalletModel::Locked)
        {
            WalletModel::UnlockContext ctx(_walletModel->requestUnlock());
            if (!ctx.isValid())
            {
                //unlock was cancelled
                QMessageBox::warning(this, tr("SPoS"),
                                     tr("Wallet is locked and user declined to unlock. Can't redeem from SPoS address."),
                                     QMessageBox::Ok, QMessageBox::Ok);

                return;
            }
            worker();
        }
        else
        {
            worker();
        }
    }
    catch(std::exception &ex)
    {
        QMessageBox::warning(this, "SPoS", ex.what());
    }
}

void SPoSPage::onThemeChanged()
{
    auto themeName = GUIUtil::getThemeName();
    ui->label->setPixmap(QPixmap(
                             QString(
                                 ":/images/res/images/pages/spos/%1/spos-header.png").arg(themeName)));
}

void SPoSPage::onShowRequestClicked()
{
    return;
    QItemSelectionModel *selectionModel = ui->stakingAddressesView->selectionModel();
    auto rows = selectionModel->selectedRows();
    if(!rows.empty())
    {
        QModelIndex index = rows.first();
        QString address = index.data(SPoSAddressesTableModel::Address).toString();
    }

}

void SPoSPage::init()
{
    connectSignals();
    onThemeChanged();
}

void SPoSPage::connectSignals()
{
    connect(ui->stakeButton, &QPushButton::clicked, this, &SPoSPage::onStakeClicked);
    connect(ui->clearButton, &QPushButton::clicked, this, &SPoSPage::onClearClicked);
    //    connect(ui->showRequestButton, &QPushButton::clicked, this, &SPoSPage::onShowRequestClicked);
    connect(ui->cancelButton, &QPushButton::clicked, this, &SPoSPage::onCancelClicked);
}

void SPoSPage::onStakeError()
{
    //    ui->stakeButton->setEnabled(false);
}


void SPoSPage::sendToSPoSAddress(const CBitcoinAddress &sposAddress)
{
    CAmount amount = ui->stakingAmount->value();
    int numberOfSplits = 1;
    if(amount > _walletModel->wallet().getStakeSplitThreshold() * COIN)
        numberOfSplits = std::min<unsigned int>(500, amount / (_walletModel->wallet().getStakeSplitThreshold() * COIN));
    SendToAddress(sposAddress.Get(), amount, numberOfSplits);
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void SPoSPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    if(_columnResizingFixer)
        _columnResizingFixer->stretchColumnWidth(SPoSAddressesTableModel::CommissionPaid);
}
