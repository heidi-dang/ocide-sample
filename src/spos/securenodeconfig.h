#ifndef SRC_SECURENODECONFIG_H_
#define SRC_SECURENODECONFIG_H_

class CSecurenodeConfig;
extern CSecurenodeConfig securenodeConfig;

class CSecurenodeConfig
{

public:

    class CSecurenodeEntry {

    private:
        std::string alias;
        std::string ip;
        std::string securePrivKey;
        std::string hashContractTxId;

    public:

        CSecurenodeEntry(std::string alias, std::string ip, std::string securePrivKey, std::string hashContractTxId) {
            this->alias = alias;
            this->ip = ip;
            this->securePrivKey = securePrivKey;
            this->hashContractTxId = hashContractTxId;
        }

        const std::string& getAlias() const {
            return alias;
        }

        void setAlias(const std::string& alias) {
            this->alias = alias;
        }

        const std::string& getSecurePrivKey() const {
            return securePrivKey;
        }

        const std::string& getContractTxID() const {
            return this->hashContractTxId;
        }

        void setSecurePrivKey(const std::string& securePrivKey) {
            this->securePrivKey = securePrivKey;
        }

        const std::string& getIp() const {
            return ip;
        }

        void setIp(const std::string& ip) {
            this->ip = ip;
        }
    };

    CSecurenodeConfig() {
        entries = std::vector<CSecurenodeEntry>();
    }

    void clear();
    bool read(std::string& strErr);
    void add(std::string alias, std::string ip, std::string securePrivKey, std::string hashContractTxId);

    std::vector<CSecurenodeEntry>& getEntries() {
        return entries;
    }

    int getCount() {
        return (int)entries.size();
    }

private:
    std::vector<CSecurenodeEntry> entries;


};


#endif /* SRC_SECURENODECONFIG_H_ */
