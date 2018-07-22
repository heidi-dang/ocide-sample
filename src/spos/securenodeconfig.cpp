#include <netbase.h>
#include <spos/securenodeconfig.h>
#include <util.h>
#include <chainparams.h>
#include <utilstrencodings.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

CSecurenodeConfig securenodeConfig;

void CSecurenodeConfig::add(std::string alias, std::string ip, std::string securePrivKey, std::string hashContractTxId) {
    CSecurenodeEntry cme(alias, ip, securePrivKey, hashContractTxId);
    entries.push_back(cme);
}

bool CSecurenodeConfig::read(std::string& strErr) {
    int linenumber = 1;
    boost::filesystem::path pathSecurenodeConfigFile = GetSecurenodeConfigFile();
    boost::filesystem::ifstream streamConfig(pathSecurenodeConfigFile);

    if (!streamConfig.good()) {
        FILE* configFile = fopen(pathSecurenodeConfigFile.string().c_str(), "a");
        if (configFile != NULL) {
            std::string strHeader = "# Securenode config file\n"
                          "# Format: alias IP:port securePrivkey contractTxId\n"
                          "# Example: mn1 127.0.0.2:19999 \n";
            fwrite(strHeader.c_str(), std::strlen(strHeader.c_str()), 1, configFile);
            fclose(configFile);
        }
        return true;
    }

    for(std::string line; std::getline(streamConfig, line); linenumber++)
    {
        if(line.empty()) continue;

        std::istringstream iss(line);
        std::string comment, alias, ip, securePrivKey, hashContractTxId;

        if (iss >> comment) {
            if(comment.at(0) == '#') continue;
            iss.str(line);
            iss.clear();
        }

        if (!(iss >> alias >> ip >> securePrivKey >> hashContractTxId)) {
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> securePrivKey >> hashContractTxId)) {
                strErr = _("Could not parse securenode.conf") + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
                streamConfig.close();
                return false;
            }
        }

        int port = 0;
        std::string hostname = "";
        SplitHostPort(ip, port, hostname);
        if(port == 0 || hostname == "") {
            strErr = _("Failed to parse host:port string") + "\n"+
                    strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
            streamConfig.close();
            return false;
        }
        int mainnetDefaultPort = CreateChainParams(CBaseChainParams::MAIN)->GetDefaultPort();
        if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
            if(port != mainnetDefaultPort) {
                strErr = _("Invalid port detected in securenode.conf") + "\n" +
                        strprintf(_("Port: %d"), port) + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                        strprintf(_("(must be %d for mainnet)"), mainnetDefaultPort);
                streamConfig.close();
                return false;
            }
        } else if(port == mainnetDefaultPort) {
            strErr = _("Invalid port detected in securenode.conf") + "\n" +
                    strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                    strprintf(_("(%d could be used only on mainnet)"), mainnetDefaultPort);
            streamConfig.close();
            return false;
        }


        add(alias, ip, securePrivKey, hashContractTxId);
    }

    streamConfig.close();
    return true;
}
