#include "libraries/eacmoduleclient/eacmoduleclient.h"
#include <fstream>
#include <filesystem>
#include <map>
#include <set>


int main() {
    EACModuleClient ModHandler("https://modules-cdn.eac-prod.on.epicgames.com/modules/prod-fn/62a9473a2dca46b29ccf17577fcf42d7/win64");
    ModHandler.processModule();
    std::ofstream("EAC_Usermode.dll", std::ios::binary).write(reinterpret_cast<const char*>(ModHandler.getDecryptedUserModeDll().data()), ModHandler.getDecryptedUserModeDll().size());
    return 0;
}
