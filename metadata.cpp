#include "metadata.h"
#include "json.hpp"
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

void save_cold_metadata(const std::string& name, const std::string& pubkey, std::time_t created) {
    std::string dir = std::string(getenv("HOME")) + "/.wallet/cold/";
    mkdir(dir.c_str(), 0700);

    std::string file = dir + "metadata.json";
    nlohmann::json arr;
    std::ifstream in(file);
    if (in) in >> arr;
    in.close();

    nlohmann::json entry;
    entry["name"] = name;
    entry["public_address"] = pubkey;
    entry["created"] = created;
    arr.push_back(entry);

    std::ofstream out(file);
    out << arr.dump(4);
    out.close();
    chmod(file.c_str(), 0600);
}

