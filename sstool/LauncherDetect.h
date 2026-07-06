#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <sstream>

#include "Console.h"
#include "Util.h"

// =====================================================================
// Minecraft launcher auto-detection.
//
// Detects all major launchers + their active instances, mods folders,
// and version folders. Supports:
//   - Official Minecraft Launcher
//   - Modrinth App
//   - Lunar Client
//   - Feather Client
//   - Prism / MultiMC / PolyMC
//   - CurseForge / Overwolf
//   - ATLauncher
//   - GDLauncher
//   - Badlion Client
//   - Custom path fallback
// =====================================================================
namespace launcherdetect {

    namespace fs = std::filesystem;

    struct MinecraftInstance {
        std::string launcherName;
        std::string instanceName;   // e.g. "1.21.4" or "SkyWars Pack"
        std::string version;        // e.g. "1.21.4"
        fs::path    rootDir;        // .minecraft or instance root
        fs::path    modsDir;
        fs::path    configDir;
        fs::path    logsDir;
        fs::path    crashReportsDir;
        bool        isActive = false; // true if currently running Minecraft version
    };

    static fs::path expandEnv(const std::wstring& raw) {
        wchar_t buf[MAX_PATH * 2];
        DWORD n = ExpandEnvironmentStringsW(raw.c_str(), buf, MAX_PATH * 2);
        if (n == 0) return {};
        return fs::path(std::wstring(buf, n - 1));
    }

    static std::string wstr(const fs::path& p) {
        return p.string();
    }

    // Read a UTF-8 text file into a string
    static std::string readFile(const fs::path& p) {
        std::ifstream f(p);
        if (!f.is_open()) return {};
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    // Quick JSON value extractor -- no full JSON lib, just finds
    // "key": "value" or "key": non-quoted-value in a flat string.
    static std::string jsonGet(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return {};
        pos += search.size();
        // skip whitespace and colon
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) pos++;
        if (pos >= json.size()) return {};
        if (json[pos] == '"') {
            pos++;
            size_t end = json.find('"', pos);
            if (end == std::string::npos) return {};
            return json.substr(pos, end - pos);
        }
        // unquoted value (number, bool)
        size_t end = pos;
        while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != '\n') end++;
        std::string v = json.substr(pos, end - pos);
        // trim
        v.erase(0, v.find_first_not_of(" \t\r\n"));
        v.erase(v.find_last_not_of(" \t\r\n") + 1);
        return v;
    }

    static MinecraftInstance makeInstance(const std::string& launcher,
                                          const std::string& name,
                                          const std::string& version,
                                          const fs::path& root,
                                          bool active = false) {
        MinecraftInstance inst;
        inst.launcherName    = launcher;
        inst.instanceName    = name;
        inst.version         = version;
        inst.rootDir         = root;
        inst.modsDir         = root / "mods";
        inst.configDir       = root / "config";
        inst.logsDir         = root / "logs";
        inst.crashReportsDir = root / "crash-reports";
        inst.isActive        = active;
        return inst;
    }

    // ---- 1. Official Minecraft Launcher ------------------------------
    static std::vector<MinecraftInstance> detectOfficialLauncher() {
        std::vector<MinecraftInstance> out;
        std::error_code ec;

        // Common .minecraft paths
        std::vector<fs::path> candidates = {
            expandEnv(L"%APPDATA%\\.minecraft"),
            expandEnv(L"%USERPROFILE%\\AppData\\Roaming\\.minecraft"),
        };

        for (const auto& mc : candidates) {
            if (!fs::exists(mc / "launcher_profiles.json", ec)) continue;

            std::string profilesJson = readFile(mc / "launcher_profiles.json");
            // Try to find the lastUsed profile version
            std::string lastVersion;
            size_t profilesPos = profilesJson.find("\"profiles\"");
            if (profilesPos != std::string::npos) {
                // Find "lastVersionId" in the profiles block
                size_t vPos = profilesJson.find("\"lastVersionId\"", profilesPos);
                if (vPos != std::string::npos) {
                    vPos += 16;
                    while (vPos < profilesJson.size() && profilesJson[vPos] != '"') vPos++;
                    if (vPos < profilesJson.size()) {
                        vPos++;
                        size_t vEnd = profilesJson.find('"', vPos);
                        if (vEnd != std::string::npos)
                            lastVersion = profilesJson.substr(vPos, vEnd - vPos);
                    }
                }
            }

            out.push_back(makeInstance("Official Launcher", "default", lastVersion, mc));
        }
        return out;
    }

    // ---- 2. Modrinth App --------------------------------------------
    static std::vector<MinecraftInstance> detectModrinth() {
        std::vector<MinecraftInstance> out;
        std::error_code ec;
        fs::path base = expandEnv(L"%APPDATA%\\com.modrinth.theseus");
        if (!fs::exists(base, ec)) base = expandEnv(L"%APPDATA%\\Modrinth App");
        if (!fs::exists(base, ec)) return out;

        fs::path profiles = base / "profiles";
        if (!fs::exists(profiles, ec)) return out;

        for (auto& entry : fs::directory_iterator(profiles, fs::directory_options::skip_permission_denied, ec)) {
            if (!entry.is_directory(ec)) continue;
            fs::path profileJson = entry.path() / "profile.json";
            if (!fs::exists(profileJson, ec)) continue;
            std::string json = readFile(profileJson);
            std::string name    = jsonGet(json, "name");
            std::string version = jsonGet(json, "game_version");
            if (name.empty()) name = entry.path().filename().string();
            out.push_back(makeInstance("Modrinth App", name, version, entry.path()));
        }
        return out;
    }

    // ---- 3. Prism / MultiMC / PolyMC --------------------------------
    static std::vector<MinecraftInstance> detectPrismFamily() {
        std::vector<MinecraftInstance> out;
        std::error_code ec;

        std::vector<std::pair<std::string, fs::path>> roots = {
            { "Prism Launcher", expandEnv(L"%APPDATA%\\PrismLauncher") },
            { "MultiMC",        expandEnv(L"%APPDATA%\\MultiMC") },
            { "PolyMC",         expandEnv(L"%APPDATA%\\PolyMC") },
            // Portable installs
            { "Prism Launcher", expandEnv(L"%USERPROFILE%\\Desktop\\PrismLauncher") },
        };

        for (auto& [launcherName, root] : roots) {
            fs::path instances = root / "instances";
            if (!fs::exists(instances, ec)) continue;

            for (auto& entry : fs::directory_iterator(instances, fs::directory_options::skip_permission_denied, ec)) {
                if (!entry.is_directory(ec)) continue;
                fs::path cfgPath = entry.path() / "instance.cfg";
                std::string version;
                std::string name = entry.path().filename().string();
                if (fs::exists(cfgPath, ec)) {
                    std::string cfg = readFile(cfgPath);
                    // Parse "IntendedVersion=1.21.4"
                    size_t vp = cfg.find("IntendedVersion=");
                    if (vp != std::string::npos) {
                        vp += 16;
                        size_t ve = cfg.find_first_of("\r\n", vp);
                        version = cfg.substr(vp, ve - vp);
                    }
                    size_t np = cfg.find("name=");
                    if (np != std::string::npos) {
                        np += 5;
                        size_t ne = cfg.find_first_of("\r\n", np);
                        name = cfg.substr(np, ne - np);
                    }
                }
                // Prism/MultiMC store the actual .minecraft at instances/<name>/.minecraft
                fs::path mc = entry.path() / ".minecraft";
                if (!fs::exists(mc, ec)) mc = entry.path();
                out.push_back(makeInstance(launcherName, name, version, mc));
            }
        }
        return out;
    }

    // ---- 4. CurseForge / Overwolf -----------------------------------
    static std::vector<MinecraftInstance> detectCurseForge() {
        std::vector<MinecraftInstance> out;
        std::error_code ec;
        std::vector<fs::path> roots = {
            expandEnv(L"%USERPROFILE%\\curseforge\\minecraft\\Instances"),
            expandEnv(L"%USERPROFILE%\\Documents\\curseforge\\minecraft\\Instances"),
            expandEnv(L"%USERPROFILE%\\Desktop\\CurseForge\\minecraft\\Instances"),
        };
        for (const auto& instances : roots) {
            if (!fs::exists(instances, ec)) continue;
            for (auto& entry : fs::directory_iterator(instances, fs::directory_options::skip_permission_denied, ec)) {
                if (!entry.is_directory(ec)) continue;
                std::string name = entry.path().filename().string();
                fs::path minecraftJson = entry.path() / "minecraftinstance.json";
                std::string version;
                if (fs::exists(minecraftJson, ec)) {
                    std::string json = readFile(minecraftJson);
                    version = jsonGet(json, "gameVersion");
                }
                out.push_back(makeInstance("CurseForge", name, version, entry.path()));
            }
        }
        return out;
    }

    // ---- 5. Lunar Client ---------------------------------------------
    static std::vector<MinecraftInstance> detectLunar() {
        std::vector<MinecraftInstance> out;
        std::error_code ec;
        fs::path lunarBase = expandEnv(L"%USERPROFILE%\\.lunarclient");
        if (!fs::exists(lunarBase, ec)) return out;

        // Lunar stores per-version data under offline/<version>
        fs::path offline = lunarBase / "offline";
        if (fs::exists(offline, ec)) {
            for (auto& entry : fs::directory_iterator(offline, fs::directory_options::skip_permission_denied, ec)) {
                if (!entry.is_directory(ec)) continue;
                std::string version = entry.path().filename().string();
                out.push_back(makeInstance("Lunar Client", version, version, entry.path()));
            }
        }
        return out;
    }

    // ---- 6. Feather Client ------------------------------------------
    static std::vector<MinecraftInstance> detectFeather() {
        std::vector<MinecraftInstance> out;
        std::error_code ec;
        std::vector<fs::path> roots = {
            expandEnv(L"%APPDATA%\\feather"),
            expandEnv(L"%APPDATA%\\.feather"),
        };
        for (const auto& r : roots) {
            if (!fs::exists(r, ec)) continue;
            out.push_back(makeInstance("Feather Client", "default", "", r));
        }
        return out;
    }

    // ---- 7. ATLauncher / GDLauncher ---------------------------------
    static std::vector<MinecraftInstance> detectOtherLaunchers() {
        std::vector<MinecraftInstance> out;
        std::error_code ec;
        std::vector<std::pair<std::string,fs::path>> known = {
            { "ATLauncher",  expandEnv(L"%APPDATA%\\ATLauncher\\instances") },
            { "GDLauncher",  expandEnv(L"%APPDATA%\\gdlauncher_next\\instances") },
            { "Badlion",     expandEnv(L"%APPDATA%\\.minecraft_badlion") },
            { "Technic",     expandEnv(L"%APPDATA%\\.technic\\modpacks") },
            { "SKLauncher",  expandEnv(L"%APPDATA%\\.sklauncher") },
        };
        for (auto& [name, base] : known) {
            if (!fs::exists(base, ec)) continue;
            if (fs::is_directory(base, ec)) {
                // If it contains instance folders, enumerate them
                bool hasSubdirs = false;
                for (auto& e : fs::directory_iterator(base, fs::directory_options::skip_permission_denied, ec)) {
                    if (e.is_directory(ec)) {
                        out.push_back(makeInstance(name, e.path().filename().string(), "", e.path()));
                        hasSubdirs = true;
                    }
                }
                if (!hasSubdirs) out.push_back(makeInstance(name, "default", "", base));
            }
        }
        return out;
    }

    // ---- Cross-check with running processes to mark active instances -
    static void markActiveInstances(std::vector<MinecraftInstance>& instances) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return;

        std::vector<std::pair<DWORD, std::wstring>> javaPids;
        PROCESSENTRY32W pe{ sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring name = pe.szExeFile;
                std::wstring lo = name;
                std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
                if (lo == L"java.exe" || lo == L"javaw.exe" || lo == L"minecraft.exe")
                    javaPids.push_back({ pe.th32ProcessID, name });
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        for (auto& inst : instances) {
            for (auto& [pid, exeName] : javaPids) {
                // Check if the process has an open handle to a file under this instance's root
                HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (!proc) continue;
                wchar_t pathBuf[MAX_PATH];
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(proc, 0, pathBuf, &pathLen)) {
                    std::wstring procPath(pathBuf, pathLen);
                    std::string procPathA = util::wideToUtf8(procPath);
                    std::string instRoot  = inst.rootDir.string();
                    // Simple heuristic: process lives near the instance root
                    if (util::toLowerA(procPathA).find(util::toLowerA(instRoot.substr(0, std::min((int)instRoot.size(), 20)))) != std::string::npos)
                        inst.isActive = true;
                }
                CloseHandle(proc);
            }
        }
    }

    // ---- Main entry point -------------------------------------------
    static std::vector<MinecraftInstance> detectAll() {
        std::vector<MinecraftInstance> all;
        auto append = [&](std::vector<MinecraftInstance> v) {
            all.insert(all.end(), v.begin(), v.end());
        };
        append(detectOfficialLauncher());
        append(detectModrinth());
        append(detectPrismFamily());
        append(detectCurseForge());
        append(detectLunar());
        append(detectFeather());
        append(detectOtherLaunchers());
        markActiveInstances(all);
        return all;
    }

    // ---- Print instance list ----------------------------------------
    static void printInstances(const std::vector<MinecraftInstance>& instances) {
        if (instances.empty()) {
            con::warn("No Minecraft installations found.");
            return;
        }
    static void printInstances(const std::vector<MinecraftInstance>& instances) {
        if (instances.empty()) {
            con::warn("No Minecraft installations found.");
            return;
        }
        for (size_t i = 0; i < instances.size(); i++) {
            const auto& inst = instances[i];
            std::error_code ec;
            bool hasMods = fs::exists(inst.modsDir, ec) && fs::is_directory(inst.modsDir, ec);
            std::string label = "[" + std::to_string(i+1) + "] "
                + inst.launcherName + " -- " + inst.instanceName;
            if (!inst.version.empty()) label += "  (" + inst.version + ")";
            if (inst.isActive) {
                con::set(con::Color::Green);
                std::cout << "  " << label << "  [ACTIVE]\n";
                con::reset();
            } else {
                con::info(label);
            }
            con::dim(inst.rootDir.string());
            if (!hasMods) con::dim("  (no mods folder found)");
        }
    }

} // namespace launcherdetect
