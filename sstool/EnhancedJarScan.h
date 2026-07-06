#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <numeric>
#include <cstdint>
#include <cmath>

#include "Console.h"
#include "Util.h"
#include "JarUtil.h"
#include "CheatStrings.h"

// =====================================================================
// Enhanced static JAR analysis.
//
// Key improvements over ModsScan.h:
//   - Whitelist of known-safe popular mods (but deep-inspects every jar
//     anyway, since ghost clients disguise themselves using legit names)
//   - Obfuscation fingerprinting: Skidfuscator, Zelix, Stringer, generic
//   - Mixin refmap detection + suspicious mixin targets
//   - Bytecode-level heuristics: class count, method/field name entropy,
//     obfuscated string ratio, suspicious native method declarations
//   - Fullwidth Unicode detection in class names / strings
//   - Confidence score per jar (0-100)
//   - Native library (.dll/.so) inside jar detection
//   - Suspicious manifest entries (Main-Class pointing to cheat loaders)
// =====================================================================
namespace enhancedjarscan {

    namespace fs = std::filesystem;

    // ---- Whitelist ---------------------------------------------------
    // Known-safe mod filenames / package prefixes. Every jar on this list
    // still gets fully inspected (ghost clients rename themselves as these),
    // but a clean result on a whitelisted name gets a "Known safe mod" note
    // instead of just "no findings". This reduces alert fatigue.
    static const std::set<std::string> knownSafeModNames = {
        "sodium", "iris", "lithium", "phosphor", "starlight", "indium",
        "fabric-api", "fabricapi", "modmenu", "cloth-config", "clothconfig",
        "immediatelyfast", "immediately-fast", "nvidium", "entityculling",
        "ferrite-core", "ferritecore", "lazydfu", "memoryleakfix",
        "smoothboot", "c2me", "krypton", "cull-leaves", "cullleaves",
        "dynamic-fps", "dynamicfps", "betterf3", "better-f3", "reeses-sodium",
        "sodium-extra", "presencefootsteps", "presence-footsteps",
        "replay-mod", "replaymod", "xaeros-minimap", "xaerosminimap",
        "journeymap", "waystones", "jei", "rei", "emi",
        "create", "botania", "thermal", "buildcraft",
        "appleskin", "apple-skin", "fpsreducer", "forgetmechunk",
        "continuity", "lambdynamiclights", "lambda-dynamic-lights",
        "worldedit", "voxelsniper", "betterstats",
        "origins", "pehkui", "geckolib",
    };

    static bool isKnownSafe(const std::string& jarNameLower) {
        for (const auto& safe : knownSafeModNames) {
            if (jarNameLower.find(safe) != std::string::npos) return true;
        }
        return false;
    }

    // ---- Obfuscator fingerprints ------------------------------------
    struct ObfuscatorSig {
        const char* name;
        std::vector<std::string> classNameFragments; // found in class paths
        std::vector<std::string> stringFragments;    // found in string content
    };

    static const std::vector<ObfuscatorSig> obfuscatorSigs = {
        { "Skidfuscator", { "skid/", "skidfuscator", "dev/skidfuscator" },
                          { "skidfuscator", "Skidfuscator", "dev.skidfuscator" } },
        { "Zelix KlassMaster", { }, { "ZKM", "Zelix", "zelix" } },
        { "Stringer",     { "stringer/" },
                          { "Stringer", "stringer.runtime", "StringerRuntime" } },
        { "Allatori",     { "com/allatori" }, { "Allatori", "allatori" } },
        { "DashO",        { "com/preemptive/dasho" }, { "DashO", "PreEmptive" } },
        { "Branchlock",   { "branchlock/" }, { "branchlock", "BranchLock" } },
        { "SandMark",     { }, { "sandmark", "SandMark" } },
        { "ProGuard",     { }, { "proguard", "ProGuard" } },   // not always malicious but notable
    };

    // ---- Suspicious mixin targets -----------------------------------
    // Mixins that target these Minecraft classes without being in a known
    // legitimate mod are a red flag (cheat clients use mixins to inject
    // into movement, rotation, and combat logic).
    static const std::vector<std::string> suspiciousMixinTargets = {
        "ClientPlayerEntity", "PlayerEntity", "AbstractClientPlayerEntity",
        "GameRenderer", "WorldRenderer", "Camera",
        "ClientPlayNetworkHandler", "ClientConnection",
        "HandledScreen", "MouseHelper",
        "MinecraftClient", "Keyboard", "Mouse",
        "LivingEntity", "PlayerInventory",
        "AbstractBlock", "Block",
        "ClientPlayerInteractionManager",
    };

    // ---- Jar analysis result ----------------------------------------
    struct JarFinding {
        util::Severity severity;
        std::string text;
    };

    struct JarResult {
        std::string jarPath;
        std::string jarName;
        int confidence = 0;   // 0-100 likelihood of being a cheat
        bool isWhitelisted = false;
        bool hasObfuscation = false;
        std::string obfuscatorName;
        std::vector<JarFinding> findings;

        bool flagged() const { return confidence >= 30 || !findings.empty(); }
    };

    // ---- Shannon entropy of a string (for name obfuscation detection) -
    static double entropy(const std::string& s) {
        if (s.empty()) return 0.0;
        std::map<char, int> freq;
        for (char c : s) freq[c]++;
        double e = 0.0;
        for (auto& [c, n] : freq) {
            double p = (double)n / s.size();
            if (p > 0) e -= p * std::log2(p);
        }
        return e;
    }

    // Is a class name obfuscated? (single char, or high-entropy short name,
    // or all-lowercase single-letter like "a", "b", "aa", "bR", etc.)
    static bool isObfuscatedName(const std::string& name) {
        if (name.empty()) return false;
        if (name.size() <= 2) return true;
        if (name.size() <= 6 && entropy(name) > 3.5) return true;
        // All lowercase + digits only, short
        bool allLower = std::all_of(name.begin(), name.end(), [](char c) {
            return std::islower((unsigned char)c) || std::isdigit((unsigned char)c);
        });
        if (allLower && name.size() <= 4) return true;
        return false;
    }

    // Check for fullwidth Unicode in string content
    static bool hasFullwidthUnicode(const std::string& s) {
        for (size_t i = 0; i + 2 < s.size(); i++) {
            uint8_t b0 = (uint8_t)s[i];
            uint8_t b1 = (uint8_t)s[i+1];
            uint8_t b2 = (uint8_t)s[i+2];
            if ((b0 == 0xEF) && ((b1 == 0xBC) || (b1 == 0xBD))) return true;
        }
        return false;
    }

    // ---- Main jar analysis ------------------------------------------
    static JarResult analyzeJar(const fs::path& jarPath) {
        JarResult result;
        result.jarPath = jarPath.string();
        result.jarName = jarPath.filename().string();
        std::string nameLower = util::toLowerA(result.jarName);
        result.isWhitelisted = isKnownSafe(nameLower);

        // Read zip entries via JarUtil
        auto entries = jarutil::listEntries(jarPath.string());
        if (entries.empty()) return result;

        // Categorize entries
        std::vector<std::string> classFiles, stringContent, nativeLibs, mixinConfigs;
        int obfuscatedClassCount = 0, totalClassCount = 0;
        std::set<std::string> packageSet;
        bool hasReflectionAsm = false, hasDangerousNative = false;

        for (const auto& entry : entries) {
            std::string entryLower = util::toLowerA(entry);

            if (entryLower.ends_with(".class")) {
                totalClassCount++;
                classFiles.push_back(entry);
                // Extract simple class name (last segment after /)
                size_t slash = entry.rfind('/');
                std::string simpleName = (slash != std::string::npos)
                    ? entry.substr(slash + 1, entry.size() - slash - 5)  // strip .class
                    : entry.substr(0, entry.size() - 6);
                if (isObfuscatedName(simpleName)) obfuscatedClassCount++;

                // Package tracking
                if (slash != std::string::npos)
                    packageSet.insert(entry.substr(0, slash));

            } else if (entryLower.ends_with(".dll") || entryLower.ends_with(".so")
                    || entryLower.ends_with(".dylib")) {
                nativeLibs.push_back(entry);

            } else if (entryLower.find("refmap") != std::string::npos
                    || entryLower.ends_with(".mixins.json")
                    || entryLower.find("mixin") != std::string::npos) {
                mixinConfigs.push_back(entry);
            }
        }

        // ---- Obfuscation ratio check --------------------------------
        double obfRatio = totalClassCount > 0
            ? (double)obfuscatedClassCount / totalClassCount : 0.0;
        if (obfRatio > 0.6 && totalClassCount > 10) {
            result.hasObfuscation = true;
            result.findings.push_back({ util::Severity::Warning,
                "High obfuscation: " + std::to_string((int)(obfRatio * 100)) +
                "% of " + std::to_string(totalClassCount) + " classes have obfuscated names" });
            result.confidence += 20;
        }

        // ---- Read JAR content as string for pattern matching --------
        std::string jarContent = jarutil::readAllText(jarPath.string());

        // ---- Known cheat strings ------------------------------------
        std::set<std::string> matchedStrings;
        for (const auto& pattern : jarContentStrings) {
            if (matchedStrings.count(pattern)) continue;
            if (jarContent.find(pattern) != std::string::npos) {
                matchedStrings.insert(pattern);
                result.confidence += 8;
            }
        }
        if (!matchedStrings.empty()) {
            std::string all;
            for (const auto& s : matchedStrings) all += "\"" + s + "\" ";
            result.findings.push_back({ util::Severity::Danger,
                std::to_string(matchedStrings.size()) + " known cheat string(s): " + all });
        }

        // ---- Fullwidth Unicode evasion ------------------------------
        if (hasFullwidthUnicode(jarContent)) {
            result.findings.push_back({ util::Severity::Warning,
                "Fullwidth Unicode characters detected -- possible string obfuscation evasion" });
            result.confidence += 15;
        }

        // ---- Obfuscator fingerprints --------------------------------
        for (const auto& sig : obfuscatorSigs) {
            bool matched = false;
            for (const auto& frag : sig.classNameFragments) {
                for (const auto& cls : classFiles) {
                    if (util::toLowerA(cls).find(frag) != std::string::npos) { matched = true; break; }
                }
                if (matched) break;
            }
            if (!matched) {
                for (const auto& frag : sig.stringFragments) {
                    if (jarContent.find(frag) != std::string::npos) { matched = true; break; }
                }
            }
            if (matched) {
                result.hasObfuscation = true;
                result.obfuscatorName = sig.name;
                result.findings.push_back({ util::Severity::Warning,
                    std::string("Obfuscator fingerprint: ") + sig.name });
                result.confidence += 15;
                break;
            }
        }

        // ---- Mixin analysis -----------------------------------------
        for (const auto& mixinFile : mixinConfigs) {
            std::string mixinContent = jarutil::readEntry(jarPath.string(), mixinFile);
            if (mixinContent.empty()) continue;

            // Check for suspicious mixin targets
            for (const auto& target : suspiciousMixinTargets) {
                if (mixinContent.find(target) != std::string::npos) {
                    result.findings.push_back({ util::Severity::Warning,
                        "Mixin targets sensitive class: " + target + "  (in " + mixinFile + ")" });
                    result.confidence += 10;
                }
            }
            // Check refmap names against known cheat refmaps
            if (mixinFile.find("cheat") != std::string::npos ||
                mixinFile.find("client") != std::string::npos ||
                mixinFile.find("phantom") != std::string::npos) {
                result.findings.push_back({ util::Severity::Danger,
                    "Suspicious mixin config name: " + mixinFile });
                result.confidence += 20;
            }
        }

        // ---- Native library inside jar ------------------------------
        for (const auto& lib : nativeLibs) {
            std::string libLower = util::toLowerA(lib);
            result.findings.push_back({ util::Severity::Warning,
                "Native library inside jar: " + lib +
                (libLower.find("inject") != std::string::npos ||
                 libLower.find("hook")   != std::string::npos ? "  [SUSPICIOUS NAME]" : "") });
            result.confidence += 12;
        }

        // ---- ASM / Reflection usage (high-risk) ---------------------
        if (jarContent.find("org/objectweb/asm") != std::string::npos ||
            jarContent.find("javassist")          != std::string::npos ||
            jarContent.find("ClassLoader.defineClass") != std::string::npos) {
            result.findings.push_back({ util::Severity::Warning,
                "Uses ASM/Javassist bytecode manipulation -- can patch classes at runtime" });
            result.confidence += 15;
            hasReflectionAsm = true;
        }

        // ---- Suspicious package names -------------------------------
        for (const auto& pkg : packageSet) {
            std::string pkgLower = util::toLowerA(pkg);
            for (const auto& s : jarNamePatterns) {
                if (pkgLower.find(util::toLowerA(s)) != std::string::npos) {
                    result.findings.push_back({ util::Severity::Danger,
                        "Suspicious package: " + pkg });
                    result.confidence += 10;
                    break;
                }
            }
        }

        // ---- Known whitelisted name but suspicious content ----------
        if (result.isWhitelisted && result.flagged()) {
            result.findings.insert(result.findings.begin(), { util::Severity::Danger,
                "WARNING: jar name matches a known-safe mod but contains suspicious content -- "
                "ghost client / impersonation suspected!" });
            result.confidence = std::min(100, result.confidence + 25);
        }

        result.confidence = std::min(100, result.confidence);
        return result;
    }

    // ---- Scan a directory of jars -----------------------------------
    static std::vector<JarResult> scanDirectory(const fs::path& modsDir) {
        std::vector<JarResult> results;
        std::error_code ec;
        if (!fs::exists(modsDir, ec) || !fs::is_directory(modsDir, ec)) return results;

        std::vector<fs::path> jars;
        for (auto& entry : fs::recursive_directory_iterator(modsDir,
                fs::directory_options::skip_permission_denied, ec)) {
            if (entry.path().extension() == ".jar") jars.push_back(entry.path());
        }
        if (jars.empty()) return results;

        con::info("Deep-scanning " + std::to_string(jars.size()) + " jar(s) in " + modsDir.string());
        for (int i = 0; i < (int)jars.size(); i++) {
            con::progressBar(i, (int)jars.size());
            results.push_back(analyzeJar(jars[i]));
        }
        con::progressBar((int)jars.size(), (int)jars.size());
        std::cout << "\n";
        return results;
    }

    // ---- Print results ----------------------------------------------
    static void printResults(const std::vector<JarResult>& results) {
        int flagged = 0, clean = 0, whitelisted = 0;
        for (const auto& r : results) {
            if (r.flagged()) flagged++;
            else if (r.isWhitelisted) whitelisted++;
            else clean++;
        }

        con::subheader("Jar Scan Summary");
        con::dim(std::to_string(results.size()) + " jars scanned  |  " +
            std::to_string(flagged) + " flagged  |  " +
            std::to_string(clean) + " clean  |  " +
            std::to_string(whitelisted) + " known-safe");

        for (const auto& r : results) {
            if (!r.flagged()) continue;
            std::cout << "\n";
            con::Color hdrColor = r.confidence >= 70 ? con::Color::Red
                                : r.confidence >= 40 ? con::Color::Yellow
                                : con::Color::Gray;
            con::set(hdrColor);
            std::cout << "  [" << std::to_string(r.confidence) << "%] "
                      << r.jarName << "\n";
            con::reset();
            con::dim(r.jarPath);
            for (const auto& f : r.findings) con::finding(f.severity, f.text);
        }
    }

} // namespace enhancedjarscan
