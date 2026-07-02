#include "PatternScan.h"
#include "ProcessScan.h"
#include "ModsScan.h"
#include "JvmScan.h"
#include "JavaProcessResolve.h"
#include "Console.h"
#include <filesystem>
#include <cstdlib>

// =====================================================================
// Pattern lists
//
// Rule for adding new strings (per README): a string must NOT be able to
// occur in vanilla Minecraft. Fully-qualified Java package/class names
// are the safest signal (0 false positive risk) because vanilla will
// never contain them. Long, specific description/tooltip strings are the
// next safest. Short generic words (e.g. "Speed", "Reach", "Sprint") are
// intentionally left out even though they appear in the client source,
// because those words alone can occur in unrelated vanilla/menu context
// and would cause false flags.
// =====================================================================

std::vector<std::string_view> novaPatterns = {
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "novaclient",
    "addFri",
    "antiAttack",
    "/assets/font/font.ttf", //also works for argon
    "Lithium is not initialized! Skipping event: ",
    "Error in hash"
};

// --- CrystalPvPHelper (net.crystalpvphelper) ---
std::vector<std::string_view> crystalPatterns = {
    "net.crystalpvphelper",
    "crystalpvphelper",
    "net.crystalpvphelper.module.ModuleManager",
    "net.crystalpvphelper.module.modules.combat.AnchorMacro",
    "net.crystalpvphelper.module.modules.combat.TriggerBot",
    "net.crystalpvphelper.module.modules.combat.AutoMace",
    "net.crystalpvphelper.module.modules.combat.WTap",
    "net.crystalpvphelper.module.modules.combat.Hitboxes",
    "net.crystalpvphelper.module.modules.combat.AimAssist",
    "net.crystalpvphelper.module.modules.combat.AutoInventoryTotem",
    "net.crystalpvphelper.module.modules.combat.AutoStun",
    "--- CrystalPvPHelper Commands ---",
    ".bind <module> <key> - Bind a module to a key",
    "Automated anchor explosion macro for Crystal PvP",
    "Automated Mace combat with density, breach, and crit mechanics",
    "Automatically breaks shields with an axe",
    "Expands player hitboxes and applies fake rotations",
    "Automatically attacks entities in crosshair",
    "Automatically resets sprint on hit for extra knockback"
};

// --- Noqwd / Skate client (hack.skate.client), includes AutoCrystal ---
std::vector<std::string_view> skatePatterns = {
    "hack.skate.client",
    "noqwdclient",
    "hack.skate.client.features.impl.combat.AnchorMacro",
    "hack.skate.client.features.impl.combat.AutoCrystal",
    "hack.skate.client.features.impl.combat.AutoCrystalV2",
    "hack.skate.client.features.impl.combat.AutoDoubleHand",
    "hack.skate.client.features.impl.combat.TriggerBot",
    "hack.skate.client.features.impl.combat.CrystalOptimizer",
    "hack.skate.client.features.impl.combat.BreachSwap",
    "hack.skate.client.features.impl.combat.AimAssistV2",
    "hack.skate.client.features.impl.client.SelfDestruct",
    "hack.skate.client.features.impl.client.ClickGUI",
    "Advanced smooth aim with movement prediction and AC bypass",
    "Bypasses stray's Anti-TriggerBot",
    "Stray Bypass"
};

// --- Argon (dev.lvstrng.argon) ---
// Argon encrypts most of its user-facing display strings at runtime
// (see dev.lvstrng.argon.utils.EncryptedString), so display names like
// "Anchor Macro" will usually NOT be readable in plaintext memory. The
// package/class names below are the reliable signal for this client.
// It also disguises its Fabric mod id as "immediatelyfast" to mimic the
// legitimate ImmediatelyFast performance mod, so the mod id alone is not
// a safe pattern to scan for.
std::vector<std::string_view> argonPatterns = {
    "dev.lvstrng.argon",
    "dev.lvstrng.argon.mixin",
    "dev.lvstrng.argon.module.ModuleManager",
    "dev.lvstrng.argon.module.modules.combat.AnchorMacro",
    "dev.lvstrng.argon.module.modules.combat.TriggerBotV2",
    "dev.lvstrng.argon.module.modules.combat.ShieldDisabler",
    "dev.lvstrng.argon.module.modules.combat.MaceStun",
    "dev.lvstrng.argon.module.modules.combat.AutoHitCrystal",
    "dev.lvstrng.argon.module.modules.combat.HoverTotem",
    "dev.lvstrng.argon.module.modules.client.SelfDestruct",
    "dev.lvstrng.argon.utils.EncryptedString"
};

// --- Shared across multiple clients (class-file signatures) ---
std::vector<std::string_view> universalPatterns = {
    "Auto Crystal",
    "Self Destruct",
    "Auto Anchor",
    "Auto Loot Yeeter",
    "CwCrystal.class",
    "ADH.class",
    "ModuleManager.class",
    "AnchorMacro.class",
    "TriggerBot.class",
    "AutoDoubleHand.class",
    "AutoInventoryTotem.class",
    "AutoCrystal.class",
    "SelfDestruct.class",
    "ClickGUI.class"
};

std::vector<std::string> clientList = {
    "Nova Client",
    "CrystalPvPHelper",
    "Noqwd / Skate Client (incl. AutoCrystal)",
    "Argon",
    "All (Might not work for all clients)"
};

void runMemoryScan() {
    HANDLE handle = resolveJavawTarget();
    if (!handle) return; // resolver already printed why

    std::cout << "Select Client To Scan For: \n";
    for (size_t i = 0; i < clientList.size(); i++)
        std::cout << (i + 1) << ". " << clientList.at(i) << "\n";

    int option;
    std::cin >> option;

    std::vector<std::string_view> scannable;
    switch (option) {
        case 1: scannable = novaPatterns; break;
        case 2: scannable = crystalPatterns; break;
        case 3: scannable = skatePatterns; break;
        case 4: scannable = argonPatterns; break;
        case 5: {
            scannable.insert(scannable.end(), novaPatterns.begin(), novaPatterns.end());
            scannable.insert(scannable.end(), crystalPatterns.begin(), crystalPatterns.end());
            scannable.insert(scannable.end(), skatePatterns.begin(), skatePatterns.end());
            scannable.insert(scannable.end(), argonPatterns.begin(), argonPatterns.end());
            scannable.insert(scannable.end(), universalPatterns.begin(), universalPatterns.end());
            break;
        }
        default:
            std::cout << "Invalid option.\n";
            CloseHandle(handle);
            return;
    }

    auto results = pattern_scan(handle, scannable);

    size_t utf16Hits = 0;
    for (const auto& r : results) if (r.wasUtf16) utf16Hits++;

    std::cout << "Found " << std::dec << results.size() << " traces";
    if (utf16Hits > 0)
        std::cout << " (" << utf16Hits << " only visible as UTF-16 Java strings)";
    std::cout << "\n";
    CloseHandle(handle);
}

void runModsFolderScanMenu() {
    // Clear the input buffer if there's a leftover newline
    if (std::cin.peek() == '\n') std::cin.ignore();

    wchar_t* appData = _wgetenv(L"USERPROFILE");
    std::filesystem::path defaultPath = appData
        ? std::filesystem::path(appData) / L"AppData" / L"Roaming" / L".minecraft" / L"mods"
        : std::filesystem::path();

    std::cout << "\n[Mods Scanner]\n";
    std::cout << "You can drag and drop the folder here or type the path manually.\n";
    std::cout << "Default path: " << (defaultPath.empty() ? "Not found" : defaultPath.string()) << "\n";
    std::cout << "Enter mods folder path (or press Enter for default): ";

    std::string input;
    std::getline(std::cin, input);

    // Remove quotes if the user dragged and dropped the folder
    if (!input.empty() && input.front() == '"' && input.back() == '"') {
        input = input.substr(1, input.size() - 2);
    }

    std::filesystem::path modsPath = input.empty() ? defaultPath : std::filesystem::path(input);

    if (modsPath.empty()) {
        std::cout << "[!] No path provided and default could not be determined.\n";
        return;
    }

    if (!std::filesystem::exists(modsPath)) {
        std::cout << "[!] The specified path does not exist: " << modsPath.string() << "\n";
        return;
    }

    modscan::runModsFolderScan(modsPath.wstring());
}

int main(int argc, char* argv[]) {
    std::cout << "Screenshare tool | Made by lvstrng | v1.2\n";

    // Handle command line argument for mods scan
    if (argc > 2 && std::string(argv[1]) == "--mods") {
        std::string path = argv[2];
        modscan::runModsFolderScan(std::filesystem::path(path).wstring());
        return 0;
    }

    while (true) {
        std::cout << "\nWhat do you want to do?\n"
                   << "1. Scan a Minecraft process for cheat client traces (live memory)\n"
                   << "2. Scan a mods folder for cheat client traces (jar analysis)\n"
                   << "3. Scan for suspicious JVM flags / injected java agents\n"
                   << "4. Scan this PC for macro software (198M Macros / Zenith Macros, running or installed)\n"
                   << "5. Exit\n";

        int choice;
        std::cin >> choice;

        if (choice == 1) {
            runMemoryScan();
        } else if (choice == 2) {
            runModsFolderScanMenu();
        } else if (choice == 3) {
            jvmscan::runJvmScan();
        } else if (choice == 4) {
            runMacroScan();
        } else {
            break;
        }
    }

    std::cout << "Press any key to exit...\n";
    std::cin.ignore();
    std::cin.get();

    return 0;
}
