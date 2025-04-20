#include <iostream>
#include <string>
#include <set>
#include <map>
#include <vector>
#include <algorithm>
#include <cctype>
#include <Windows.h>
#include <thread>
#include <atomic>
#include <signal.h>
#include <fstream>
#include <ctime>
#include <sstream>
#include <iomanip>

class Logger
{
private:
    std::ofstream logFile;
    bool loggingEnabled;
    std::string logFilePath;

    std::string getCurrentTimeStamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);

        std::tm tm_now;
        localtime_s(&tm_now, &time_t_now);

        std::stringstream ss;
        ss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

public:
    Logger() : loggingEnabled(false) {}

    ~Logger()
    {
        if (logFile.is_open())
        {
            logFile.close();
        }
    }

    bool initialize(const std::string &filePath = "history.log")
    {
        logFilePath = filePath;
        logFile.open(filePath, std::ios::app);

        if (!logFile.is_open())
        {
            std::cerr << "Failed to open log file: " << filePath << std::endl;
            loggingEnabled = false;
            return false;
        }

        loggingEnabled = true;
        log("Logging system initialized");
        return true;
    }

    void close()
    {
        if (logFile.is_open())
        {
            log("Logging system shut down");
            logFile.close();
        }
        loggingEnabled = false;
    }

    void log(const std::string &message)
    {
        if (loggingEnabled && logFile.is_open())
        {
            logFile << "[" << getCurrentTimeStamp() << "] " << message << std::endl;
            logFile.flush();
        }
    }

    bool isEnabled() const
    {
        return loggingEnabled;
    }

    std::string getLogFilePath() const
    {
        return logFilePath;
    }
};

class KeyboardDisabler
{
private:
    std::set<int> disabledKeys;
    std::map<std::string, int> keyMapping;
    std::atomic<bool> isDisabled;
    std::thread keyboardHookThread;
    HHOOK keyboardHook;
    DWORD hookThreadId;
    bool escapeEnablesKeyboard;
    Logger logger;

    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
    {
        if (nCode >= 0)
        {
            KeyboardDisabler *instance = reinterpret_cast<KeyboardDisabler *>(GetWindowLongPtr(GetConsoleWindow(), GWLP_USERDATA));
            if (instance && instance->isDisabled.load())
            {
                KBDLLHOOKSTRUCT *kbStruct = reinterpret_cast<KBDLLHOOKSTRUCT *>(lParam);
                int vkCode = kbStruct->vkCode;

                if (vkCode == VK_ESCAPE && instance->escapeEnablesKeyboard)
                {

                    instance->logger.log("ESC key pressed - emergency keyboard enable requested");
                    PostThreadMessage(GetCurrentThreadId(), WM_USER + 1, 0, 0);
                    return 0;
                }

                if (instance->disabledKeys.find(vkCode) != instance->disabledKeys.end())
                {

                    std::string keyName = "Unknown";
                    for (const auto &pair : instance->keyMapping)
                    {
                        if (pair.second == vkCode)
                        {
                            keyName = pair.first;
                            break;
                        }
                    }
                    instance->logger.log("Blocked key press: " + keyName);
                    return 1;
                }
            }
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }

    void initializeKeyMapping()
    {

        keyMapping["ctrl"] = VK_CONTROL;
        keyMapping["control"] = VK_CONTROL;
        keyMapping["alt"] = VK_MENU;
        keyMapping["shift"] = VK_SHIFT;
        keyMapping["tab"] = VK_TAB;
        keyMapping["esc"] = VK_ESCAPE;
        keyMapping["escape"] = VK_ESCAPE;
        keyMapping["space"] = VK_SPACE;
        keyMapping["enter"] = VK_RETURN;
        keyMapping["return"] = VK_RETURN;
        keyMapping["backspace"] = VK_BACK;
        keyMapping["delete"] = VK_DELETE;
        keyMapping["del"] = VK_DELETE;
        keyMapping["insert"] = VK_INSERT;
        keyMapping["ins"] = VK_INSERT;
        keyMapping["home"] = VK_HOME;
        keyMapping["end"] = VK_END;
        keyMapping["pageup"] = VK_PRIOR;
        keyMapping["pagedown"] = VK_NEXT;
        keyMapping["up"] = VK_UP;
        keyMapping["down"] = VK_DOWN;
        keyMapping["left"] = VK_LEFT;
        keyMapping["right"] = VK_RIGHT;

        for (int i = 1; i <= 12; i++)
        {
            keyMapping["f" + std::to_string(i)] = VK_F1 + i - 1;
        }

        for (char c = 'a'; c <= 'z'; c++)
        {
            std::string key(1, c);
            keyMapping[key] = 'A' + (c - 'a');
        }

        for (char c = '0'; c <= '9'; c++)
        {
            std::string key(1, c);
            keyMapping[key] = c;
        }
    }

    void startKeyboardHook()
    {

        hookThreadId = GetCurrentThreadId();

        keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
        if (!keyboardHook)
        {
            logger.log("ERROR: Failed to install keyboard hook");
            std::cerr << "Failed to install keyboard hook!" << std::endl;
            return;
        }

        logger.log("Keyboard hook installed successfully");

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0))
        {

            if (msg.message == WM_USER + 1)
            {
                isDisabled.store(false);
                logger.log("ESC key triggered keyboard enable");
                std::cout << "\nESC key pressed! Enabling keyboard..." << std::endl;
                continue;
            }

            TranslateMessage(&msg);
            DispatchMessage(&msg);

            if (!isDisabled.load())
            {
                break;
            }
        }

        UnhookWindowsHookEx(keyboardHook);
        logger.log("Keyboard hook removed");
    }

public:
    KeyboardDisabler() : isDisabled(false), hookThreadId(0), escapeEnablesKeyboard(true)
    {
        initializeKeyMapping();

        SetWindowLongPtr(GetConsoleWindow(), GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    }

    ~KeyboardDisabler()
    {
        enableKeyboard();
        logger.close();
    }

    bool initializeLogger(const std::string &logFilePath = "history.log")
    {
        bool success = logger.initialize(logFilePath);
        if (success)
        {
            logger.log("KeyboardDisabler initialized");
        }
        return success;
    }

    void addKey(const std::string &key)
    {
        std::string lowercaseKey = key;
        std::transform(lowercaseKey.begin(), lowercaseKey.end(), lowercaseKey.begin(), [](unsigned char c)
                       { return std::tolower(c); });
        if (keyMapping.find(lowercaseKey) != keyMapping.end())
        {

            if (lowercaseKey == "esc" || lowercaseKey == "escape")
            {
                if (escapeEnablesKeyboard)
                {
                    logger.log("WARNING: Attempt to disable ESC key while escape hatch is enabled - denied");
                    std::cout << "Warning: Cannot disable ESC key when it's set as the emergency enable key." << std::endl;
                    std::cout << "Use 'escapehatch off' command first if you want to disable ESC." << std::endl;
                    return;
                }
            }

            disabledKeys.insert(keyMapping[lowercaseKey]);
            logger.log("Added key to disabled list: " + lowercaseKey);
            std::cout << "Added key: " << lowercaseKey << std::endl;
        }
        else
        {
            logger.log("ERROR: Unrecognized key: " + lowercaseKey);
            std::cout << "Key '" << lowercaseKey << "' is not recognized." << std::endl;
        }
    }

    void addKeys(const std::string &keysText)
    {
        std::vector<std::string> keys;
        std::string currentKey;

        for (char c : keysText)
        {
            if (c == ',')
            {
                if (!currentKey.empty())
                {

                    currentKey.erase(0, currentKey.find_first_not_of(" \t"));
                    currentKey.erase(currentKey.find_last_not_of(" \t") + 1);

                    if (!currentKey.empty())
                    {
                        keys.push_back(currentKey);
                    }
                    currentKey.clear();
                }
            }
            else
            {
                currentKey += c;
            }
        }

        if (!currentKey.empty())
        {

            currentKey.erase(0, currentKey.find_first_not_of(" \t"));
            currentKey.erase(currentKey.find_last_not_of(" \t") + 1);

            if (!currentKey.empty())
            {
                keys.push_back(currentKey);
            }
        }

        logger.log("Adding multiple keys: " + keysText);

        for (const auto &key : keys)
        {
            addKey(key);
        }
    }

    void clearKeys()
    {
        logger.log("Cleared all disabled keys");
        disabledKeys.clear();
        std::cout << "All keys cleared." << std::endl;
    }

    void displayDisabledKeys()
    {
        if (disabledKeys.empty())
        {
            logger.log("Listing disabled keys: none");
            std::cout << "No keys are currently disabled." << std::endl;
            return;
        }

        std::string keysList;
        bool first = true;

        std::map<int, std::string> reverseMapping;
        for (const auto &pair : keyMapping)
        {
            reverseMapping[pair.second] = pair.first;
        }

        std::cout << "Disabled keys: ";

        for (int keyCode : disabledKeys)
        {
            if (!first)
            {
                std::cout << ", ";
                keysList += ", ";
            }

            if (reverseMapping.find(keyCode) != reverseMapping.end())
            {
                std::cout << reverseMapping[keyCode];
                keysList += reverseMapping[keyCode];
            }
            else
            {
                std::cout << "Unknown(" << keyCode << ")";
                keysList += "Unknown(" + std::to_string(keyCode) + ")";
            }

            first = false;
        }

        logger.log("Listing disabled keys: " + keysList);
        std::cout << std::endl;
    }

    void disableKeyboard()
    {
        if (disabledKeys.empty())
        {
            logger.log("WARNING: Attempt to disable keyboard with no keys specified");
            std::cout << "Please add at least one key to disable." << std::endl;
            return;
        }

        if (isDisabled.load())
        {
            logger.log("WARNING: Attempted to disable keyboard that was already disabled");
            std::cout << "Keyboard is already disabled." << std::endl;
            return;
        }

        std::string keysList;
        bool first = true;

        std::map<int, std::string> reverseMapping;
        for (const auto &pair : keyMapping)
        {
            reverseMapping[pair.second] = pair.first;
        }

        for (int keyCode : disabledKeys)
        {
            if (!first)
            {
                keysList += ", ";
            }

            if (reverseMapping.find(keyCode) != reverseMapping.end())
            {
                keysList += reverseMapping[keyCode];
            }
            else
            {
                keysList += "Unknown(" + std::to_string(keyCode) + ")";
            }

            first = false;
        }

        isDisabled.store(true);
        logger.log("Keyboard disabled with keys: " + keysList);
        std::cout << "Selected keys are now disabled." << std::endl;

        if (escapeEnablesKeyboard)
        {
            std::cout << "Press ESC key at any time to enable all keys." << std::endl;
        }

        keyboardHookThread = std::thread(&KeyboardDisabler::startKeyboardHook, this);
    }

    void enableKeyboard()
    {
        if (!isDisabled.load())
        {
            logger.log("WARNING: Attempted to enable keyboard that was not disabled");
            std::cout << "Keyboard is not disabled." << std::endl;
            return;
        }

        isDisabled.store(false);
        logger.log("Enabling keyboard");

        if (hookThreadId != 0)
        {
            PostThreadMessage(hookThreadId, WM_QUIT, 0, 0);
        }

        if (keyboardHookThread.joinable())
        {
            keyboardHookThread.join();
        }

        std::cout << "Keyboard has been enabled." << std::endl;
    }

    bool isKeyboardDisabled() const
    {
        return isDisabled.load();
    }

    void setEscapeHatch(bool enabled)
    {

        if (!enabled && isDisabled.load())
        {
            auto it = disabledKeys.find(VK_ESCAPE);
            if (it != disabledKeys.end())
            {
                logger.log("ERROR: Cannot disable escape hatch while ESC key is in the disabled list");
                std::cout << "Cannot disable escape hatch while ESC key is in the disabled keys list." << std::endl;
                return;
            }
        }

        escapeEnablesKeyboard = enabled;
        logger.log("Escape hatch " + std::string(enabled ? "ENABLED" : "DISABLED"));
        std::cout << "Escape key emergency enable feature: " << (enabled ? "ON" : "OFF") << std::endl;
    }

    bool getEscapeHatchStatus() const
    {
        return escapeEnablesKeyboard;
    }

    std::string getLogFilePath() const
    {
        return logger.getLogFilePath();
    }

    bool isLoggingEnabled() const
    {
        return logger.isEnabled();
    }
};

KeyboardDisabler *globalDisablerPtr = nullptr;
void signalHandler(int signal)
{
    if (globalDisablerPtr)
    {
        if (globalDisablerPtr->isLoggingEnabled())
        {
            std::cout << "\nReceived interrupt signal. Enabling keyboard before exit..." << std::endl;
        }

        if (globalDisablerPtr->isKeyboardDisabled())
        {
            globalDisablerPtr->enableKeyboard();
        }
    }
    exit(signal);
}

void showHelp()
{
    std::cout << "Keyboard Disabler - Command Line Interface\n";
    std::cout << "=========================================\n";
    std::cout << "Available commands:\n";
    std::cout << "  add <keys>     - Add keys to disable (comma separated)\n";
    std::cout << "  clear          - Clear all disabled keys\n";
    std::cout << "  list           - List currently disabled keys\n";
    std::cout << "  disable        - Disable the selected keys\n";
    std::cout << "  enable         - Enable all keys (stop blocking)\n";
    std::cout << "  escapehatch    - Show escape hatch status (ESC key enables keyboard)\n";
    std::cout << "  escapehatch on/off - Turn escape hatch feature on/off\n";
    std::cout << "  logfile        - Show current log file path\n";
    std::cout << "  help           - Show this help message\n";
    std::cout << "  exit           - Exit the application\n";
    std::cout << "=========================================\n";
    std::cout << "When keys are disabled, press ESC to enable all keys immediately (if enabled).\n";
    std::cout << "All actions are logged to the log file.\n";
}

int main()
{
    std::cout << "Keyboard Disabler - Command Line Interface\n";
    std::cout << "Type 'help' for available commands.\n";

    KeyboardDisabler disabler;

    if (!disabler.initializeLogger())
    {
        std::cerr << "WARNING: Failed to initialize logging system." << std::endl;
    }
    else
    {
        std::cout << "Logging to: " << disabler.getLogFilePath() << std::endl;
    }

    globalDisablerPtr = &disabler;

    signal(SIGINT, signalHandler);

    std::string command;
    bool running = true;

    while (running)
    {
        std::cout << "\n> ";
        std::getline(std::cin, command);

        std::string cmd;
        std::string args;

        size_t spacePos = command.find(' ');
        if (spacePos != std::string::npos)
        {
            cmd = command.substr(0, spacePos);
            args = command.substr(spacePos + 1);
        }
        else
        {
            cmd = command;
        }

        std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c) { return std::tolower(c); });

        if (cmd == "add")
        {
            if (args.empty())
            {
                std::cout << "Please specify keys to add (comma separated)." << std::endl;
            }
            else
            {
                disabler.addKeys(args);
            }
        }
        else if (cmd == "clear")
        {
            disabler.clearKeys();
        }
        else if (cmd == "list")
        {
            disabler.displayDisabledKeys();
        }
        else if (cmd == "disable")
        {
            disabler.disableKeyboard();
        }
        else if (cmd == "enable")
        {
            disabler.enableKeyboard();
        }
        else if (cmd == "escapehatch")
        {
            if (args.empty())
            {
                std::cout << "Escape key emergency enable feature: " << (disabler.getEscapeHatchStatus() ? "ON" : "OFF") << std::endl;
            }
            else
            {
                std::string option = args;
                std::transform(option.begin(), option.end(), option.begin(), [](unsigned char c) { return std::tolower(c); });

                if (option == "on")
                {
                    disabler.setEscapeHatch(true);
                }
                else if (option == "off")
                {
                    disabler.setEscapeHatch(false);
                }
                else
                {
                    std::cout << "Invalid option. Use 'on' or 'off'." << std::endl;
                }
            }
        }
        else if (cmd == "logfile")
        {
            if (disabler.isLoggingEnabled())
            {
                std::cout << "Current log file: " << disabler.getLogFilePath() << std::endl;
            }
            else
            {
                std::cout << "Logging is disabled." << std::endl;
            }
        }
        else if (cmd == "help")
        {
            showHelp();
        }
        else if (cmd == "exit" || cmd == "quit")
        {

            if (disabler.isKeyboardDisabled())
            {
                disabler.enableKeyboard();
            }
            running = false;
        }
        else
        {
            std::cout << "Unknown command. Type 'help' for available commands." << std::endl;
        }
    }

    std::cout << "Exiting Keyboard Disabler. Goodbye!" << std::endl;
    return 0;
}