#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <limits>
#include <cstdlib>
#include <ctime>

using namespace CryptoPP;
namespace fs = std::filesystem;

// Анимация прогресса
void ShowProgress(int percent, const std::string& operation) {
    std::cout << "\r[" << operation << "] [";
    for (int i = 0; i < 50; i++) {
        if (i < percent / 2) std::cout << "■";
        else std::cout << " ";
    }
    std::cout << "] " << percent << "%";
    std::cout.flush();
}

std::string ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void WriteFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(data.data(), data.size());
}

void SaveKeysAndIV(const std::string& filename,
                   const SecByteBlock& key1,
                   const SecByteBlock& key2,
                   const SecByteBlock& key3,
                   const SecByteBlock& iv) {
    std::ofstream keyFile(filename);
    if (keyFile) {
        std::string key1Hex, key2Hex, key3Hex, ivHex;
        StringSource(key1, key1.size(), true, new HexEncoder(new StringSink(key1Hex)));
        StringSource(key2, key2.size(), true, new HexEncoder(new StringSink(key2Hex)));
        StringSource(key3, key3.size(), true, new HexEncoder(new StringSink(key3Hex)));
        StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(ivHex)));

        keyFile << "Key1 (HEX): " << key1Hex << "\n";
        keyFile << "Key2 (HEX): " << key2Hex << "\n";
        keyFile << "Key3 (HEX): " << key3Hex << "\n";
        keyFile << "IV   (HEX): " << ivHex << "\n";
    }
}

void GenerateKeysAndIV(SecByteBlock& key1, SecByteBlock& key2, SecByteBlock& key3, SecByteBlock& iv) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key1, key1.size());
    prng.GenerateBlock(key2, key2.size());
    prng.GenerateBlock(key3, key3.size());
    prng.GenerateBlock(iv, iv.size());
}

SecByteBlock CombineKeys(const SecByteBlock& key1, const SecByteBlock& key2, const SecByteBlock& key3) {
    std::vector<byte> combined;
    combined.insert(combined.end(), key1.begin(), key1.end());
    combined.insert(combined.end(), key2.begin(), key2.end());
    combined.insert(combined.end(), key3.begin(), key3.end());

    SecByteBlock finalKey(AES::MAX_KEYLENGTH);
    memcpy(finalKey, combined.data(), AES::MAX_KEYLENGTH);
    return finalKey;
}

bool EncryptFile(const std::string& inputFile, const std::string& outputFile) {
    if (!fs::exists(inputFile)) {
        std::cerr << "✖ Ошибка: файл \"" << inputFile << "\" не существует!\n";
        return false;
    }

    try {
        std::cout << "\n▬▬▬▬▬▬▬▬ НАЧАЛО ШИФРОВАНИЯ ▬▬▬▬▬▬▬▬\n";

        SecByteBlock key1(AES::BLOCKSIZE), key2(AES::BLOCKSIZE), key3(AES::BLOCKSIZE), iv(AES::BLOCKSIZE);
        GenerateKeysAndIV(key1, key2, key3, iv);
        SecByteBlock finalKey = CombineKeys(key1, key2, key3);

        std::string plaintext = ReadFile(inputFile);
        if (plaintext.empty()) {
            std::cerr << "✖ Ошибка чтения файла или файл пустой!\n";
            return false;
        }

        std::string ciphertext;
        CBC_Mode<AES>::Encryption encryptor(finalKey, finalKey.size(), iv);
        StringSource ss(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext), BlockPaddingSchemeDef::PKCS_PADDING));
        ciphertext.insert(0, reinterpret_cast<const char*>(iv.data()), iv.size());

        WriteFile(outputFile, ciphertext);

        for (int i = 0; i <= 100; i++) {
            ShowProgress(i, "ШИФРОВАНИЕ");
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }

        std::cout << "\n✔ Успешно зашифровано: " << outputFile << "\n";
        SaveKeysAndIV(outputFile + ".key.txt", key1, key2, key3, iv);
        std::cout << " Ключи и IV сохранены.\n";
        return true;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "✖ Крипто-ошибка: " << e.what() << "\n";
        return false;
    }
}

bool DecryptFile(const std::string& inputFile, const std::string& outputFile,
                 const SecByteBlock& key1, const SecByteBlock& key2, const SecByteBlock& key3) {
    if (!fs::exists(inputFile)) {
        std::cerr << "✖ Ошибка: файл \"" << inputFile << "\" не существует!\n";
        return false;
    }

    try {
        std::string ciphertext = ReadFile(inputFile);
        if (ciphertext.size() <= AES::BLOCKSIZE) {
            std::cerr << "✖ Недостаточно данных или повреждённый файл.\n";
            return false;
        }

        SecByteBlock iv(reinterpret_cast<const byte*>(ciphertext.data()), AES::BLOCKSIZE);
        std::string encryptedData = ciphertext.substr(AES::BLOCKSIZE);
        SecByteBlock finalKey = CombineKeys(key1, key2, key3);

        std::string plaintext;
        CBC_Mode<AES>::Decryption decryptor(finalKey, finalKey.size(), iv);
        StringSource ss(encryptedData, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext), BlockPaddingSchemeDef::PKCS_PADDING));

        WriteFile(outputFile, plaintext);

        for (int i = 0; i <= 100; i++) {
            ShowProgress(i, "РАСШИФРОВКА");
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }

        std::cout << "\n✔ Расшифровка завершена: " << outputFile << "\n";
        return true;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "✖ Ошибка расшифровки: " << e.what() << "\n";
        return false;
    }
}

bool ReadKeyFromHex(const std::string& hexStr, SecByteBlock& key) {
    try {
        StringSource ss(hexStr, true, new HexDecoder(new ArraySink(key, key.size())));
        return true;
    } catch (...) {
        return false;
    }
}

void ShowMainLogo() {
    std::cout << R"(
 ██▓███   ██▓ ██▓███  ▓█████  ██▓███   ██▓▓█████ 
▓██░  ██▒▓██▒▓██░  ██▒▓█   ▀ ▓██░  ██▒▓██▒▓█   ▀ 
▓██░ ██▓▒▒██▒▓██░ ██▓▒▒███   ▓██░ ██▓▒▒██▒▒███   
▒██▄█▓▒ ▒░██░▒██▄█▓▒ ▒▒▓█  ▄ ▒██▄█▓▒ ▒░██░▒▓█  ▄ 
▒██▒ ░  ░░██░▒██▒ ░  ░░▒████▒▒██▒ ░  ░░██░░▒████▒
▒▓▒░ ░  ░░▓  ▒▓▒░ ░  ░░░ ▒░ ░▒▓▒░ ░  ░░▓  ░░ ▒░ ░
░▒ ░      ▒ ░░▒ ░      ░ ░  ░░▒ ░      ▒ ░ ░ ░  ░
░░        ▒ ░░░          ░   ░░        ▒ ░   ░   
          ░              ░  ░          ░     ░  ░
)" << "\n";
}

void ShowEncryptorBanner() {
    std::cout << R"(
▄▄▄ . ▐ ▄  ▄▄· ▄▄▄   ▄· ▄▌ ▄▄▄·▄▄▄▄▄      ▄▄▄  
▀▄.▀·•█▌▐█▐█ ▌▪▀▄ █·▐█▪██▌▐█ ▄█•██  ▪     ▀▄ █·
▐▀▀▪▄▐█▐▐▌██ ▄▄▐▀▀▄ ▐█▌▐█▪ ██▀· ▐█.▪ ▄█▀▄ ▐▀▀▄ 
▐█▄▄▌██▐█▌▐███▌▐█•█▌ ▐█▀·.▐█▪·• ▐█▌·▐█▌.▐▌▐█•█▌
 ▀▀▀ ▀▀ █▪·▀▀▀ .▀  ▀  ▀ • .▀    ▀▀▀  ▀█▄▀▪.▀  ▀
)" <<"\n\n";
}

void ShowFindBanner() {
    std::cout << R"(
   |
   |
   |
  \|/
   V

▄████  ▄█    ▄   ██▄   
█▀   ▀ ██     █  █  █  
█▀▀    ██ ██   █ █   █ 
█      ▐█ █ █  █ █  █  
 █      ▐ █  █ █ ███▀  
  ▀       █   ██       
)" << "\n\n";
}

// Быстрая анимация
void AnimateSearching(const std::vector<std::string>& folderNames) {
    for (int i = 0; i < 10; ++i) {
        if (folderNames.empty()) return;
        int index = rand() % folderNames.size();
        std::cout << "\r Поиск в: " << folderNames[index] << "..." << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "\r";
}

void FindFilesOrDirs() {
    while (true) {
        ShowMainLogo();
        ShowFindBanner();

        std::cout << "1.  Начать поиск\n"
                  << "2.  Вернуться в главное меню\n"
                  << "> ";

        int option;
        if (!(std::cin >> option)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }
        std::cin.ignore(1000, '\n');

        if (option == 2) return;

        if (option == 1) {
            std::string type, query;
            while (true) {
                std::cout << "Введите тип (f — файл, dir — директория): ";
                std::getline(std::cin, type);
                if (type == "f" || type == "dir") break;
                std::cout << "✖ Неверный тип!\n";
            }

            std::cout << "Введите имя файла или папки для поиска (для файла можно без разширенния): ";
            std::getline(std::cin, query);

            std::vector<std::pair<std::string, std::string>> results;
            std::vector<std::string> allFolders;

            for (const auto& entry : fs::recursive_directory_iterator("/home", fs::directory_options::skip_permission_denied)) {
                try {
                    std::string name = entry.path().filename().string();
                    allFolders.push_back(entry.path().string());

                    if (type == "f" && entry.is_regular_file()) {
                        if (name.find(query) != std::string::npos) {
                            results.emplace_back(name, entry.path().string());
                        }
                    }
                    else if (type == "dir" && entry.is_directory()) {
                        if (name.find(query) != std::string::npos) {
                            results.emplace_back(name, entry.path().string());
                        }
                    }
                } catch (...) {}
            }

            AnimateSearching(allFolders);

            std::cout << "\nРезультаты:\n";
            if (results.empty()) {
                std::cout << "✖ Ничего не найдено.\n";
            } else {
                for (const auto& [name, path] : results) {
                    std::cout << name << " ----> " << path << "\n";
                }
            }

            std::cout << "\nНажмите Enter для возврата...";
            std::cin.get();
        }
    }
}

int main() {
    srand(time(0));
    int mainChoice;

    do {
        ShowMainLogo();
        std::cout << "Главное меню:\n"
                  << "1.  Открыть шифратор\n"
                  << "2.  Поиск файлов и папок\n"
                  << "3. ❌ Выход\n"
                  << "> ";

        if (!(std::cin >> mainChoice)) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            continue;
        }
        std::cin.ignore(1000, '\n');

        if (mainChoice == 1) {
            ShowEncryptorBanner();
            int choice;
            do {
                std::cout << "1.  Зашифровать файл\n"
                          << "2.  Расшифровать файл\n"
                          << "3.  Назад\n"
                          << "> ";

                if (!(std::cin >> choice)) {
                    std::cin.clear();
                    std::cin.ignore(1000, '\n');
                    continue;
                }
                std::cin.ignore(1000, '\n');

                if (choice == 1) {
                    std::string input, output;
                    std::cout << "Введите путь к файлу: ";
                    std::getline(std::cin, input);
                    std::cout << "Введите путь для сохранения: ";
                    std::getline(std::cin, output);
                    EncryptFile(input, output);
                } else if (choice == 2) {
                    std::string input, output, k1, k2, k3;
                    std::cout << "Введите путь к зашифрованному файлу: ";
                    std::getline(std::cin, input);
                    std::cout << "Введите путь для расшифровки: ";
                    std::getline(std::cin, output);
                    std::cout << "Введите Key1 (HEX): "; std::getline(std::cin, k1);
                    std::cout << "Введите Key2 (HEX): "; std::getline(std::cin, k2);
                    std::cout << "Введите Key3 (HEX): "; std::getline(std::cin, k3);

                    SecByteBlock key1(AES::BLOCKSIZE), key2(AES::BLOCKSIZE), key3(AES::BLOCKSIZE);
                    if (!ReadKeyFromHex(k1, key1) || !ReadKeyFromHex(k2, key2) || !ReadKeyFromHex(k3, key3)) {
                        std::cerr << "✖ Неверный HEX ключ!\n";
                        continue;
                    }
                    DecryptFile(input, output, key1, key2, key3);
                }
            } while (choice != 3);
        }
        else if (mainChoice == 2) {
            FindFilesOrDirs();
        }
        else if (mainChoice == 3) {
            std::cout << R"(                                                    

 ▗▄▄▖ ▗▄▖  ▗▄▖ ▗▄▄▄  ▗▄▄▖ ▗▖  ▗▖▗▄▄▄▖
▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌  █ ▐▌ ▐▌ ▝▚▞▘ ▐▌   
▐▌▝▜▌▐▌ ▐▌▐▌ ▐▌▐▌  █ ▐▛▀▚▖  ▐▌  ▐▛▀▀▘
▝▚▄▞▘▝▚▄▞▘▝▚▄▞▘▐▙▄▄▀ ▐▙▄▞▘  ▐▌  ▐▙▄▄▖
)" << "\n\n";
            break;
        }

    } while (true);

    return 0;
}