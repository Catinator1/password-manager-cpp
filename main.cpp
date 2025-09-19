#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <unordered_map>
#include <limits>

using namespace std;

const int ASCII_START = 32;
const int ASCII_RANGE = 95;
const string ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ";

// ----------------- Base64 helpers -----------------
static const string b64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

string base64_encode(const string &in) {
    string out;
    int val=0, valb=-6;
    for (unsigned char c : in) {
        val = (val<<8) + c;
        valb += 8;
        while (valb>=0) {
            out.push_back(b64_chars[(val>>valb)&0x3F]);
            valb-=6;
        }
    }
    if (valb>-6) out.push_back(b64_chars[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
}

string base64_decode(const string &in) {
    vector<int> T(256, -1);
    for (int i=0;i<64;i++) T[(unsigned char)b64_chars[i]] = i;
    string out;
    int val=0, valb=-8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            out.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}
// --------------------------------------------------

// substitution table from master key
vector<char> generateSubstitutionTable(const string &masterKey) {
    vector<char> table(ALPHABET.begin(), ALPHABET.end());
    size_t seed = hash<string>{}(masterKey);
    mt19937 rng(static_cast<uint32_t>(seed));
    shuffle(table.begin(), table.end(), rng);
    return table;
}

unordered_map<char,char> buildEncryptionTable(const vector<char>& table) {
    unordered_map<char,char> enc;
    for (size_t i=0;i<ALPHABET.size();++i) enc[ALPHABET[i]] = table[i];
    return enc;
}
unordered_map<char,char> buildDecryptionTable(const unordered_map<char,char>& enc) {
    unordered_map<char,char> dec;
    for (auto &p : enc) dec[p.second] = p.first;
    return dec;
}

// ASCII-extended Vigenere (printable chars 32..126)
string vigenereEncryption(const string &password, const string &masterKey) {
    if (masterKey.empty()) return password;
    string out; out.reserve(password.size());
    int klen = (int)masterKey.size();
    for (int i=0;i<(int)password.size();++i) {
        unsigned char c = password[i];
        if (c >= ASCII_START && c <= 126) {
            int cIndex = c - ASCII_START;
            int kIndex = (unsigned char)masterKey[i % klen] - ASCII_START;
            int enc = (cIndex + kIndex) % ASCII_RANGE;
            out.push_back((char)(enc + ASCII_START));
        } else out.push_back((char)c);
    }
    return out;
}
string vigenereDecryption(const string &cipher, const string &masterKey) {
    if (masterKey.empty()) return cipher;
    string out; out.reserve(cipher.size());
    int klen = (int)masterKey.size();
    for (int i=0;i<(int)cipher.size();++i) {
        unsigned char c = cipher[i];
        if (c >= ASCII_START && c <= 126) {
            int cIndex = c - ASCII_START;
            int kIndex = (unsigned char)masterKey[i % klen] - ASCII_START;
            int dec = (cIndex - kIndex + ASCII_RANGE) % ASCII_RANGE;
            out.push_back((char)(dec + ASCII_START));
        } else out.push_back((char)c);
    }
    return out;
}

// ---------------- Core functions ----------------
void addEntry() {
    string username, password, masterKey;
    cout << "Enter username: ";
    getline(cin, username);
    if (username.empty()) {
        cout << "Username cannot be empty.\n";
        return;
    }
    cout << "Enter password: ";
    getline(cin, password);
    cout << "Enter master key: ";
    getline(cin, masterKey);
    if (masterKey.empty()) {
        cout << "Master key cannot be empty.\n";
        return;
    }

    // Vigenere -> Substitution -> Base64
    string v = vigenereEncryption(password, masterKey);
    auto table = generateSubstitutionTable(masterKey);
    auto encMap = buildEncryptionTable(table);

    string subst; subst.reserve(v.size());
    for (unsigned char c : v) {
        auto it = encMap.find((char)c);
        if (it != encMap.end()) subst.push_back(it->second);
        else subst.push_back((char)c);
    }

    string b64 = base64_encode(subst);

    ofstream ofs("vault.dat", ios::app);
    if (!ofs) { cout << "Failed to open vault.dat for writing.\n"; return; }
    ofs << username << "|" << b64 << "\n";
    ofs.close();
    cout << "Saved.\n";
}

void getPassword() {
    cout << "Enter master key: ";
    string masterKey; getline(cin, masterKey);
    if (masterKey.empty()) { cout << "Master key cannot be empty.\n"; return; }
    cout << "Enter username to search: ";
    string query; getline(cin, query);
    if (query.empty()) { cout << "Username cannot be empty.\n"; return; }

    ifstream ifs("vault.dat");
    if (!ifs) { cout << "vault.dat not found.\n"; return; }

    auto table = generateSubstitutionTable(masterKey);
    auto encMap = buildEncryptionTable(table);
    auto decMap = buildDecryptionTable(encMap);

    string line;
    bool found = false;
    while (getline(ifs, line)) {
        if (line.empty()) continue;
        size_t pos = line.find('|');
        if (pos == string::npos) continue;
        string user = line.substr(0,pos);
        string b64 = line.substr(pos+1);
        if (user == query) {
            string subst = base64_decode(b64);        //Get data after substitution 
            string afterSubst; afterSubst.reserve(subst.size());
            for (unsigned char c : subst) {
                auto it = decMap.find((char)c);
                if (it != decMap.end()) afterSubst.push_back(it->second);
                else afterSubst.push_back((char)c);
            }
            string plain = vigenereDecryption(afterSubst, masterKey);
            cout << "Decrypted password: " << plain << "\n";
            found = true;
            break;
        }
    }
    if (!found) cout << "No entry found for username: " << query << "\n";
    ifs.close();
}

void listEntries() {
    ifstream ifs("vault.dat");
    if (!ifs) { cout << "vault.dat not found.\n"; return; }
    cout << "Saved usernames:\n";
    string line;
    while (getline(ifs, line)) {
        if (line.empty()) continue;
        size_t pos = line.find('|');
        if (pos != string::npos) {
            cout << "- " << line.substr(0,pos) << "\n";
        }
    }
    ifs.close();
}

// -------------------- main --------------------
int main() {
    while (true) {
        cout << "\n1) Add entry\n2) Get password\n3) List entries\n4) Exit\nChoose: ";
        int choice;
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input\n";
            continue;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n'); // consume newline

        if (choice == 1) addEntry();
        else if (choice == 2) getPassword();
        else if (choice == 3) listEntries();
        else if (choice == 4) { cout << "Exiting\n"; break; }
        else cout << "Invalid choice\n";
    }
    return 0;
}
