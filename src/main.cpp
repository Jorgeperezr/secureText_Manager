#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

#define FILENAME "encrypted_texts.dat"
#define PIN_FILENAME "pin.dat"

// Singleton para gestionar la clave y el vector de inicialización
class KeyManager {
public:
    static KeyManager& getInstance() {
        static KeyManager instance;
        return instance;
    }

    const unsigned char* getKey() const { return key; }
    const unsigned char* getIV() const { return iv; }

private:
    unsigned char key[EVP_MAX_KEY_LENGTH] = "0123456789abcdef";
    unsigned char iv[EVP_MAX_IV_LENGTH] = {'a', 'b', 'c', 'd', 'e', 'f', '9', '8', '7', '6', '5', '4', '3', '2', '1', '0'};

    KeyManager() {}
};

// Función para manejar errores de OpenSSL
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Abstract Factory para operaciones de cifrado y descifrado
class CryptoOperation {
public:
    virtual ~CryptoOperation() = default;
    virtual void process(const std::string& input, std::vector<unsigned char>& output) = 0;
};

class EncryptOperation : public CryptoOperation {
public:
    void process(const std::string& plaintext, std::vector<unsigned char>& ciphertext) override {
        const auto& key = KeyManager::getInstance().getKey();
        const auto& iv = KeyManager::getInstance().getIV();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleErrors();

        int len;
        int ciphertext_len;
        std::vector<unsigned char> temp(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

        if (1 != EVP_EncryptUpdate(ctx, temp.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length()))
            handleErrors();
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, temp.data() + len, &len))
            handleErrors();
        ciphertext_len += len;

        temp.resize(ciphertext_len);
        ciphertext = std::move(temp);

        EVP_CIPHER_CTX_free(ctx);
    }
};

class DecryptOperation : public CryptoOperation {
public:
    void process(const std::string& ciphertext, std::vector<unsigned char>& plaintext) override {
        const auto& key = KeyManager::getInstance().getKey();
        const auto& iv = KeyManager::getInstance().getIV();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleErrors();

        int len;
        int plaintext_len;
        std::vector<unsigned char> temp(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

        if (1 != EVP_DecryptUpdate(ctx, temp.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()))
            handleErrors();
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx, temp.data() + len, &len))
            handleErrors();
        plaintext_len += len;

        temp.resize(plaintext_len);
        plaintext = std::move(temp);

        EVP_CIPHER_CTX_free(ctx);
    }
};

// Generación de operaciones
class CryptoFactory {
public:
    std::unique_ptr<CryptoOperation> createOperation(const std::string& type) {
        if (type == "encrypt") {
            return std::make_unique<EncryptOperation>();
        } else if (type == "decrypt") {
            return std::make_unique<DecryptOperation>();
        } else {
            throw std::invalid_argument("Tipo de operación inválido");
        }
    }
};

// Función para guardar el PIN en un archivo binario
void savePin(const std::string& pin) {
    std::ofstream file(PIN_FILENAME, std::ios::binary);
    if (!file) {
        perror("Error al guardar el PIN");
        exit(1);
    }
    file.write(pin.c_str(), pin.size());
    file.close();
}

// Función para cargar el PIN desde un archivo
std::string loadPin() {
    std::ifstream file(PIN_FILENAME, std::ios::binary);
    if (!file) {
        // Si el archivo no existe, el programa pedirá al usuario crear un PIN.
        return "";
    }
    std::string pin;
    file.seekg(0, std::ios::end);
    pin.resize(file.tellg());
    file.seekg(0, std::ios::beg);
    file.read(&pin[0], pin.size());
    file.close();
    return pin;
}

// Función para guardar texto cifrado con nombre
void saveEncryptedText(const std::vector<unsigned char>& ciphertext, const std::string& name) {
    std::ofstream file(FILENAME, std::ios::binary | std::ios::app);
    if (!file) {
        perror("Error al abrir el archivo para escritura");
        exit(1);
    }

    int name_len = name.size();
    int text_len = ciphertext.size();

    file.write(reinterpret_cast<const char*>(&name_len), sizeof(name_len)); // Guardar longitud del nombre
    file.write(name.c_str(), name_len); // Guardar nombre
    file.write(reinterpret_cast<const char*>(&text_len), sizeof(text_len)); // Guardar longitud del texto cifrado
    file.write(reinterpret_cast<const char*>(ciphertext.data()), text_len); // Guardar texto cifrado

    file.close();
}

// Función para listar textos cifrados
void listEncryptedTexts() {
    std::ifstream file(FILENAME, std::ios::binary);
    if (!file) {
        perror("Error al abrir el archivo para lectura");
        return;
    }

    int name_len;
    int text_len;
    char name[256];
    int index = 0;

    while (file.read(reinterpret_cast<char*>(&name_len), sizeof(name_len))) {
        file.read(name, name_len);
        name[name_len] = '\0'; // Terminar la cadena
        file.read(reinterpret_cast<char*>(&text_len), sizeof(text_len));
        file.seekg(text_len, std::ios::cur); // Saltar el texto cifrado
        std::cout << "Texto cifrado #" << ++index << ": " << name << " (tamaño: " << text_len << " bytes)" << std::endl;
    }

    file.close();
}

// Función para recuperar texto cifrado usando el índice
void retrieveEncryptedText(int index, std::vector<unsigned char>& ciphertext) {
    std::ifstream file(FILENAME, std::ios::binary);
    if (!file) {
        perror("Error al abrir el archivo para lectura");
        exit(1);
    }

    int currentIndex = 0;
    int name_len, text_len;
    char name[256];

    while (file.read(reinterpret_cast<char*>(&name_len), sizeof(name_len))) {
        file.read(name, name_len);
        name[name_len] = '\0';
        file.read(reinterpret_cast<char*>(&text_len), sizeof(text_len));

        if (++currentIndex == index) {
            ciphertext.resize(text_len);
            file.read(reinterpret_cast<char*>(ciphertext.data()), text_len);
            file.close();
            return;
        }

        file.seekg(text_len, std::ios::cur);
    }

    file.close();
    std::cerr << "Texto cifrado con índice " << index << " no encontrado" << std::endl;
    exit(1);
}

// Menú principal
void showMenu() {
    std::cout << "\n--- Menú Principal ---" << std::endl;
    std::cout << "1. Cifrar un nuevo texto" << std::endl;
    std::cout << "2. Recuperar un texto cifrado" << std::endl;
    std::cout << "3. Listar textos cifrados almacenados" << std::endl;
    std::cout << "4. Salir del programa" << std::endl;
    std::cout << "Elige una opción (1-4): ";
}

int main() {
    CryptoFactory factory;
    std::vector<unsigned char> output;
    std::string input;
    std::string pin = loadPin();  // Cargar PIN existente

    if (pin.empty()) {
        // Solicitar un nuevo PIN si no hay ninguno guardado
        std::cout << "No se ha encontrado un PIN guardado. Crea uno para futuras sesiones (4 a 6 dígitos): ";
        std::getline(std::cin, pin);
        if (pin.size() < 4 || pin.size() > 6) {
            std::cerr << "Error: El PIN debe tener entre 4 y 6 dígitos." << std::endl;
            return 1;
        }
        savePin(pin);  // Guardar el nuevo PIN
        std::cout << "PIN guardado exitosamente." << std::endl;
    } else {
        // Solicitar PIN existente
        std::string enteredPin;
        std::cout << "Introduce el PIN para acceder: ";
        std::getline(std::cin, enteredPin);

        if (enteredPin != pin) {
            std::cerr << "Error: PIN incorrecto. El programa se cerrará." << std::endl;
            return 1;
        }
        std::cout << "PIN correcto. Accediendo al sistema..." << std::endl;
    }

    while (true) {
        showMenu();
        int option;
        std::cin >> option;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        try {
            if (option == 1) {
                std::cout << "Introduce el texto que deseas cifrar: ";
                std::getline(std::cin, input);
                std::string name;
                std::cout << "Asigna un nombre para identificar este texto cifrado: ";
                std::getline(std::cin, name);
                auto encryptor = factory.createOperation("encrypt");
                encryptor->process(input, output);
                saveEncryptedText(output, name);
                std::cout << "El texto ha sido cifrado y almacenado correctamente." << std::endl;

            } else if (option == 2) {
                listEncryptedTexts();
                std::cout << "Introduce el número del texto cifrado que deseas recuperar: ";
                int index;
                std::cin >> index;
                std::vector<unsigned char> ciphertext;
                retrieveEncryptedText(index, ciphertext);
                auto decryptor = factory.createOperation("decrypt");
                std::vector<unsigned char> plaintext;
                decryptor->process(std::string(ciphertext.begin(), ciphertext.end()), plaintext);
                std::cout << "Texto descifrado: " << std::string(plaintext.begin(), plaintext.end()) << std::endl;

            } else if (option == 3) {
                listEncryptedTexts();

            } else if (option == 4) {
                std::cout << "Cerrando el programa. ¡Hasta pronto!" << std::endl;
                break;

            } else {
                std::cerr << "Error: Opción no válida. Por favor, selecciona una opción entre 1 y 4." << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

    return 0;
}
