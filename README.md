# secureText_Manager

secureText_Manager es una aplicación en C++ que permite cifrar y descifrar textos utilizando el algoritmo AES-128-CBC de OpenSSL. Los textos cifrados se almacenan en un archivo binario y se pueden recuperar usando un PIN de sesión.

## Características
- Cifrado y descifrado de textos usando AES-128-CBC.
- Gestión segura del PIN de sesión.
- Almacenamiento de textos cifrados en un archivo binario.
- Recuperación de textos cifrados mediante un índice.

## Requisitos para la compilación
1. **Sistema Operativo**: macOS (funciona en Linux y Windows con ajustes mínimos).
2. **Dependencias**: 
   - OpenSSL: `brew install openssl` en macOS.
   - Compilador de C++: g++ o clang++.
   
## Compilación
1. Abre una terminal y navega al directorio del proyecto:
2. Ejecuta el siguiente comando para compilar el proyecto, mismo que genera el archivo ejecutable secureText_Manager en el directorio raíz del proyecto:
```bash
g++ -o secureText_Manager src/main.cpp -lssl -lcrypto
