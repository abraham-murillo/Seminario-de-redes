#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <map>
using namespace std;

template <class T>
void printHex(T x) {
  // Imprime el número en hexadecimal a dos dígitos sin salto de línea
  cout << setfill('0') << setw(2) << hex << (0xff & (unsigned int)x);
}

string toHex(char* bytes, int size) {
  static string hex = "0123456789ABCDEF";
  string ans;
  for (int i = 0; i < size; ++i) {
    const char ch = bytes[i];
    ans += hex[(ch & 0xF0) >> 4];
    ans += hex[ch & 0xF];
  }
  return ans;
}

int main() {

  // Archivo de entrada y salida para leer
  const string nombreArchivo = "Paquetes-redes/ethernet_1.bin";
  fstream archivo(nombreArchivo.c_str());

  if (archivo.is_open()) {
    // Lee caracter por caracter mientras pueda leer = archivo.get(x)
    {
      char x;
      cout << "Dirección MAC de origen - ";
      for (int i = 0; i < 6; i++) {
        if (i > 0) {
          cout << ":";
        }
        archivo.get(x);
        printHex(x);
      }
      cout << '\n';
    }

    {
      char x;
      cout << "Dirección MAC de destino - ";
      for (int i = 0; i < 6; i++) {
        if (i > 0) {
          cout << ":";
        }
        archivo.get(x);
        printHex(x);
      }
      cout << '\n';
    }

    {
      map<string, string> mp = {{"0800", "IPv4"}, {"0806", "ARP"}, {"8035", "RARP"}, {"86DD", "IPv6"}};
      cout << "Tipo de código - ";
      char x[2];
      for (int i = 0; i < 2; i++)
        archivo.get(x[i]);
      string codigo = toHex(x, 2);
      cout << codigo << ' ' << mp[codigo] << '\n';
    }

    {
      char x;
      cout << "Datos - \n";
      while (archivo.get(x)) {
        printHex(x);
      }
      cout << '\n';
    }
  } else {
    cout << "Algo hiciste mal >:c\n";
    return 1;
  }

  archivo.close();

  return 0;
}
