#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
using namespace std;

template <class T>
void printHex(T x) {
  // Imprime el número en hexadecimal a dos dígitos con salto de línea
  cout << setfill('0') << setw(2) << hex << (0xff & (unsigned int)x);
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
      cout << "Tipo de código - ";
      char x, y;
      archivo.get(x), archivo.get(y);
      printHex(x), printHex(y); // Pasar a los formatos de acuerdo a la tabla
      cout << '\n';
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