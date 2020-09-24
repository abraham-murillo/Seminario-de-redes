#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <map>
#include <algorithm>
#define IPV4_HEADER_SIZE 20

#pragma pack(1)
union Banderas {
  struct Desglosado {
    uint16_t posicionFragmento: 13;
    uint16_t banderas: 3;
  } desglosado;
  uint16_t numero;
};

#pragma pack(1)
struct Ipv4Header {
  uint8_t tamanoCabecera: 4;
  uint8_t version: 4;
  uint8_t caracteristicasDeServicio: 5;
  uint8_t prioridad: 3;
  uint16_t longitudTotal;
  uint16_t identificador;
  Banderas banderas;
  uint8_t tiempoDeVida;
  uint8_t protocolo;
  uint16_t sumaDeControlDeCabecera;
  uint32_t direccionIpOrigen;
  uint32_t direccionIpDestino;
};


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
template <class T>
void endswap(T *objp)
{
  unsigned char *memp = reinterpret_cast<unsigned char*>(objp);
  std::reverse(memp, memp + sizeof(T));
}

void analizaCabeceraIpv4(fstream* archivo);
string uint32AIpString(uint32_t ip);

int main() {

  // Archivo de entrada y salida para leer
  const string nombreArchivo = "Paquetes-redes/ethernet_ipv4_icmp_ping_2.bin";
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

    analizaCabeceraIpv4(&archivo);
    
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

map<uint8_t, string> mapaDeTipoServicio = {
  {0b000, "0b000 De rutina"},
  {0b001, "0b001 Prioritario"},
  {0b010, "0b010 Inmediato"},
  {0b011, "0b011 Relampago"},
  {0b100, "0b100 Invalidacion relampago"},
  {0b101, "0b101 Procesando llamada critica y de emergencia"},
  {0b110, "0b110 Control de trabajo de Internet"},
  {0b111, "0b111 Control de red"}
};

map<uint8_t, string> mapaDeProtocolo = {
  {1, "ICMP v4"},
  {6, "TCP"},
  {17, "UDP"},
  {58, "ICMPv6"},
  {118, "STP"},
  {121, "SMP"},
};


void analizaCabeceraIpv4(fstream* archivo) {
  Ipv4Header leido ;
  archivo->read((char*)(&leido), sizeof(Ipv4Header));
  endswap(&leido.longitudTotal);
  endswap(&leido.identificador);
  endswap(&leido.sumaDeControlDeCabecera);
  endswap(&leido.direccionIpOrigen);
  endswap(&leido.direccionIpDestino);
  endswap(&leido.banderas.numero);
  cout << "Version: " << +leido.version << "\n";
  cout << "Tamano cabecera: " << +leido.tamanoCabecera << " = " << std::dec << leido.tamanoCabecera * 32 << "bits = " << leido.tamanoCabecera * 8 << "bytes \n";
  cout << "Tipo de servicio: " << mapaDeTipoServicio[leido.prioridad] << "\n";
  cout << "Caracteristica del servicio: \n" <<
    "\tBit 3 Retardo: " <<  (leido.caracteristicasDeServicio & (1 << 4) ? "1 = bajo" : "0 = normal") << "\n" <<
    "\tBit 4 Rendimiento: " <<  (leido.caracteristicasDeServicio & (1 << 3) ? "1 = bajo" : "0 = normal") << "\n" <<
    "\tBit 5 Fiabilidad: " <<  (leido.caracteristicasDeServicio & (1 << 2) ? "1 = bajo" : "0 = normal") << "\n";
  cout << "Longitud total: " << std::dec << leido.longitudTotal << "\n";
  cout << "Identificador: 0x" << std::hex << leido.identificador << " = " << std::dec << +leido.identificador << "\n";
  cout << "Flags (banderas): "  << "\n"
    "\tBit 0 (Reservado): " <<  (leido.banderas.desglosado.banderas & (1 << 2) ? "1 = hay algo mal, esa bandera deberia ser 0 100pre" : "0") << "\n" <<
    "\tBit 1: " <<  (leido.banderas.desglosado.banderas & (1 << 1) ? "1 = No divisible" : "0 = Divisible") << "\n" <<
    "\tBit 2: " <<  (leido.banderas.desglosado.banderas & 1 ? "1 = Le siguen mas fragmentos" : "0 = Ultimo fragmento") << "\n";
  cout << "Posicion de Fragmento: " << std::dec << leido.banderas.desglosado.posicionFragmento << "\n";
  cout << "Tiempo de vida: " << std::dec << +leido.tiempoDeVida << "\n";
  cout << "Protocolo: " << mapaDeProtocolo[leido.protocolo] << "\n";
  cout << "Checksum: 0x" << std::hex << leido.sumaDeControlDeCabecera << " = " << std::dec << ((uint32_t)leido.sumaDeControlDeCabecera) << "\n";
  cout << "Ip Origen: " << uint32AIpString(leido.direccionIpOrigen) << "\n";
  cout << "Ip Destino: " << uint32AIpString(leido.direccionIpDestino) << "\n";

}

string uint32AIpString(uint32_t ip) {
  stringstream ss;
  ss << ((ip >> 24) & 0xFF) <<
  "." << ((ip >> 16) & 0xFF) <<
  "." << ((ip >> 8) & 0xFF) <<
  "." << (ip & 0xFF);
  return ss.str();
}

