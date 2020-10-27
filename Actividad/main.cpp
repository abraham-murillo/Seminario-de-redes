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

enum ValoresS{
  IPv4,
  ARP,
  RARP,
  IPv6
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

#pragma pack(1)
struct Ipv6Header {
  uint32_t primeraParte; 
  uint16_t tamanoDatos;
  uint8_t encabezadoSiguiente;
  uint8_t limiteDeSalto;
  uint8_t direccionOrigen[16];
  uint8_t direccionDestino[16];
};

#pragma pack(1)
struct ICMPv4 {
    uint8_t tipo;
    uint8_t codigo;
    uint16_t checksum;
};

#pragma pack(1)
struct ARPHeader{
  uint16_t tipoHardware;
  uint8_t tipoProtocolo;
  uint8_t tipoProtocolo2;
  uint8_t dirHardware;
  uint8_t dirProtocolo;
  uint16_t codOperacion;
  uint8_t mac;
  uint8_t mac2;
  uint8_t mac3;
  uint8_t mac4;
  uint8_t mac5;
  uint8_t mac6;
  uint32_t direccionIPEmisor;
  uint8_t macDestino;
  uint8_t macDestino2;
  uint8_t macDestino3;
  uint8_t macDestino4;
  uint8_t macDestino5;
  uint8_t macDestino6;
  uint32_t direccionIPReceptor;
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
void analizaICMP(fstream* archivo);
void analizaARP(fstream* archivo);
string uint32AIpString(uint32_t ip);
void analizaCabeceraIpv6(fstream* archivo);
string I28ByteAIpv6String(uint8_t* ip);

int main() {  
  // Archivo de entrada y salida para leer
  const string nombreArchivo = "Paquetes-redes/ipv6_icmpv6_hop_limit.bin";
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
      map<string, ValoresS> mp2 = {{"0800", IPv4}, {"0806", ARP}, {"8035", RARP}, {"86DD", IPv6}};
      cout << "Tipo de código - ";
      char x[2];
      for (int i = 0; i < 2; i++)
        archivo.get(x[i]);
      string codigo = toHex(x, 2);
      cout << codigo << ' ' << mp[codigo] << '\n';
      switch (mp2[codigo])
      {
        case IPv4:
          analizaCabeceraIpv4(&archivo);
          analizaICMP(&archivo);
          break;
        case ARP:
          analizaARP(&archivo);
          break;
        case IPv6:
          analizaCabeceraIpv6(&archivo);
          break;
        default:
          cout << "Desconocido" << endl;
          break;
      }
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

map<uint8_t, string> mapaTipoDeMensaje = {
  {0, "Echo Reply"},
  {3, "Destination Unreachable"},
  {4, "Source Quench"},
  {5, "Redirect"},
  {8, "Echo"},
  {11, "Time Exceeded"},
  {12, "Parameter Problem"},
  {13, "Timestamp"},
  {14, "Timestamp Reply"},
  {15, "Information Request"},
  {16, "Information Request"},
  {17, "Addressmask"},
  {18, "Addressmask Reply"}
};

map<uint8_t, string> mapaCodigoError = {
  {0, "No se puede llegara a la red"},
  {1, "No se puede llegar al host"},
  {2, "El destino no dispone del protocolo solicitado"},
  {3, "No se puede llegar al puerto destino o la aplicación destino no está libre"},
  {4, "Se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario"},
  {5, "La ruta de origen no es correcta"},
  {6, "No se conoce la red destino"},
  {7, "No se conoce la host destino "},
  {8, "El host origen está aislado"},
  {9, "La comunicación con la red destino está prohibida por razones administrativas"},
  {10, "La comunicación con el host destino está prohibida por razones administrativas"},
  {11, "No se puede llegar a la red destino debido al Tipo de servicio"},
  {12, "No se puede llegar al host destino debido al Tipo de servicio"}
};

map<uint16_t, string> mapaCodOperacion = {
  {0, "Reserved"},
  {1, "REQUEST"},
  {2, "REPLY"},
  {3, "request Reverse"},
  {4, "reply Reverse"},
  {5, "DRARP-Request"},
  {6, "DRARP-Reply"},
  {7, "DRARP-Error"},
  {8, "InARP-Request"},
  {9, "InARP-Reply"},
  {10, "ARP-NAK"},
  {11, "MARS-Request"},
  {12, "MARS-Multi"},
  {13, "MARS-MServ"},
  {14, "MARS-Join"},
  {15, "MARS-Leave"}
};

map<uint16_t, string> mapaTipoHardware = {
  {0, "Reserved"},
  {1, "Ethernet (10Mb)"},
  {2, "Experimental Ethernet (3Mb)"},
  {3, "Amateur Radio AX.25"},
  {4, "Proteon ProNET Token Ring"},
  {5, "Chaos"},
  {6, "IEEE 802 Networks"},
  {7, "ARCNET"},
  {8, "Hyperchannel"},
  {9, "Lanstar"},
  {10, "Autonet Short Address"},
  {11, "LocalTalk"},
  {12, "LocalNet (IBM PCNet or SYTEK LocalNET)"},
  {13, "Ultra link"},
  {14, "SMDS"},
  {15, "Frame Relay"},
  {16, "Asynchronous Transmission Mode (ATM)"},
  {17, "HDLC"},
  {18, "Fibre Channel"},
  {19, "Asynchronous Transmission Mode (ATM)"},
  {20, "Serial Line"},
  {21, "Asynchronous Transmission Mode (ATM)"},
  {22, "MIL-STD-188-220"},
  {23, "Metricom"},
  {24, "IEEE 1394.1995"},
  {25, "MAPOS"},
  {26, "Twinaxial"},
  {27, "EUI-64"},
  {28, "HIPARP"},
  {29, "IP and ARP over ISO 7816-3"},
  {30, "ARPSec"},
  {31, "IPsec tunnel"},
  {32, "InfiniBand (TM)"},
  {33, "TIA-102 Project 25 Common Air Interface (CAI)"},
  {34, "Wiegand Interface"},
  {35, "Pure IP"},
  {36, "HW_EXP1"},
  {37, "HFI"},
  {38, "Unassigned"},
  {256, "HW_EXP2"},
  {257, "AEthernet"},
  {258, "Unassigned"},
  {65535, "Reserved"}
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

void analizaICMP(fstream* archivo)
{
    ICMPv4 leer;
    archivo -> read((char*)(&leer), sizeof(ICMPv4));
    endswap(&leer.checksum);
    cout << "Tipo de mensaje: " << std::dec << +leer.tipo << " = " << mapaTipoDeMensaje[leer.tipo] << "\n";
    cout << "Codigo de error: " << std::dec << +leer.codigo << " = " << mapaCodigoError[leer.codigo] << "\n";
    cout << "Checksum: 0x" << std::hex << leer.checksum << "\n";
}

void analizaARP(fstream* archivo)
{
  ARPHeader lee;
  archivo -> read((char*)(&lee), sizeof(ARPHeader));
  endswap(&lee.tipoHardware);
  endswap(&lee.codOperacion);
  endswap(&lee.direccionIPEmisor);
  endswap(&lee.direccionIPReceptor);
  cout << "Tipo de hardware - " << std::dec << +lee.tipoHardware << " = " << mapaTipoHardware[lee.tipoHardware] <<  "\n";
  cout << "Tipo de protocolo - "; printHex(lee.tipoProtocolo); printHex(lee.tipoProtocolo2); cout << "\n";
  cout << "Longitud de hardware - " << std::dec << +lee.dirHardware <<"\n";
  cout << "Longitud de protocolo - " << std::dec << +lee.dirProtocolo << "\n";
  cout << "Codigo de Operacion - " << std::dec << +lee.codOperacion << " = " << mapaCodOperacion[lee.codOperacion] << "\n";
  cout << "Direccion MAC emisor - ";
  printHex(lee.mac); cout << ":"; printHex(lee.mac2); cout << ":";
  printHex(lee.mac3); cout << ":"; printHex(lee.mac4); cout << ":";
  printHex(lee.mac5); cout << ":"; printHex(lee.mac6); cout<< "\n";
  cout << "Direccion IP emisor - " << uint32AIpString(lee.direccionIPEmisor) << "\n";
  cout << "Direccion MAC receptor - ";
  printHex(lee.macDestino); cout << ":"; printHex(lee.macDestino2); cout << ":";
  printHex(lee.macDestino3); cout << ":"; printHex(lee.macDestino4); cout << ":";
  printHex(lee.macDestino5); cout << ":"; printHex(lee.macDestino6); cout<< "\n";
  cout << "Direccion IP receptor - " << uint32AIpString(lee.direccionIPReceptor) << "\n";
}

void printIpV6(uint8_t* first) {
  cout << "\n";
  for(int i = 0; i < 128; i++){
    cout << std::dec;
    cout << (int)first[i] << ",";
  }
  cout << "\n";
}


void analizaCabeceraIpv6(fstream* archivo) {
  Ipv6Header leido ;
  archivo->read((char*)(&leido), sizeof(Ipv6Header));
  endswap(&leido.primeraParte);
  endswap(&leido.tamanoDatos);
  cout << "Version: " << (leido.primeraParte >> 28) << "\n";
  cout << "Tipo de servicio: " << mapaDeTipoServicio[((leido.primeraParte >> 20) & 0xFF)] << "\n";
  cout << "Etiqueta de flujo: " << std::dec << ((leido.primeraParte & 0xFFFFF)) << "\n";
  cout << "Tamano de datos: " << std::dec << leido.tamanoDatos << "\n";
  cout << "Encabezado siguiente: " << std::dec << (int)leido.encabezadoSiguiente << "\n";
  cout << "Limite de salto: " << std::dec << (int)leido.limiteDeSalto << "\n";
  cout << "Ipv6 Origen: " << I28ByteAIpv6String(leido.direccionOrigen) << "\n";
  cout << "Ipv6 Destino: " << I28ByteAIpv6String(leido.direccionDestino) << "\n";
}


string uint32AIpString(uint32_t ip) {
  stringstream ss;
  ss << ((ip >> 24) & 0xFF) <<
  "." << ((ip >> 16) & 0xFF) <<
  "." << ((ip >> 8) & 0xFF) <<
  "." << (ip & 0xFF);
  return ss.str();
}

string I28ByteAIpv6String(uint8_t* ipv6) {
  stringstream ss;
  ss << std::hex;
  for(int i = 0; i < 16; i++){
    ss << std::setfill('0') << std::setw(2);
    ss << (int)ipv6[i];
    if (i % 2 == 1 && i != 15) {
      ss << ":";
    }
  }
  return ss.str();
}

