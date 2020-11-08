#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <map>
#include <algorithm>
#define IPV4_HEADER_SIZE 20
using namespace std;

#pragma pack(1)
union Banderas {
  struct Desglosado {
    uint16_t posicionFragmento: 13;
    uint16_t banderas: 3;
  } desglosado;
  uint16_t numero;
};

enum Protocolos {
  IPv4,
  ARP,
  RARP,
  IPv6, 
  TCP
};

////////////////////////////////////////////////////////////

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

map<uint8_t, string> mapaTipoDeError = {
  {1, "Mensaje de destino inalcanzable"},
  {2, "Mensaje de paquete demasiado grande"},
  {3, "Time exceeded message"},
  {4, "Mensaje de problema de par�metro"},
  {128, "Mensaje del pedido de eco"},
  {129, "Mensaje de respuesta de eco"},
  {133, "Mensaje de solicitud del router"},
  {134, "Mensaje de anuncio del router"},
  {135, "Mensaje de solicitud vecino"},
  {136, "Mensaje de anuncio de vecino"},
  {137, "Reoriente el mensaje"}
};

map<uint8_t, string> mapaCodigo1 = {
  {0, "No existe ruta destino"},
  {1, "Comunicacion con el destino administrativamente prohibida"},
  {2, "No asignado"},
  {3, "Direccion inalcanzable"}
};

map<uint8_t, string> mapaCodigo3 = {
  {0, "El limite de salto excedido"},
  {1, "Tiempo de reensamble de fragmento excedido"}
};

map<uint8_t, string> mapaCodigo4 = {
  {0, "El campo del encabezado erroneo encontro"},
  {1, "El tipo siguiente desconocido del encabezado encontro"},
  {2, "Opcion desconocida del IPv6 encontrada"}
};


map<uint16_t, string> mapaPuertos = {
  {20, "(FTP - TCP)"},
  {21, "(FTP - TCP)"},
  {22, "(SSH - TCP)"},
  {23, "(TELNET - TCP)"},
  {25, "(SMTP - TCP)"},
  {53, "(DNS - TCP/UDP)"},
  {67, "(DHCP - UDP)"},
  {68, "(DHCP - UDP)"},
  {69, "(TFTP - UDP)"},
  {80, "(HTTP - TCP)"},
  {110, "(POP3 - TCP)"},
  {143, "(IMAP - TCP)"},
  {443, "(HTTPS - TCP)"},
  {993, "(IMAP SSL - TCP)"},
  {995, "(POP SSL - TCP)"}, 
  {1023, "(Puertos bien conocidos)"},
  {49151, "(Puertos registrados)"},
  {65535, "(Puertos dinámicos o privados)"}
};

////////////////////////////////////////////////////////////

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
struct ARPHeader {
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

#pragma pack(1)
struct ICMPv6 {
  uint8_t tipo;
  uint8_t codigo;
  uint16_t checksum;
};

#pragma pack(1)
struct TCPHeader {
  uint16_t puertoOrigen;
  uint16_t puertoDestino;
  uint32_t numeroSecuencia;
  uint32_t numeroAcuseDeRecibo;
  uint8_t longitudCabecera: 4;
  uint8_t reservado: 3;
  uint8_t NS: 1;
  uint8_t CWR : 1;
  uint8_t ECE : 1;
  uint8_t URG : 1;
  uint8_t ACK : 1;
  uint8_t PSH : 1;
  uint8_t RST : 1;
  uint8_t SYN : 1;
  uint8_t FIN : 1;
  uint16_t ventanaRecepcion;
  uint16_t checksum;
  uint16_t punteroUrgente;
};

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
void endswap(T *objp) {
  unsigned char *memp = reinterpret_cast<unsigned char*>(objp);
  std::reverse(memp, memp + sizeof(T));
}

Ipv4Header analizaCabeceraIpv4(fstream* archivo);
void analizaICMPv4(fstream* archivo);
void analizaARP(fstream* archivo);
string uint32AIpString(uint32_t ip);
void analizaCabeceraIpv6(fstream* archivo);
string I28ByteAIpv6String(uint8_t* ip);
void analizaICMPv6(fstream* archivo);
void analizaTCP(fstream* archivo);

int main() {
  // Archivo de entrada y salida para lee
  const string nombreArchivo = "Paquetes-redes/ethernet_ipv4_tcp.bin";
  fstream archivo(nombreArchivo.c_str());

  if (archivo.is_open()) {
    // Lee caracter por caracter mientras pueda lee = archivo.get(x)
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
      map<string, string> mapaTipoProtocolo = {{"0800", "IPv4"}, {"0806", "ARP"}, {"8035", "RARP"}, {"86DD", "IPv6"}};
      map<string, Protocolos > mapaTipoProtocolo2 = {{"0800", IPv4}, {"0806", ARP}, {"8035", RARP}, {"86DD", IPv6}, {"x", TCP}};
      enum { ICMPv4 = 1, TCP = 6, UDP = 17, ICMPv6 = 58, STP = 118, SMP = 121 };
      
      cout << "Tipo de código - ";
      char x[2];
      for (int i = 0; i < 2; i++)
        archivo.get(x[i]);
      string tipoProtocolo = toHex(x, 2);
      cout << tipoProtocolo << ' ' << mapaTipoProtocolo[tipoProtocolo] << '\n';

      switch (mapaTipoProtocolo2[tipoProtocolo]) {
        case IPv4: {
          Ipv4Header ipv4Header = analizaCabeceraIpv4(&archivo);
          switch (ipv4Header.protocolo) {
            case ICMPv4:
              analizaICMPv4(&archivo);
              break;

            case TCP:
              analizaTCP(&archivo);
              break;

            default:
              cout << "Protocolo no encontrado\n";
              break;
          }
          break;
        }

        case ARP:
          analizaARP(&archivo);
          break;

        case IPv6:
          analizaCabeceraIpv6(&archivo);
          analizaICMPv6(&archivo);
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

Ipv4Header analizaCabeceraIpv4(fstream* archivo) {
  Ipv4Header lee;
  archivo->read((char*)(&lee), sizeof(Ipv4Header));
  endswap(&lee.longitudTotal);
  endswap(&lee.identificador);
  endswap(&lee.sumaDeControlDeCabecera);
  endswap(&lee.direccionIpOrigen);
  endswap(&lee.direccionIpDestino);
  endswap(&lee.banderas.numero);
  cout << "Version: " << +lee.version << "\n";
  cout << "Tamano cabecera: " << +lee.tamanoCabecera << " = " << std::dec << lee.tamanoCabecera * 32 << "bits = " << lee.tamanoCabecera * 8 << "bytes \n";
  cout << "Tipo de servicio: " << mapaDeTipoServicio[lee.prioridad] << "\n";
  cout << "Caracteristica del servicio: \n" <<
    "\tBit 3 Retardo: " <<  (lee.caracteristicasDeServicio & (1 << 4) ? "1 = bajo" : "0 = normal") << "\n" <<
    "\tBit 4 Rendimiento: " <<  (lee.caracteristicasDeServicio & (1 << 3) ? "1 = bajo" : "0 = normal") << "\n" <<
    "\tBit 5 Fiabilidad: " <<  (lee.caracteristicasDeServicio & (1 << 2) ? "1 = bajo" : "0 = normal") << "\n";
  cout << "Longitud total: " << std::dec << lee.longitudTotal << "\n";
  cout << "Identificador: 0x" << std::hex << lee.identificador << " = " << std::dec << +lee.identificador << "\n";
  cout << "Flags (banderas): "  << "\n"
    "\tBit 0 (Reservado): " <<  (lee.banderas.desglosado.banderas & (1 << 2) ? "1 = hay algo mal, esa bandera deberia ser 0 100pre" : "0") << "\n" <<
    "\tBit 1: " <<  (lee.banderas.desglosado.banderas & (1 << 1) ? "1 = No divisible" : "0 = Divisible") << "\n" <<
    "\tBit 2: " <<  (lee.banderas.desglosado.banderas & 1 ? "1 = Le siguen mas fragmentos" : "0 = Ultimo fragmento") << "\n";
  cout << "Posicion de Fragmento: " << std::dec << lee.banderas.desglosado.posicionFragmento << "\n";
  cout << "Tiempo de vida: " << std::dec << +lee.tiempoDeVida << "\n";
  cout << "Protocolo: " << mapaDeProtocolo[lee.protocolo] << "\n";
  cout << "Checksum: 0x" << std::hex << lee.sumaDeControlDeCabecera << " = " << std::dec << ((uint32_t)lee.sumaDeControlDeCabecera) << "\n";
  cout << "Ip Origen: " << uint32AIpString(lee.direccionIpOrigen) << "\n";
  cout << "Ip Destino: " << uint32AIpString(lee.direccionIpDestino) << "\n";
  cout << '\n';
  return lee;
}

void analizaICMPv4(fstream* archivo) {
  ICMPv4 lee;
  archivo -> read((char*)(&lee), sizeof(ICMPv4));
  endswap(&lee.checksum);
  cout << "Tipo de mensaje: " << std::dec << +lee.tipo << " = " << mapaTipoDeMensaje[lee.tipo] << "\n";
  cout << "Codigo de error: " << std::dec << +lee.codigo << " = " << mapaCodigoError[lee.codigo] << "\n";
  cout << "Checksum: 0x" << std::hex << lee.checksum << "\n";
}

void analizaARP(fstream* archivo) {
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
  Ipv6Header lee ;
  archivo->read((char*)(&lee), sizeof(Ipv6Header));
  endswap(&lee.primeraParte);
  endswap(&lee.tamanoDatos);
  cout << "Version: " << (lee.primeraParte >> 28) << "\n";
  cout << "Tipo de servicio: " << ((lee.primeraParte >> 20) & 0xFF) << " = " << mapaDeTipoServicio[((lee.primeraParte >> 20) & 0xFF)] << "\n";
  cout << "Etiqueta de flujo: " << std::dec << ((lee.primeraParte & 0xFFFFF)) << "\n";
  cout << "Tamano de datos: " << std::dec << lee.tamanoDatos << "\n";
  cout << "Encabezado siguiente: " << std::dec << (int)lee.encabezadoSiguiente << " = " << mapaDeProtocolo[lee.encabezadoSiguiente] << "\n";
  cout << "Limite de salto: " << std::dec << (int)lee.limiteDeSalto << "\n";
  cout << "Ipv6 Origen: " << I28ByteAIpv6String(lee.direccionOrigen) << "\n";
  cout << "Ipv6 Destino: " << I28ByteAIpv6String(lee.direccionDestino) << "\n";
}

void analizaICMPv6(fstream* archivo) {
  ICMPv6 lee;
  archivo->read((char*)(&lee), sizeof(ICMPv6));
  endswap(&lee.checksum);
  cout << "Tipo: " << std::dec << +lee.tipo << " = " << mapaTipoDeError[lee.tipo] << endl;
  cout << "Codigo: " << std::dec << +lee.codigo;

  switch((int)lee.tipo)
  {
  case 1:
      cout << " = " <<mapaCodigo1[lee.codigo] << endl;
      break;
  case 3:
      cout << " = " << mapaCodigo3[lee.codigo] << endl;
      break;
  case 4:
      cout << " = " << mapaCodigo4[lee.codigo] << endl;
      break;
  default:
      cout << endl;
      break;
  }
  cout << "Checksum: " << std::hex << lee.checksum << endl;
}

void analizaTCP(fstream* archivo) {
  TCPHeader lee;
  archivo -> read((char*)(&lee), sizeof(TCPHeader));
  endswap(&lee.checksum);
  {
    map<uint16_t, string>::iterator it;
    if (!mapaPuertos.count(lee.puertoOrigen)) 
      lee.puertoOrigen = max<uint16_t>(1023, lee.puertoOrigen);
    it = mapaPuertos.lower_bound(lee.puertoOrigen);
    cout << "Puerto origen - " << std::dec << +lee.puertoOrigen << " " << it->second <<  "\n";

    if (!mapaPuertos.count(lee.puertoDestino)) 
      lee.puertoDestino = max<uint16_t>(1023, lee.puertoDestino);
    it = mapaPuertos.lower_bound(lee.puertoDestino);
    cout << "Puerto destino - " << std::dec << +lee.puertoDestino << " " << it->second <<  "\n";
  }

  cout << "Número de secuencia - " << std::dec << +lee.numeroSecuencia << '\n';
  cout << "Número de acuse de recibo - " << std::dec << +lee.numeroAcuseDeRecibo << '\n';
  cout << "Longitud de cabecera - "; printHex((lee.longitudCabecera >> 4) & 0xFF); cout << '\n';
  cout << "Reservado - " << std::dec << +lee.reservado << '\n';

  cout << "Banderas\n";
  cout << "NS - " << std::dec << +lee.NS << '\n';
  cout << "CWR - " << std::dec << +lee.CWR << '\n';
  cout << "ECE - " << std::dec << +lee.ECE << '\n';
  cout << "URG - " << std::dec << +lee.URG << '\n';
  cout << "ACK - " << std::dec << +lee.ACK << '\n';
  cout << "PSH - " << std::dec << +lee.PSH << '\n';
  cout << "RST - " << std::dec << +lee.RST << '\n';
  cout << "SYN - " << std::dec << +lee.SYN << '\n';
  cout << "FIN - " << std::dec << +lee.FIN << '\n';

  cout << "Ventana de recepción - " << std::dec << +lee.ventanaRecepcion << '\n';
  cout << "Checksum - "; printHex(lee.checksum); cout << '\n';
  cout << "Puntero urgente - " << std::dec << +lee.punteroUrgente << '\n';
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
