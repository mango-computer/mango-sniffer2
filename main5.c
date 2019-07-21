
/*
 * mangovisiblenet 1.0.0
 * Copyright (C) 2009 Mango Computer c.a Jose Andres Morales
 *
 * Email comprasmangocomputer@gmail.com for information about contributors
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * compilar gcc -o ms2 main5.c -lpcap
 * Es necesario tener instalada la libreria pcap http://www.tcpdump.org/pcap.htm
 */



#include <stdio.h> 
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <string.h>

#define PACKETSIZE	64
#define VERSION		"Version 1.0.0"

void dump(void* b, int len);
void llegada(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void uso();

struct packet_icmp
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

	

int main(int nump, char* param[]){


	char *net; 			// direccion de red
	char *mask; 			// mascara de subred
	char *dev; 			// nombre del dispositivo de red
	int ret; 			// codigo de retorno
	char errbuf[PCAP_ERRBUF_SIZE]; // buffer para mensajes de error
	bpf_u_int32 netp; 		// direcion de red en modo raw
	bpf_u_int32 maskp; 		// mascara de red en modo raw
	struct bpf_program fp;		// contenedor con el programa compilado
	struct in_addr addr;
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr; // Ethernet

	uso();

	printf("Obteniendo Tarjeta de red [");

	if ((dev = pcap_lookupdev(errbuf))==NULL){ //obtener la tarjeta de red
		printf("Fallo]-> %s\n", errbuf);
		exit(-1);
	} 
	
	printf("OK] \n->	%s\n",dev);
	
	printf("Obtener red y mascara [");

	if ((ret = pcap_lookupnet(dev, &netp, &maskp, errbuf))==-1){
		printf("Fallo]-> %s\n", errbuf);
		exit(-1);
	}
	
	addr.s_addr = netp;
	if ((net = inet_ntoa(addr))==NULL){
		printf("Fallo]->  Red -> inet_ntoa\n");
		exit(-1);
	}	
	
	printf("OK] \n-> Red: %s\n",net);

	addr.s_addr = maskp;
	if ((mask = inet_ntoa(addr))==NULL){
		printf("[Fallo]->  Mascara de Red -> inet_ntoa\n");
		exit(-1);
	}	

	printf("-> Mascara de Red: %s\n", mask);

	if ((descr=pcap_open_live(dev,BUFSIZ,1,20,errbuf))==NULL){
		printf("Fallo en open live: %s\n",errbuf);
		exit(-1);
	}

	if (nump>1 ){
		printf("*** Opcion de Filtrado Activa ***\n Compilar Filtro [");	

		if ((pcap_compile(descr, &fp, param[1], 0, netp)) == -1){
			printf("Fallo] compilando %s\n",param[1]);
			exit(-1);
		}	
		printf("OK] %s\n",param[1]);
	
		printf("Estableciendo Filtro [");
	
		if ((pcap_setfilter(descr,&fp))==-1){
			printf("Fallo] estableciendo filtro \n");
			exit(-1);
		}

		printf("OK]\n");
		pcap_loop(descr,(nump==3 ? atoi(param[2]):1),llegada,NULL);

	} else {
		pcap_loop(descr,2,llegada,NULL);
	}
	
	printf("\n..\n");	

	exit(0);

}//end main


void dump(void* b, int len)
{   unsigned char *buf = b;
    int i, cnt=0;
    char str[17];
    memset(str, 0, 17);


    for ( i = 0; i < len; i++ )
    {
        if ( cnt % 16 == 0 )
        {
	    printf("  %s\n%04X: ", str, cnt);
	    memset(str, 0, 17);
        }
        if ( buf[cnt] < ' '  ||  buf[cnt] >= 127 )
            str[cnt%16] = '.';
        else
            str[cnt%16] = buf[cnt];
	printf("%02X ", buf[cnt++]);	
    }
    
    printf("  %*s\n\n", 16+(16-len%16)*2, str);
}


/*
* Función que es llamada por la libreria pcap cada vez que llega 
* una trama a la tarjeta de red
*
* void llegada(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
* 
* Donde el parametro const u_char* packet es una arreglo de bytes sin signo de los datos
* totales de la trama.  
*/

void llegada(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	static int count;
	int largoCabeceras;
	struct ether_header *eptr;
	struct ip *ipc;
	struct ether_arp *arpc;
	int largoTrama;

	count++;
	printf("TN %d\n",count); 		//Trama numero 	
	eptr = (struct ether_header *) packet;

	printf("%s->", ether_ntoa((struct ether_addr*)eptr->ether_shost)); 		//MAC origen:
	printf("%s ", ether_ntoa((struct ether_addr*)eptr->ether_dhost));		//MAC destino 

	if (ntohs(eptr->ether_type)==ETHERTYPE_IP){
		printf("IP ");
		ipc = (struct ip *) (packet+sizeof(struct ether_header));
		largoTrama = ntohs(ipc->ip_len)+sizeof(struct ether_header);
		printf("%s->",inet_ntoa(ipc->ip_src)); 		//ip origen
		printf("%s ",inet_ntoa(ipc->ip_dst));
		printf("TTL:%d ",ipc->ip_ttl);
		printf("TS:%d ",ipc->ip_tos); 			//Tipo de Servicio
		printf("ID:%d ",ntohs(ipc->ip_id));
		printf("OFF:%d ",ntohs(ipc->ip_off));
		printf("CS:%d ",ntohs(ipc->ip_sum));		//Check Suma
		printf("LT:%d\n",largoTrama); 			//len trama

	} else if (ntohs(eptr->ether_type)==ETHERTYPE_ARP){
		printf(" ARP ");
		arpc = (struct ether_arp *) (packet+sizeof(struct ether_header));
		printf("%d.%d.%d.%d->",arpc->arp_spa[0],arpc->arp_spa[1],arpc->arp_spa[2],arpc->arp_spa[3] );	//ip origen
		printf("%d.%d.%d.%d\n",arpc->arp_tpa[0],arpc->arp_tpa[1],arpc->arp_tpa[2],arpc->arp_tpa[3] );	//ip destino
		printf("TH:%d",ntohs(arpc->ea_hdr.ar_hrd)); 	//Tipo de Hardware
		printf("TP:%d ",ntohs(arpc->ea_hdr.ar_pro)); 	//Tipo Protocolo
		printf("LDH:%d ",arpc->ea_hdr.ar_hln); 		//Len Direccion Hardware
		printf("LDR:%d ",arpc->ea_hdr.ar_pln);		//Len Direccion Red
		printf("CO:%d ",ntohs(arpc->ea_hdr.ar_op)); 	//Codigo Operacion
		printf("HO:%s ", ether_ntoa((struct ether_addr*)arpc->arp_sha));			//Hardware origen
		printf("HD:%s\n", ether_ntoa((struct ether_addr*)arpc->arp_tha));			//Hardware Destino
		dump((void*)(packet+sizeof(struct ether_header)),sizeof(struct ether_arp));
		return;
	} else if (ntohs(eptr->ether_type)==ETHERTYPE_REVARP){
		printf(" RARP\n");
		return;
	} else {
		printf("Es de Tipo Desconocido\n");
		dump((void*)packet,sizeof(struct ether_header));
		return;
	}// end if	
	

	switch(ipc->ip_p) {

		case 1: {
			printf(" ICMP ");
			struct packet_icmp *cicmp = (struct packet_icmp*)(packet+sizeof(struct ether_header) + (ipc->ip_hl*4));
			printf("TP:%d ", cicmp->hdr.type);
			printf("CO:%d ", cicmp->hdr.code);
			printf("CS:%d ", ntohs(cicmp->hdr.checksum));
			printf("ID:%d ", ntohs(cicmp->hdr.un.echo.id));
			printf("SQ:%d ", ntohs(cicmp->hdr.un.echo.sequence));
			printf("GW:%d\n", ntohs(cicmp->hdr.un.gateway));
			largoCabeceras = (sizeof(struct ether_header) + (ipc->ip_hl*4) + sizeof(struct icmphdr));			
			dump((void*)(packet+largoCabeceras),(largoTrama-largoCabeceras));
			break;
		} case 6: {
			printf(" TCP ");
			struct tcphdr *tcpc = (struct tcphdr*)(packet+sizeof(struct ether_header) + (ipc->ip_hl*4));
			printf("PO:%d ", ntohs(tcpc->source));		//Puerto de Origen: 
			printf("PD:%d ", ntohs(tcpc->dest));		//Puerto de Destino:
			int tmp_len_tcphdr = tcpc->doff*4;
			printf("LC:%d ", tmp_len_tcphdr);
			printf("NS:%d ", ntohs(tcpc->seq));		//Numero de Secuencia:
			printf("NA:%d ", ntohs(tcpc->ack_seq));		//Numero de acuse de recibo:
			printf("cwr:%d ", tcpc->res2&0x01);
			printf("ece:%d ", tcpc->res2&0x02);
			printf("urg:%d ", tcpc->urg);
			printf("ack:%d ", tcpc->ack);
			printf("psh:%d ", tcpc->psh);
			printf("rst:%d ", tcpc->rst);
			printf("syn:%d ", tcpc->syn);
			printf("fin:%d ", tcpc->fin);
			printf("WI:%d ", tcpc->window);
			printf("CS:%d ", tcpc->check);
			printf("UR:%d\n", tcpc->urg_ptr);

			if (tmp_len_tcphdr>20){
				largoCabeceras = (sizeof(struct ether_header) + (ipc->ip_hl*4) + 20);
				printf("Opciones len %d\n",tmp_len_tcphdr-20);			
			} else {
				largoCabeceras = (sizeof(struct ether_header) + (ipc->ip_hl*4) + tmp_len_tcphdr);
			}
			dump((void*)(packet+largoCabeceras),(largoTrama-largoCabeceras));
			break;
		} case 17: {
			printf(" UDP ");
			struct udphdr *udpc= (struct udphdr*)(packet+sizeof(struct ether_header) + (ipc->ip_hl*4));
			largoCabeceras = (sizeof(struct ether_header) + (ipc->ip_hl*4) + sizeof(struct udphdr));			
			printf("PO:%d ", ntohs(udpc->source)); 		//Puerto de Origen:
			printf("PD:%d ", ntohs(udpc->dest)); 		//Puerto de Destino
			printf("CS:%d\n", ntohs(udpc->check));		//check suma
			dump((void*)(packet+largoCabeceras),(largoTrama-largoCabeceras));
			break;
		} default: {

			printf("Otro Paquete #%d \n",ipc->ip_p);
			dump((void*)packet,largoTrama);
		}
	}//end switch
	printf("\n");

} 

void uso(){

	printf("Mango Computer c.a \nProgramado por: Jose Andres Morales email:comprasmangocomputer@gmail.com\nMango Visible Red %s\nEste programa es sofware libre\n\n? sudo <\'>> NOMBRE_ARCHIVO\'> ./ms2 <FILTRO><MAX PAQUETES A CAPTURAR>\nNomenclatura:\nTN: Numero de Trama\n\nCabedera IP\nTTL: Tiempo de Vida\nTS: Tipo se Servicio\nID:ID del programa\nOFF: Offset\nCS: CheckSum\nLT:Largo de Toda la Trama\n\nCabecera ARP\nTH:Tipo de Hardware\nTP:Tipo de Protocolo\nLDH:Largo Direccion de Hardware\nLDR:Largo Direccion de Red\nCO:Codigo Operacion\nHO:MAC del Hardware de Origen\nHD:MAC del Hardware Destino\n\nPaquete ICMP\nTP:Tipo\nCO:Codigo\nCS:CheckSum\nID:ID del Programa\nSQ: Secuencia\nGW:Gateway\nPaquete TCP\nPO:Puerto Origen\nPD:Puerto Destino\nLC:Largo Cabecera TCP\nNS:Numero de Secuencia\nNA:Numero de Acuse de Recibo NACK\nWI: Window Tamaño de la ventana del buffer\nCS:CheckSum\nUR:Puntero Urgente\n\nPaquete UDP\nPO:Puerto Origen\nPD:Puerto Destino\nCS:CheckSum\n\nIniciando...\n\n",VERSION); 
}
