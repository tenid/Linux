#define _CRT_SECURE_NO_WARNINGS    // fopen 보안 경고로 인한 컴파일 에러 방지
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> 
#include<stdlib.h>    
#include<string.h>    
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/ip_icmp.h>
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<signal.h>
#include <time.h>


void ProcessPacket(unsigned char*, int, int);
void simply_print(unsigned char*, int, int);
void print_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void print_icmp_packet(unsigned char*, int);
void printdata(unsigned char*, int);
void print_http(unsigned char*, int);
void print_https(unsigned char*, int);
void print_dns(unsigned char*, int);
void print_telnet(unsigned char*, int);
void print_ftp(unsigned char*, int);
void print_ip_flags_frag(int);
void print_tcp_flags(int);
void print_left_dot(int, int[]);
void print_right_dot(int, int[], int);
void print_set(int);
void print_dns_response_flags(char[], char[]);
void print_dns_request_flags(char[], char[]);
int iden_http(char[3][10]);
void check_res(int);
void check_opc(int[]);
void check_auth(int);
void check_trun(int);
void check_red(int);
void check_rea(int);
void check_ans(int);
void check_non(int);
void check_rec(int[]);
int tran_hex(char[2][2]);
void ans_data(int, int, int, unsigned char*, char[1000], int, int);
void print_view(int);
void handler(int);

struct sockaddr_in source, dest;
int check = 0; int count = 0;

typedef struct Node {
   int index;
   int protocol;
   char tran_id[2][10];
   char* buffer;
   struct tcphdr* tcph;
   struct udphdr* udph;
   struct icmphdr* icmph;
   struct timeval getTime;
   int size;
}Packet;
Packet packet[1000] = { 0, };
int flags = 0;
FILE *fp ;
int main() {
   int saddr_size, data_size, num = 5;
   struct sockaddr saddr;
   struct iphdr* iph;
   void (*hand)(int);
   fp = fopen("log.txt", "wt");
   hand = signal(SIGQUIT, handler);
   if (hand == SIG_ERR) {
      perror("signal");
      exit(0);
   }


   printf("컴퓨터 네트워크 7팀 패킷 캡처 프로그램\n");
   printf("프로그램 설명 \n");



   while (1) {
      int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

      if (sock_raw < 0)
      {
         //Print the error with proper message
         perror("Socket Error");
         return 1;
      }

      printf("Capture Start! \n");
      printf("Num\tSource\t\t\t Destination\t\t Protocol\t Length\t\t Info\n");
      check = 1;
      while (1)
      {
         unsigned char* buffer = (unsigned char*)malloc(65536);
         saddr_size = sizeof saddr;
         //Receive a packet
         data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)& saddr_size);

  
         if (data_size < 0)
         {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
         }

         if (flags == 1) {
            break;      //ctrl + \ 입력시 탈출
         }
         iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
         memset(&source, 0, sizeof(source));
         source.sin_addr.s_addr = iph->saddr;
     	//except local loopback
         if (strcmp(inet_ntoa(source.sin_addr), "127.0.1.1") != 0 && strcmp(inet_ntoa(source.sin_addr), "127.0.0.1") != 0
        			&& strcmp(inet_ntoa(source.sin_addr),"127.0.0.53") != 0 )
            ProcessPacket(buffer, data_size, 5);

      }
      close(sock_raw);
      printf("Finished");
      flags = 0;      // 플래그 초기화
      fflush(stdout);
      while (1) {
         printf("1.HTTP   2.HTTPS   3.DNS   4.ICMP   5.ALL   6.Capture   7.Quit\n");
         printf("Enter the number you would like to sniff : ");
         scanf("%d", &num);
         if (num <= 5 && num > 0) {
            print_view(num);
            continue;
         }
         else if (num == 6 || num == 7) break;
         printf("Wrong number!\n");
      }
      if (num == 7) break;
   }
   fclose(fp);
   return 0;
}

void handler(int signo) {
   printf("\n 패킷 캡쳐 종료\n");
   psignal(signo, "Received Signal");
   flags = 1;
}

void print_view(int num) {
   printf("Num\tSource\t\t\t Destination\t\t Protocol\t Length\t\t Info\n");
   int i,id = 0;
   //filtering  all
   switch (num) {
   case 1:   //http
      for (i = 0; i < count; i++) {
         if (packet[i].protocol == 6)
		 if (ntohs(packet[i].tcph->dest) == 80 || ntohs(packet[i].tcph->source) == 80)
			simply_print(packet[i].buffer, packet[i].size, packet[i].index);
      }
      break;
   case 2:   //https
      for (i = 0; i < count; i++) {
    	if (packet[i].protocol == 6)
		 if (ntohs(packet[i].tcph->dest) == 443 || ntohs(packet[i].tcph->source) == 443)
			simply_print(packet[i].buffer, packet[i].size, packet[i].index);
      }
      break;
   case 3:   //dns
      for (i = 0; i < count; i++) {
         if (packet[i].protocol == 6) {
            if (ntohs(packet[i].tcph->dest) == 53 || ntohs(packet[i].tcph->source) == 53)
               simply_print(packet[i].buffer, packet[i].size,packet[i].index );
         }
         else if (packet[i].protocol == 17) {
            if (ntohs(packet[i].udph->dest) == 53 || ntohs(packet[i].udph->source) == 53)
               simply_print(packet[i].buffer, packet[i].size,packet[i].index );
         }
      }
      break;
   case 4:   //icmp
      for (i = 0; i < count; i++) {
         if (packet[i].protocol == 1) {
            simply_print(packet[i].buffer, packet[i].size, i);
         }
      }
      break;
   case 5:   //all
      for (i = 0; i < count; i++) {
         if (packet[i].protocol == 6) {
	     //https
 	     if (ntohs(packet[i].tcph->dest) == 80 || ntohs(packet[i].tcph->source) == 80)
			simply_print(packet[i].buffer, packet[i].size,packet[i].index );
	     //https
	     else if (ntohs(packet[i].tcph->dest) == 443 || ntohs(packet[i].tcph->source) == 443)
			simply_print(packet[i].buffer, packet[i].size, packet[i].index);
	    //dns
            else if (ntohs(packet[i].tcph->dest) == 53 || ntohs(packet[i].tcph->source) == 53)
               simply_print(packet[i].buffer, packet[i].size,packet[i].index );
         }
         else if (packet[i].protocol == 17) {
	    //dns
            if (ntohs(packet[i].udph->dest) == 53 || ntohs(packet[i].udph->source) == 53)
               simply_print(packet[i].buffer, packet[i].size, packet[i].index);
         }
         else if (packet[i].protocol == 1) {
            simply_print(packet[i].buffer, packet[i].size, packet[i].index);
         }
      }
      break;

   default:
      break;
   }
   while (id != -2) {
      printf("\nSelect packet for detail view \n(-1: all -2: Quit)\n-> ");
      scanf("%d", &id);


      if (id > count || id < -1) {
         printf("This number is invalid! \n");
         continue;
      }
       __fpurge(stdin);
      if (id == -2) return;
      else if (id == -1) {
         switch (num) {
         case 1:   //http
  	      for (i = 0; i < count; i++) {
		if(packet[i].protocol == 6)
		 if (ntohs(packet[i].tcph->dest) == 80 || ntohs(packet[i].tcph->source) == 80){
		    print_http(packet[i].buffer, packet[i].size);
		}
	    }
            break;

         case 2:   //https
            for (i = 0; i < count; i++) {
		if(packet[i].protocol == 6)
		 if (ntohs(packet[i].tcph->dest) == 443 || ntohs(packet[i].tcph->source) == 443){
		    print_https(packet[i].buffer, packet[i].size);
		}
	    }
            break;

         case 3:   //DNS
            for (i = 0; i < count; i++) {
               if (packet[i].protocol == 6) {
                  if (ntohs(packet[i].tcph->dest) == 53 || ntohs(packet[i].tcph->source) == 53)
                     print_dns(packet[i].buffer, packet[i].size);
               }
               else if (packet[i].protocol == 17) {
                  if (ntohs(packet[i].udph->dest) == 53 || ntohs(packet[i].udph->source) == 53)
                     print_dns(packet[i].buffer, packet[i].size);
               }
            }
            printf("=======================================end \n");
            break;

         case 4:   //ICMP
            for (i = 0; i < count + 1; i++) {
               if (packet[i].protocol == 1)
                  print_icmp_packet(packet[i].buffer, packet[i].size);
            }
            printf("=======================================end \n");
            break;

         case 5:   //all
            for (i = 0; i < count + 1; i++) {
               //http
		 if (ntohs(packet[i].tcph->dest) == 80 || ntohs(packet[i].tcph->source) == 80)
		    print_http(packet[i].buffer, packet[i].size);
               //https
		 else if (ntohs(packet[i].tcph->dest) == 443 || ntohs(packet[i].tcph->source) == 443)
		    print_https(packet[i].buffer, packet[i].size);
	       //dns	
                 else if (packet[i].protocol == 6) {
                  if (ntohs(packet[i].tcph->dest) == 53 || ntohs(packet[i].tcph->source) == 53)
                     print_dns(packet[i].buffer, packet[i].size);
               }
               else if (packet[i].protocol == 17) {
                  if (ntohs(packet[i].udph->dest) == 53 || ntohs(packet[i].udph->source) == 53)
                     print_dns(packet[i].buffer, packet[i].size);
               }
               else if (packet[i].protocol == 1)
                  print_icmp_packet(packet[i].buffer, packet[i].size);

            }
            break;

         default:
            break;
         }
      }
      else {
         switch (num) {
         case 1:   //http
		if(packet[id].protocol == 6)
    	    if (ntohs(packet[id].tcph->dest) == 80 || ntohs(packet[id].tcph->source) == 80)
	    	print_http(packet[id].buffer, packet[id].size);
            break;

         case 2:   //https
		if(packet[id].protocol == 6)
	    if (ntohs(packet[id].tcph->dest) == 443 || ntohs(packet[id].tcph->source) == 443)
	    	print_https(packet[id].buffer, packet[id].size);
            break;
         case 3:   //DNS
               if (packet[id].protocol == 6) {
                  if (ntohs(packet[id].tcph->dest) == 53 || ntohs(packet[id].tcph->source) == 53)
                     print_dns(packet[id].buffer, packet[id].size);
               }
               else if (packet[id].protocol == 17) {
                  if (ntohs(packet[id].udph->dest) == 53 || ntohs(packet[id].udph->source) == 53)
                     print_dns(packet[id].buffer, packet[id].size);
               }
            break;

         case 4:   //ICMP
               if (packet[id].protocol == 1)
                  print_icmp_packet(packet[id].buffer, packet[id].size);
               break;

         case 5:   //all
               if (packet[id].protocol == 6) {
               //http
	    	    if (ntohs(packet[i].tcph->dest) == 80 || ntohs(packet[i].tcph->source) == 80)
		    	print_http(packet[i].buffer, packet[i].size);
		//https
	    	    else if (ntohs(packet[i].tcph->dest) == 443 || ntohs(packet[i].tcph->source) == 443)
		    	print_https(packet[i].buffer, packet[i].size);
                  else if (ntohs(packet[id].tcph->dest) == 53 || ntohs(packet[id].tcph->source) == 53)
                     print_dns(packet[id].buffer, packet[id].size);
               }
               else if (packet[id].protocol == 17) {
                  if (ntohs(packet[id].udph->dest) == 53 || ntohs(packet[id].udph->source) == 53)
                     print_dns(packet[id].buffer, packet[id].size);
               }
               else if (packet[id].protocol == 1)
                  print_icmp_packet(packet[id].buffer, packet[id].size);            
            break;

         default:
            break;
         }
      }
   }
   
   return;
}


void ProcessPacket(unsigned char* buffer, int size, int num)
{
   //Get the IP Header part of this packet, excluding the ethernet header
   struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
   struct tcphdr* tcph;
   struct udphdr* udph;
   struct icmphdr* icmph;
   unsigned short iphdrlen = iph->ihl * 4;
   unsigned int protocol = iph->protocol;
   int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
   unsigned char* data = buffer + header_size;
   char tran_id[2][10];
   int i;

   if (protocol != NULL && flags!=1) {
      packet[count].index = count+1;//배열은 0부터 시작하지만 인덱스는 1부터 시작
      packet[count].protocol = protocol;
      packet[count].size = size;
      packet[count].buffer = buffer;

      if (protocol == 6) {
         tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
         header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
         packet[count].tcph = tcph;
      }
      else if (protocol == 17) {
         udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
         packet[count].udph = udph;
      }
      else if (protocol == 1) {
         icmph = (struct icmphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
         packet[count].icmph = icmph;
      }

      gettimeofday( &packet[count].getTime, NULL);




      switch (num) {
      case 1:
         //filtering HTTP   
         //if (ntohs(tcph->dest) == 80 || ntohs(tcph->source) == 80)
         //   print_http(buffer, size);
         break;
      case 2:
         //filtering HTTPS
         break;
      case 3:
         printf("====================================strat count:%d \n", count);
         for (i = 0; i < count; i++)
         {
            //filtering DNS
            if (packet[i].protocol == 6) {
               if (ntohs(packet[i].tcph->dest) == 53 || ntohs(packet[i].tcph->source) == 53)
                  print_dns(packet[i].buffer, packet[i].size);
            }
            else if (packet[i].protocol == 17) {
               if (ntohs(packet[i].udph->dest) == 53 || ntohs(packet[i].udph->source) == 53)
                  print_dns(packet[i].buffer, packet[i].size);
            }

         };

         printf("=======================================exit \n");
         break;

      case 4:
         //filtering ICMP
         for (i = 0; i < count; i++) {
            if (packet[i].protocol == 1)
               print_icmp_packet(packet[i].buffer, packet[i].size);
         }
         printf("=======================================exit \n");
         break;

      case 5:
         if (check == 0)
            printf("Num\tSource\t\t\t Destination\t\t Protocol\t Length\t\t Info\n");
         check = 1;

         //filtering  all

         if (protocol == 6) {
	    if (ntohs(tcph->dest) == 80 || ntohs(tcph->source) == 80){
	            simply_print(buffer, size,packet[count].index);
                    fprintf(fp,"%d\t",packet[count].index);
                    fprintf(fp,"%-3d\t",80);
                    fprintf(fp,"%02d.%02d\n",packet[count].getTime.tv_sec,packet[count].getTime.tv_usec);
                    count++;

	    }
	    else if (ntohs(tcph->dest) == 443 || ntohs(tcph->source) == 443){
	            simply_print(buffer, size,packet[count].index );
                    fprintf(fp,"%d\t",packet[count].index);
                    fprintf(fp,"%-3d\t",443);
                    fprintf(fp,"%02d.%02d\n",packet[count].getTime.tv_sec,packet[count].getTime.tv_usec);
                    count++;

	    }

            else if (ntohs(tcph->dest) == 53 || ntohs(tcph->source) == 53){
       		        simply_print(buffer, size, packet[count].index);
			fprintf(fp,"%d\t",packet[count].index);
 			fprintf(fp,"%-3d\t",53);
                        fprintf(fp,"0x%02x%02x\t",data[0],data[1]);
		        fprintf(fp,"%02d.%02d\n",packet[count].getTime.tv_sec,packet[count].getTime.tv_usec);
			count++;
	    }	
         }
         else if (protocol == 17) {
            if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53){
               simply_print(buffer, size,packet[count].index);
                fprintf(fp,"%d\t",packet[count].index);
                fprintf(fp,"%-3d\t",53);
                fprintf(fp,"0x%02x%02x\t",data[0],data[1]);
                fprintf(fp,"%02d.%02d\n",packet[count].getTime.tv_sec,packet[count].getTime.tv_usec);
                count++;
       

            }		
         }
         else if (protocol == 1) {
            simply_print(buffer, size,packet[count].index);
            fprintf(fp,"%d\t",packet[count].index);
            fprintf(fp,"%-3d\t",1);
            fprintf(fp,"0x%02x%02x\t",data[0],data[1]);
            fprintf(fp,"%02d.%02d\n",packet[count].getTime.tv_sec,packet[count].getTime.tv_usec);
            count++;
       
         }

         break;

      }
   }
}

void print_icmp_packet(unsigned char* Buffer, int Size) {
   unsigned short iphdrlen;

   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   iphdrlen = iph->ihl * 4;
   struct icmphdr* icmph = (struct icmphdr*)(Buffer + iphdrlen);

   printf("\n\n***********************ICMP Packet*************************\n");

   print_ip_header(Buffer, Size);

   printf("\n");
   printf("ICMP Header\n");


   printf("    Type : %d", (unsigned int)(icmph->type));
   if ((unsigned int)(icmph->type) == 11)
      printf("  (TTL Expired)\n");
   else if ((unsigned int)(icmph->type) == 0)
      printf("  (ICMP Echo Reply)\n");
   printf("    Code : %d\n", (unsigned int)(icmph->code));
   printf("    Checksum : %d\n", ntohs(icmph->checksum));
   printf("\n");
   printf("IP Header\n");
   printdata(Buffer, iphdrlen);
   printf("ICMP Header\n");
   printdata(Buffer + iphdrlen, sizeof(icmph));

   printf("Data Payload\n");

   printdata(Buffer + iphdrlen + sizeof(icmph), (Size - sizeof(icmph) - iph->ihl * 4));

   printf("\n\n********************************************************************************\n");
}


void simply_print(unsigned char* Buffer, int size, int num) {
   char* info; unsigned short iphdrlen;
   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   iphdrlen = iph->ihl * 4;
   struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
   struct udphdr* udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
   struct icmphdr* icmph = (struct icmphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
   int protocol;

   memset(&source, 0, sizeof(source));
   source.sin_addr.s_addr = iph->saddr;

   memset(&dest, 0, sizeof(dest));
   dest.sin_addr.s_addr = iph->daddr;

   if (iph->protocol == 6) {
      if (ntohs(tcph->source) == 53 || ntohs(tcph->source) == 80
		|| ntohs(tcph->source) == 443) {//Response
         protocol = ntohs(tcph->source);
         info = "Respeonse.";
      }
      else if (ntohs(tcph->dest) == 53 || ntohs(tcph->dest) == 80
		|| ntohs(tcph->dest) == 443) {//Request
         protocol = ntohs(tcph->dest);
         info = "Request.";
      }
   }
   else if (iph->protocol == 17) {
      if (ntohs(udph->source) == 53) {//Response
         protocol = ntohs(udph->source);
         info = "Respeonse.";
      }
      else if (ntohs(udph->dest) == 53) {//Request
         protocol = ntohs(udph->dest);
         info = "Request.";
      }
   }
   else if (iph->protocol == 1) {
      protocol = iph->protocol;
      if ((unsigned int)(icmph->type) == 11)
         info = "TTL Expired.";
      else if ((unsigned int)(icmph->type) == 8)
         info = "ICMP Echo.";
      else if ((unsigned int)(icmph->type) == 0)
         info = "ICMP Echo Reply.";
   }

   //printf("%d\t%-20s\t %-20s\t %-10d\t %-10d\t %s\t \n", num
   //   , inet_ntoa(source.sin_addr)
   //   , inet_ntoa(dest.sin_addr)
   //   , protocol, ntohs(iph->tot_len), info);
   printf("%d\t", num);
   printf("%s\t\t", inet_ntoa(source.sin_addr));
   printf("%s\t\t", inet_ntoa(dest.sin_addr));
   printf(" %d\t\t %-10d\t %s\n", protocol, ntohs(iph->tot_len), info);
}

void print_ethernet_header(unsigned char* Buffer, int Size) {
   struct ethhdr* eth = (struct ethhdr*)Buffer;
   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   int i;
   char padding[100];

   printf("\n");
   printf("Ethernet Header\n");
   printf("    Destination: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
   printf("    Source: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
   printf("    Type: ");
   if ((unsigned short)eth->h_proto == 8)
      printf("IPv4 (0x0800)\n");
   else
      printf("%u\n", (unsigned short)eth->h_proto);
   if (Size == 60 && sizeof(struct ethhdr) + ntohs(iph->tot_len) < 60) {
      for (i = 0; i < 2 * (Size - sizeof(struct ethhdr) - ntohs(iph->tot_len)); i++)
         padding[i] = '0';
      padding[i] = '\0';
      printf("    Padding: %s\n", padding);
   }

}

void print_ip_header(unsigned char* Buffer, int Size) {
   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   int frag;
   char frag_hex[2][2];

   unsigned char* data = Buffer + sizeof(struct ethhdr);

   sprintf(frag_hex[0], "%02x", data[6]);
   sprintf(frag_hex[1], "%02x", data[7]);
   frag = tran_hex(frag_hex);

   memset(&source, 0, sizeof(source));
   source.sin_addr.s_addr = iph->saddr;

   memset(&dest, 0, sizeof(dest));
   dest.sin_addr.s_addr = iph->daddr;

   print_ethernet_header(Buffer, Size);

   printf("\n");
   printf("IP Header\n");
   printf("    Version: %d\n", (unsigned int)iph->version);
   printf("    Header Length: %d bytes\n", ((unsigned int)(iph->ihl)) * 4);
   printf("    Differentiated Services Field: 0x%02x\n", (unsigned int)iph->tos);
   printf("    Total Length: %d bytes\n", ntohs(iph->tot_len));
   printf("    Identification: 0x%04x (%d)\n", ntohs(iph->id), ntohs(iph->id));
   print_ip_flags_frag(frag);
   printf("    Time to live: %d\n", (unsigned int)iph->ttl);
   printf("    Protocol: ");
   if ((unsigned int)iph->protocol == 6)
      printf("TCP (6)\n");
   else if ((unsigned int)iph->protocol == 17)
      printf("UDP (17)\n");
   printf("    Header checksum: 0x%04x\n", ntohs(iph->check));
   printf("    Source: %s\n", inet_ntoa(source.sin_addr));
   printf("    Destination: %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size) {
   unsigned short iphdrlen;

   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   iphdrlen = iph->ihl * 4;

   struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

   int flags = (unsigned int)tcph->th_flags;

   printf("\n\n********************************************************************************\n");

   print_ip_header(Buffer, Size);

   printf("\n");
   printf("Transmission Control Protocol\n");
   printf("    Source Port: %u\n", ntohs(tcph->source));
   printf("    Destination Port: %u\n", ntohs(tcph->dest));
   printf("    Sequence Number: %u\n", ntohl(tcph->seq));
   printf("    Acknowledge Number: %u\n", ntohl(tcph->ack_seq));
   printf("    Header Length: %d bytes\n", (unsigned int)tcph->doff * 4);
   printf("    Flag: 0x%03x\n", (unsigned int)tcph->th_flags);
   print_tcp_flags(flags);
   printf("    Window size value: %d\n", ntohs(tcph->window));
   printf("    Checksum: 0x%04x\n", ntohs(tcph->check));
   printf("    Urgent pointer: %d\n", tcph->urg_ptr);
   printf("\n");
}

void print_http(unsigned char* Buffer, int Size) {
   int i, j, http_len = 0;
   printf("\n\n************************************http*******************************************\n");
   print_tcp_packet(Buffer, Size);

   int data_len = 0;
   int etherlen = sizeof(struct ethhdr);
   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   unsigned short iphdrlen = iph->ihl * 4;

   struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

   int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

   unsigned char* data = Buffer + header_size;
   char temp[3][10], iden[3][10];
   int method;

   for (j = 0; j < 4; j++) {
      sprintf(temp[j], "%c", data[0 + j]);
      sprintf(iden[j], "%s", temp[j]);
   }

   method = iden_http(iden);

   if (method == 1) {
      printf("Hypertext Transfer Protocol\n");
      printf("    ");
      for (i = 0; i < Size - header_size; i++) {
         for (j = 0; j < 4; j++)
            sprintf(temp[j], "%02x", data[i + j]);

         printf("%c", data[i]);

         if (strcmp(temp[0], "0a") == 0)
            printf("    ");

         if (strcmp(temp[0], "0d") == 0 && strcmp(temp[1], "0a") == 0 && strcmp(temp[2], "0d") == 0 && strcmp(temp[3], "0a") == 0) {
            printf("\n");
            i += 4;
            http_len += 4;
            break;
         }
         http_len++;
      }
      data_len = Size - header_size - i;
   }


   if (data_len != 0)
      printf("    File Data: %d bytes\n", data_len);

   printf("\nEthernet Header\n");
   printdata(Buffer, etherlen);

   printf("IP Header\n");
   printdata(Buffer + etherlen, iphdrlen);

   printf("TCP Header\n");
   printdata(Buffer + iphdrlen + etherlen, tcph->doff * 4);

   if (http_len > 0) {
      if (Size == 60 && iphdrlen + tcph->doff * 4 == ntohs(iph->tot_len))
         printf("\n");
      else if (Size == 60) {
         printf("HTTP Header\n");
         printdata(Buffer + header_size, http_len);
         if (data_len > 0) {
            printf("HTTP Payload\n");
            printdata(Buffer + header_size + http_len, ntohs(iph->tot_len) - iphdrlen - tcph->doff * 4 - http_len);
         }
      }
      else {
         printf("HTTP Header\n");
         printdata(Buffer + header_size, http_len);
         if (data_len > 0) {
            printf("HTTP Payload\n");
            printdata(Buffer + header_size + http_len, data_len);
         }
      }
   }
   printf("\n\n********************************************************************************\n");
}
void print_https(unsigned char* Buffer, int Size) {
   int i, j, http_len = 0;
   printf("\n\n************************************https*******************************************\n");
   print_tcp_packet(Buffer, Size);

   int data_len = 0;
   int etherlen = sizeof(struct ethhdr);
   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   unsigned short iphdrlen = iph->ihl * 4;

   struct tcphdr* tcph = (struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

   int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

   unsigned char* data = Buffer + header_size;
   char temp[4][10], iden[4][10];
   int method;

      printf("HTTPS\n");
      printf("    ");
      for (i = 0; i < Size - header_size; i++) {
         for (j = 0; j < 4; j++)
            sprintf(temp[j], "%02x", data[i + j]);

         printf("%c", data[i]);

         if (strcmp(temp[0], "0a") == 0)
            printf("    ");

         if (strcmp(temp[0], "0d") == 0 && strcmp(temp[1], "0a") == 0 && strcmp(temp[2], "0d") == 0 && strcmp(temp[3], "0a") == 0) {
            printf("\n");
            i += 4;
            http_len += 4;
            break;
         }
         http_len++;
      }
      data_len = Size - header_size - i;

   if (data_len != 0)
      printf("    File Data: %d bytes\n", data_len);

   printf("\nEthernet Header\n");
   printdata(Buffer, etherlen);

   printf("IP Header\n");
   printdata(Buffer + etherlen, iphdrlen);

   printf("TCP Header\n");
   printdata(Buffer + iphdrlen + etherlen, tcph->doff * 4);

   if (http_len > 0) {
      if (Size == 60 && iphdrlen + tcph->doff * 4 == ntohs(iph->tot_len))
         printf("\n");
      else if (Size == 60) {
         printf("HTTPS Header\n");
         printdata(Buffer + header_size, http_len);
         if (data_len > 0) {
            printf("HTTPS Payload\n");
            printdata(Buffer + header_size + http_len, ntohs(iph->tot_len) - iphdrlen - tcph->doff * 4 - http_len);
         }
      }
      else {
         printf("HTTPS Header\n");
         printdata(Buffer + header_size, http_len);
         if (data_len > 0) {
            printf("HTTPS Payload\n");
            printdata(Buffer + header_size + http_len, data_len);
         }
      }
   }
   printf("\n\n********************************************************************************\n");
}

int iden_http(char temp[3][10]) {
   int ok = 0;
   if (strcmp(temp[0], "G") == 0 && strcmp(temp[1], "E") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], " ") == 0)
      ok = 1;
   else if (strcmp(temp[0], "H") == 0 && strcmp(temp[1], "T") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], "P") == 0)
      ok = 1;
   else if (strcmp(temp[0], "P") == 0 && strcmp(temp[1], "O") == 0 && strcmp(temp[2], "S") == 0 && strcmp(temp[3], "T") == 0)
      ok = 1;
   else if (strcmp(temp[0], "P") == 0 && strcmp(temp[1], "U") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], " ") == 0)
      ok = 1;
   else if (strcmp(temp[0], "D") == 0 && strcmp(temp[1], "E") == 0 && strcmp(temp[2], "L") == 0 && strcmp(temp[3], "E") == 0 && strcmp(temp[4], "T") == 0 && strcmp(temp[5], "E") == 0 && strcmp(temp[6], "E") == 0)
      ok = 1;
   else if (strcmp(temp[0], "C") == 0 && strcmp(temp[1], "O") == 0 && strcmp(temp[2], "N") == 0 && strcmp(temp[3], "N") == 0 && strcmp(temp[4], "E") == 0 && strcmp(temp[5], "C") == 0 && strcmp(temp[6], "T") == 0)
      ok = 1;
   else if (strcmp(temp[0], "O") == 0 && strcmp(temp[1], "P") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], "I") == 0 && strcmp(temp[4], "O") == 0 && strcmp(temp[5], "N") == 0)
      ok = 1;
   else if (strcmp(temp[0], "T") == 0 && strcmp(temp[1], "R") == 0 && strcmp(temp[2], "A") == 0 && strcmp(temp[3], "C") == 0 && strcmp(temp[4], "E") == 0)
      ok = 1;
   else if (strcmp(temp[0], "P") == 0 && strcmp(temp[1], "A") == 0 && strcmp(temp[2], "T") == 0 && strcmp(temp[3], "C") == 0 && strcmp(temp[4], "H") == 0)
      ok = 1;

   return ok;
}

char domain_name[1000];
char name[1000];
char name_data[1000];
int first;

void print_dns(unsigned char* Buffer, int Size) {
   int i, j, k, l, payload_len = 0, dns_header;
   unsigned short iphdrlen;
   int etherlen = sizeof(struct ethhdr);
   char tran_id[2][10], flags[2][10];
   int ques, ans_rrs, auth_rrs, add_rrs, quer_type, res_type, res_class, data_len, quer_class;
   char data_len_hex[2][2], ques_hex[2][2], ans_rrs_hex[2][2], auth_rrs_hex[2][2], add_rrs_hex[2][2], res_type_hex[2][2], quer_type_hex[2][2];
   char temp[4];
   char* bin;


   struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
   iphdrlen = iph->ihl * 4;

   struct udphdr* udph = (struct udphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

   int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

   unsigned char* data = Buffer + header_size;

   printf("\n\n************************************dns*******************************************\n");

   print_ip_header(Buffer, Size);

   printf("\nUser Datagram Protocol\n");
   printf("    Source Port: %d\n", ntohs(udph->source));
   printf("    Destination Port: %d\n", ntohs(udph->dest));
   printf("    Length: %d\n", ntohs(udph->len));
   printf("    Checksum: %d\n", ntohs(udph->check));


   sprintf(tran_id[0], "%02x", data[0]);
   sprintf(tran_id[1], "%02x", data[1]);

   sprintf(flags[0], "%02x", data[2]);
   sprintf(flags[1], "%02x", data[3]);

   sprintf(ques_hex[0], "%02x", data[4]);
   sprintf(ques_hex[1], "%02x", data[5]);
   ques = tran_hex(ques_hex);

   sprintf(ans_rrs_hex[0], "%02x", data[6]);
   sprintf(ans_rrs_hex[1], "%02x", data[7]);
   ans_rrs = tran_hex(ans_rrs_hex);

   sprintf(auth_rrs_hex[0], "%02x", data[8]);
   sprintf(auth_rrs_hex[1], "%02x", data[9]);
   auth_rrs = tran_hex(auth_rrs_hex);

   sprintf(add_rrs_hex[0], "%02x", data[10]);
   sprintf(add_rrs_hex[1], "%02x", data[11]);
   add_rrs = tran_hex(add_rrs_hex);

   printf("\nDomain Name System");
   if (ntohs(udph->source) == 53)//Response
      printf(" (response)\n");
   else if (ntohs(udph->dest) == 53)//Request
      printf(" (query)\n");
   printf("    Transaction ID: 0x%s%s\n", tran_id[0], tran_id[1]);
   printf("    Flags: 0x%s%s\n", flags[0], flags[1]);

   if (ntohs(udph->source) == 53)//Response
      print_dns_response_flags(flags[0], flags[1]);
   else if (ntohs(udph->dest) == 53)//Request
      print_dns_request_flags(flags[0], flags[1]);

   printf("    Questions: %d\n", ques);
   printf("    Answer RRs: %d\n", ans_rrs);
   printf("    Authority RRS: %d\n", auth_rrs);
   printf("    Additional RRs: %d\n", add_rrs);
   printf("    Queries\n");

   k = 12;
   dns_header = 12;

   for (i = 0; i < strlen(domain_name); i++)
      domain_name[i] = '\0';

   for (i = 0; i < ques; i++) {
      printf("      ");
      l = 0;
      for (j = k + 1; j < 100000; j++) {

         //sprintf(end[j - 12], "%02x", data[j]);

         //if(strcmp(end[i - 12], "00") == 0)
         //   break;
         k++;
         if (data[j] >= 33 && data[j] <= 127) {
            domain_name[l] = data[j];
            l++;
         }
         else if (data[j] == 0) {
            domain_name[l] = '\0';
            break;
         }
         else {
            domain_name[l] = '.';
            l++;
         }
      }

      sprintf(quer_type_hex[0], "%02x", data[j + 1]);
      sprintf(quer_type_hex[1], "%02x", data[j + 2]);
      quer_type = tran_hex(quer_type_hex);

      sprintf(temp, "%02x%02x", data[j + 3], data[j + 4]);
      quer_class = strtol(temp, &bin, 16) /

         printf("%s:", domain_name);

      if (quer_type == 1)
         printf(" type %c,", 'A');
      else if (quer_type == 2)
         printf(" type %s,", "NS");
      else if (quer_type == 5)
         printf(" type %s,", "CNAME");
      else if (quer_type == 6)
         printf(" type %s,", "SOA");
      else if (quer_type == 28)
         printf(" type %s,", "AAAA");
      else
         printf(" type %d,", quer_type);

      if (quer_class == 1)
         printf(" class %s\n", "IN");
      else if (quer_class == 2)
         printf(" class %s\n", "Unassigned");
      else if (quer_class == 3)
         printf(" class %s\n", "CH");
      else if (quer_class == 4)
         printf(" class %s\n", "HS");
      else
         printf(" type 0x%04x\n", quer_class);

      k += 5;
   }

   first = 1;
   if (ans_rrs != 0)
      printf("    Answers\n");

   strcpy(name, domain_name);

   for (i = 0; i < ans_rrs; i++) {
      k += 2;
      sprintf(res_type_hex[0], "%02x", data[k]);
      sprintf(res_type_hex[1], "%02x", data[k + 1]);
      res_type = tran_hex(res_type_hex);

      sprintf(temp, "%02x%02x", data[k + 2], data[k + 3]);
      res_class = strtol(temp, &bin, 16);

      sprintf(data_len_hex[0], "%02x", data[k + 8]);
      sprintf(data_len_hex[1], "%02x", data[k + 9]);
      data_len = tran_hex(data_len_hex);

      ans_data(res_type, data_len, k + 10, data, domain_name, res_type, res_class);
      first = 0;

      printf("\n");
      k += 10 + data_len;
   }

   if (auth_rrs != 0)
      printf("    Authoritative nameservers\n");

   for (i = 0; i < auth_rrs; i++) {
      k += 2;
      sprintf(res_type_hex[0], "%02x", data[k]);
      sprintf(res_type_hex[1], "%02x", data[k + 1]);
      res_type = tran_hex(res_type_hex);
      //sprintf(temp, "%02x%02x", data[k], data[k+1]);
      //res_type = strtol(temp, &bin, 16);

      sprintf(temp, "%02x%02x", data[k + 2], data[k + 3]);
      res_class = strtol(temp, &bin, 16);

      sprintf(data_len_hex[0], "%02x", data[k + 8]);
      sprintf(data_len_hex[1], "%02x", data[k + 9]);
      data_len = tran_hex(data_len_hex);

      ans_data(res_type, data_len, k + 10, data, domain_name, res_type, res_class);

      printf("\n");
      k += 10 + data_len;
   }

   if (add_rrs != 0)
      printf("    Additional records\n");

   for (i = 0; i < add_rrs; i++) {
      k += 2;
      sprintf(res_type_hex[0], "%02x", data[k]);
      sprintf(res_type_hex[1], "%02x", data[k + 1]);
      res_type = tran_hex(res_type_hex);
      //sprintf(temp, "%02x%02x", data[k], data[k+1]);
      //res_type = strtol(temp, &bin, 16);

      sprintf(temp, "%02x%02x", data[k + 2], data[k + 3]);
      res_class = strtol(temp, &bin, 16);

      sprintf(data_len_hex[0], "%02x", data[k + 8]);
      sprintf(data_len_hex[1], "%02x", data[k + 9]);
      data_len = tran_hex(data_len_hex);

      ans_data(res_type, data_len, k + 10, data, domain_name, res_type, res_class);

      printf("\n");
      k += 10 + data_len;
   }

   payload_len = k;

   printf("\nEthernet Header\n");
   printdata(Buffer, etherlen);

   printf("IP Header\n");
   printdata(Buffer + etherlen, iphdrlen);

   printf("UDP Header\n");
   printdata(Buffer + iphdrlen + etherlen, sizeof(udph));

   if (payload_len > 0) {
      if (Size == 60 && iphdrlen + sizeof(udph) == ntohs(iph->tot_len))
         printf("\n");
      else if (Size == 60) {
         printf("DNS Header\n");
         printdata(Buffer + header_size, dns_header);
         printf("DNS Payload\n");
         printdata(Buffer + header_size + dns_header, ntohs(iph->tot_len) - iphdrlen - sizeof(udph) - dns_header);
      }
      else {
         printf("DNS Header\n");
         printdata(Buffer + header_size, dns_header);
         printf("DNS Payload\n");
         printdata(Buffer + header_size + dns_header, ntohs(iph->tot_len) - iphdrlen - sizeof(udph) - dns_header);
      }
   }
   printf("\n\n********************************************************************************\n");
}

//Print Data Dump
void printdata(unsigned char* data, int Size)
{
   int i, j;

   for (i = 0; i < Size; i++)
   {
      if (i != 0 && i % 16 == 0)   //if one line of hex printing is complete...
      {
         printf("         ");
         for (j = i - 16; j < i; j++)
         {
            if (data[j] >= 33 && data[j] <= 127)
               printf("%c", (unsigned char)data[j]); //if its a number or alphabet

            else printf("."); //otherwise print a dot
         }
         printf("\n");
      }

      if (i % 16 == 0) printf("   ");
      printf(" %02x", (unsigned int)data[i]);

      if (i == Size - 1)  //print the last spaces
      {
         for (j = 0; j < 15 - i % 16; j++)
         {
            printf("   "); //extra spaces
         }

         printf("         ");

         for (j = i - i % 16; j <= i; j++)
         {
            if (data[j] >= 33 && data[j] <= 127)
            {
               printf("%c", (unsigned char)data[j]);
            }
            else
            {
               printf(".");
            }
         }

         printf("\n");
      }
   }
}

//Print TCP Header flags
void print_tcp_flags(int flags) {
   int non, con, ecn, urg, ack, pus, res, syn, fin;
   int n, i;
   int bin[14];
   n = sizeof(bin) / sizeof(int);
   for (i = n - 1; i >= 0; i--) {
      if (i == 4 || i == 9) {
         bin[i] = 2;
         continue;
      }
      bin[i] = flags % 2;
      flags /= 2;
   }

   printf("      ");
   for (i = 0; i < 3; i++)
      printf("%d", bin[i]);

   print_right_dot(i, bin, n);
   printf(" = Reserved: Not set\n");

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   non = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Nonce: ");
   print_set(non);
   i++;

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   con = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Congest Window Reduced (CWR): ");
   print_set(con);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   ecn = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = ECN-Echo: ");
   print_set(ecn);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   urg = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Urgent: ");
   print_set(urg);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   ack = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Acknowledgment: ");
   print_set(ack);
   i++;

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   pus = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Push: ");
   print_set(pus);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   res = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Reset: ");
   print_set(res);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   syn = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Syn: ");
   print_set(syn);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   fin = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Fin: ");
   print_set(fin);
}


void print_set(int check) {
   if (check == 1)
      printf("Set\n");
   else if (check == 0)
      printf("Not set\n");
}

//Print IP Header flags
void print_ip_flags_frag(int frag) {
   int dont, more, flag, offset = 0;
   int n, i, j, square;
   int bin[17];
   int temp[16];
   int remain;

   remain = frag;
   n = sizeof(bin) / sizeof(int);
   for (i = n - 1; i >= 0; i--) {
      if (i == 4) {
         bin[i] = 2;
         continue;
      }
      bin[i] = remain % 2;
      remain /= 2;
   }

   dont = bin[1];
   more = bin[2];

   if (dont == 1 && more == 1)
      flag = 3;
   else if (dont == 1 && more == 0)
      flag = 2;
   else if (dont == 0 && more == 1)
      flag = 1;
   else if (dont == 0 && more == 0)
      flag = 0;

   printf("    Flag: 0x0%d\n", flag);

   i = 0;
   printf("      ");
   printf("%d", bin[0]);
   i++;
   print_right_dot(i, bin, 9);
   printf(" = Reserved bit: Not set\n");//Reserved bit is always "Not set"

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[1]);
   i++;
   print_right_dot(i, bin, 9);
   printf(" = Don't fragment: ");
   print_set(dont);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[2]);
   i++;
   print_right_dot(i, bin, 9);
   printf(" = More fragment: ");
   print_set(more);

   remain = frag;
   n = sizeof(temp) / sizeof(int);
   for (i = n - 1; i >= 0; i--) {
      temp[i] = remain % 2;
      remain /= 2;
   }

   for (i = 3; i < 16; i++) {
      square = 1;
      for (j = i; j < 12; j++)
         square *= 2;
      offset += temp[i] * square;
   }

   printf("    Fragment offset: %d\n", offset);
}

//Printf DNS Request flags
void print_dns_request_flags(char flags1[], char flags2[]) {
   int res, opc[4], trun, red, non;
   char* temp1;
   int temp2 = strtol(flags1, &temp1, 16);
   int bin[19];
   int i, j;
   int n = sizeof(bin) / sizeof(int);

   for (i = 8; i >= 0; i--) {
      if (i == 4) {
         bin[i] = 2;
         continue;
      }
      bin[i] = temp2 % 2;
      temp2 /= 2;
   }
   temp2 = strtol(flags2, &temp1, 16);

   for (i = 18; i >= 9; i--) {
      if (i == 14 || i == 9) {
         bin[i] = 2;
         continue;
      }
      bin[i] = temp2 % 2;
      temp2 /= 2;
   }
   i = 0;
   printf("      ");
   printf("%d", bin[i]);
   res = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Response: Message is a ");
   check_res(res);

   printf("      ");
   print_left_dot(i, bin);
   for (j = i; j < 6; j++) {
      if (bin[j] == 2) {
         printf(" ");
         i++;
         continue;
      }
      printf("%d", bin[j]);
      opc[j] = bin[j];
      i++;
   }
   print_right_dot(i, bin, n);
   printf(" = Opcode: ");
   check_opc(opc);

   printf("      ");
   i++;
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   trun = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Truncated: Message is ");
   check_trun(trun);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   red = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Recursion desired: ");
   check_red(red);

   printf("      ");
   i += 2;
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   i++;
   print_right_dot(i, bin, n);
   printf(" = Z: reserved (0)\n");//Z is always "reserved"

   printf("      ");
   i++;
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   non = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Non-authenticated data: ");
   check_non(non);
}

//Printf DNS Response flags
void print_dns_response_flags(char flags1[], char flags2[]) {
   int res, opc[4], auth, trun, red, rea, ans, non, rec[4];
   char* temp1;
   int temp2 = strtol(flags1, &temp1, 16);
   int bin[19];
   int i, j, l = 0;
   int n = sizeof(bin) / sizeof(int);

   for (i = 8; i >= 0; i--) {
      if (i == 4) {
         bin[i] = 2;
         continue;
      }
      bin[i] = temp2 % 2;
      temp2 /= 2;
   }

   temp2 = strtol(flags2, &temp1, 16);

   for (i = 18; i >= 9; i--) {
      if (i == 14 || i == 9) {
         bin[i] = 2;
         continue;
      }
      bin[i] = temp2 % 2;
      temp2 /= 2;
   }
   i = 0;
   printf("      ");
   printf("%d", bin[i]);
   res = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Response: Message is a ");
   check_res(res);

   printf("      ");
   print_left_dot(i, bin);
   for (j = i; j < 6; j++) {
      if (bin[j] == 2) {
         printf(" ");
         i++;
         continue;
      }
      printf("%d", bin[j]);
      opc[l] = bin[j];
      l++;
      i++;
   }
   print_right_dot(i, bin, n);
   printf(" = Opcode: ");
   check_opc(opc);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   auth = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Authoritative: Server is ");
   check_auth(auth);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   trun = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Truncated: Message is ");
   check_trun(trun);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   red = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Recursion desired: ");
   check_red(red);

   printf("      ");
   i++;
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   rea = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Recursion available: Server can ");
   check_rea(rea);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   i++;
   print_right_dot(i, bin, n);
   printf(" = Z: reserved\n");

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   ans = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Answer authenticated: Answer/authority portion was ");
   check_ans(ans);

   printf("      ");
   print_left_dot(i, bin);
   printf("%d", bin[i]);
   non = bin[i];
   i++;
   print_right_dot(i, bin, n);
   printf(" = Non-authenticated data: ");
   check_non(non);

   printf("      ");
   i++;
   print_left_dot(i, bin);
   l = 0;
   for (j = i; j < 19; j++) {
      printf("%d", bin[j]);
      rec[l] = bin[j];
      l++;
      i++;
   }
   print_right_dot(i, bin, n);
   printf(" = Reply code: ");
   check_rec(rec);

}

//Check DNS flags
void check_res(int check) {
   if (check == 1)
      printf("response\n");
   else if (check == 0)
      printf("query\n");
}

void check_opc(int check[]) {
   if (check[1] == 1)
      printf("Inverse (4)\n");
   else if (check[2] == 1)
      printf("Not used (2)\n");
   else if (check[3] == 1)
      printf("Not used (1)\n");
   else if (check[0] == 0 && check[1] == 0 && check[2] == 0 && check[3] == 0)
      printf("Standard query (0)\n");
}

void check_auth(int check) {
   if (check == 1)
      printf("an authority for domain\n");
   else if (check == 0)
      printf("not an authority for domain\n");
}

void check_trun(int check) {
   if (check == 1)
      printf("truncated\n");
   else if (check == 0)
      printf("not truncated\n");
}

void check_red(int check) {
   if (check == 1)
      printf("Do query recursively\n");
   else if (check == 0)
      printf("Do not query recursively\n");
}

void check_rea(int check) {
   if (check == 1)
      printf("do recursive queries\n");
   else if (check == 0)
      printf("do not recursive queries\n");
}

void check_ans(int check) {
   if (check == 1)
      printf("authenticated by the server\n");
   else if (check == 0)
      printf("not authenticated by the server\n");
}

void check_non(int check) {
   if (check == 1)
      printf("Acceptable\n");
   else if (check == 0)
      printf("Unacceptable\n");
}

void check_rec(int check[]) {
   int rec = 0;
   rec = 8 * check[0] + 4 * check[1] + 2 * check[2] + 1 * check[3];
   switch (rec) {
   case 0:
      printf("No error (0)\n");
      break;
   case 1:
      printf("Format error (1)\n");
      break;
   case 2:
      printf("Server failure (2)\n");
      break;
   case 3:
      printf("Name Error (3)\n");
      break;
   case 4:
      printf("Not Implemented (4)\n");
      break;
   case 5:
      printf("Refused (5)\n");
      break;
   case 6:
      printf("YXDomain (6)\n");
      break;
   case 7:
      printf("YXRRSet (7)\n");
      break;
   case 8:
      printf("NXRRSet (8)\n");
      break;
   case 9:
      printf("NotAuth (9)\n");
      break;
   case 10:
      printf("NotZone (10)\n");
      break;
   default:
      printf("BAD (16-22)\n");
   }
}

//print dot
void print_right_dot(int i, int bin[], int max) {
   int j;
   for (j = i; j < max; j++) {
      if (bin[j] == 2) {
         printf(" ");
         continue;
      }
      printf(".");
   }
}

//print dot
void print_left_dot(int i, int bin[]) {
   int j;
   for (j = 0; j < i; j++) {
      if (bin[j] == 2) {
         printf(" ");
         continue;
      }
      printf(".");
   }
}

//Trans hex to dec
int tran_hex(char hex[2][2]) {
   char temp;
   int bin, result = 0;
   int i, j, k;

   for (i = 0; i < 4; i++) {
      k = 1;
      temp = hex[0][i];
      switch (temp) {
      case '0':
         bin = 0; break;
      case '1':
         bin = 1; break;
      case '2':
         bin = 2; break;
      case '3':
         bin = 3; break;
      case '4':
         bin = 4; break;
      case '5':
         bin = 5; break;
      case '6':
         bin = 6; break;
      case '7':
         bin = 7; break;
      case '8':
         bin = 8; break;
      case '9':
         bin = 9; break;
      case 'a':
         bin = 10; break;
      case 'b':
         bin = 11; break;
      case 'c':
         bin = 12; break;
      case 'd':
         bin = 13; break;
      case 'e':
         bin = 14; break;
      case 'f':
         bin = 15; break;
      defalut:
         printf("hex error"); break;
      }
      for (j = i; j < 3; j++)
         k *= 16;
      result += bin * k;
   }
   return result;
}

//DNS Response data
void ans_data(int type, int data_len, int k, unsigned char* data, char domain_name[1000], int res_type, int res_class) {
   int i, l;
   l = 0;
   char data_type[10];
   int* aa_name_data = malloc(1000);

   if (first == 0) {
      sprintf(&name[0], "%02x", data[k - 12]);
      sprintf(&name[2], "%02x", data[k - 11]);
   }
   switch (type) {
   case 2: {//NS
      strcpy(data_type, " ns ");
      for (i = k; i < k + data_len; i++) {
         aa_name_data[l] = data[i];
         l++;
      }
      break;
   }
   case 5: {//CNAME
      strcpy(data_type, " cname ");
      for (i = k; i < k + data_len; i++) {
         aa_name_data[l] = data[i];
         l++;
      }
      break;
   }
   case 6: {//SOA
      strcpy(data_type, " mname ");
      for (i = k + 1; i < k + data_len; i++) {
         if (data[i - 1] == 0 || data[i - 2] == 192)
            break;
         else {
            for (i = k; i < k + data_len; i++) {
               aa_name_data[l] = data[i];
               l++;
            }
         }
      }
      break;
   }
   default:
      break;
   }

   printf("      ");
   printf("%s:", name);

   if (res_type == 1)
      printf(" type %c,", 'A');
   else if (res_type == 2)
      printf(" type %s,", "NS");
   else if (res_type == 5)
      printf(" type %s,", "CNAME");
   else if (res_type == 6)
      printf(" type %s,", "SOA");
   else if (res_type == 28)
      printf(" type %s,", "AAAA");
   else
      printf(" type %d,", res_type);

   if (res_class == 1)
      printf(" class %s,", "IN");
   else if (res_class == 2)
      printf(" class %s,", "Unassigned");
   else if (res_class == 3)
      printf(" class %s,", "CH");
   else if (res_class == 4)
      printf(" class %s,", "HS");
   else
      printf(" type 0x%04x,", res_class);

   if (type == 1 || type == 28) {//A
      if (type == 1) {
         printf(" addr ");
         for (i = k; i < k + data_len; i++) {
            printf("%d", data[i]);
            if (i == k + data_len - 1)
               break;
            else
               printf(".");
         }
      }
      else if (type == 28) {//AAAA
         printf(" addr ");
         for (i = k; i < k + data_len; i += 2) {
            if (data[i] == 0 && data[i + 1] == 0) {
               l += 1;
               continue;
            }
            else if (data[i] == 0 && data[i + 1] != 0) {
               if (l >= 2) {
                  printf(":");
                  l = 0;
               }
               printf("%x", data[i + 1]);
               if (i == k + data_len - 2)
                  break;
               else
                  printf(":");
               continue;
            }
            if (l >= 2) {
               printf(":");
               l = 0;
            }
            printf("%x", data[i]);
            printf("%02x", data[i + 1]);
            if (i == k + data_len - 2)
               break;
            else
               printf(":");
         }
      }
   }
   else {
      printf("%s", data_type);
      for (i = 0; i < sizeof(aa_name_data); i++)
         printf("%02x", aa_name_data[i]);
   }
}

