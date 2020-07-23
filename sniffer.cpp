/* sniffing related */
#include <stdint.h>
#include <cstdint>
#include <vector>
#include <stddef.h>
#include "header/ieee80211_modified.h"  // utilities of IEEE80211
#include "header/radiotap.h"
#include "header/win_linux.h"
#include <pcap.h>   // sniffing library
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <string.h>
#include <iostream>
#include <fstream> //for writing data to file
#include <ctime>    //get system time
#include <chrono>   //get system time
/* socket related */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>  // byte order switch functions
#include <sys/ioctl.h>

using namespace std;

#define PROTECTED_LEN 8
#define RBUF_LEN 64    //socket receive buffer length
#define SBUF_LEN 8192   //socket send buffer length

int sockfd;
char receive_buffer[RBUF_LEN];
char send_buffer[SBUF_LEN];
char *fname;    // file to which to write packet
pcap_dumper_t *dump_handle;
pcap_t *handle;
int socket_bytes;
bool set_filter;   // true - only capture EV and EVSE data, false - capture all data
//u8 EV_addr[ETH_ALEN] = {0xb8, 0x27, 0xeb, 0x68, 0xe5, 0xeb};
//u8 EVSE_addr[ETH_ALEN] = {0xb8, 0x27, 0xeb, 0x47, 0x19, 0x12};
u8 EV_addr[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
u8 EVSE_addr[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

void print_content(const u_char *begin, int length) {
    //general function to print content specified by the start pointer and length in octets{
    if(length <= 0)
        return;
    auto p = begin;
    for (int cnt = 1; cnt <= length; cnt++){
        printf("%02hhx ", *(u8*)(p + cnt - 1));
        if( cnt % 8 == 0 && cnt != length){
            if ( cnt % 32 == 0)
                printf("\n");
            else
                printf("  ");
        }
    }
    return;
}

static bool addr_equal(u8 addr[ETH_ALEN], u8 pattern[ETH_ALEN]){
    for(int i = 0; i < ETH_ALEN; i++){
        if( addr[i] != pattern[i] )
            return false;
    }
    return true;
}


int is_from_EV_EVSE(const u_char *ieee80211_frame, int frame_length){
    /* NOTE check the vendor element at first, if is found, buffer the source address and return a value;
     * if frame has no vendor element, check if the source address correspond with the buffered address and return a value;
     * return value: 0 - not found, 1 - found SECC OUI, 2 - found EVCC OUI, 3 - frame without OUI, but address corresponds the buffered address*/
    
    /* NOTE to buffer address in MAC header refer to IEEE80211 8.3.3.1 */
    /* if OUI is found ,the frame must be a management frame */
    /* The SA in data frame depends on the ToDS and FromDS bit, The fourth address field is only used by wireless bridges, and is therefore relatively uncommon.
     *  * ToDS    FromDS  A1(RA)  A2(TA)  A3      A4      Use
     * -----------------------------------------------------------------
     *  0       0       DA      SA      BSSID   -       IBSS/DLS
     *  0       1       DA      BSSID   SA      -       AP -> STA
     *  1       0       BSSID   SA      DA      -       AP <- STA
     *  1       1       RA      TA      DA      SA      unspecified (WDS)
     */
    /* the address 3 of the management frame ist the BSSID or SA, in case 1 and 2 SA = BSSID */
    /*the buffer function ist not gauranteed to be reliable*/
    
    struct ieee80211_hdr *machdr = (struct ieee80211_hdr*)ieee80211_frame;
    const static u_char organizationID[] = {0xdd, 0x00, 0x70, 0xb3, 0xd5, 0x31, 0x90};
    for (int i = 0; i < frame_length; i++){
        if ( *(u_char*)(ieee80211_frame + i) == 0xdd){
            if ( (*(u_char*)(ieee80211_frame + i + 2) == organizationID[2])
                && (*(u_char*)(ieee80211_frame + i + 3) == organizationID[3])
                && (*(u_char*)(ieee80211_frame + i + 4) == organizationID[4])
                && (*(u_char*)(ieee80211_frame + i + 5) == organizationID[5])
                && (*(u_char*)(ieee80211_frame + i + 6) == organizationID[6]))
            {                
                if ( *(u_char*)(ieee80211_frame + i + 7) == 0x01 ){
                    // frame is from EVSE; The EVSE working as AP, thus the BSSID is its MAC address, a management frame is only in case 1 and 2 transmitted by AP, and in case 2 the SA = BSSID, so it's enough, buffer the 3rd address field from the probe response or association response
                    //static bool toDS = ieee80211_has_tods(machdr->frame_control);
                    //static bool fromDS = ieee80211_has_fromds(machdr->frame_control);
                    //if (!toDS && !fromDS)
                        bcopy(machdr->addr3, EVSE_addr, ETH_ALEN);
                    //else if (!toDS && fromDS)
                        //bcopy(machdr->addr2, EVSE_addr, ETH_ALEN);
                    return 1;
                }
                else if ( *(u_char*)(ieee80211_frame + i + 7) == 0x02 ){
                    // frame is from EV, EV is in case 1 and 3 the SA
                    // probe request / association request / reassociation request
                    bcopy(machdr->addr2, EV_addr, ETH_ALEN);
                    return 2;
                }
            }
        }
    }
    /* NOTE check whether SECC or EVCC MAC address is present in frame */
    
    if( addr_equal(machdr->addr1, EV_addr) ||
        addr_equal(machdr->addr2, EV_addr) ||
        addr_equal(machdr->addr3, EV_addr) ||
        addr_equal(machdr->addr4, EV_addr) ||
        addr_equal(machdr->addr1, EVSE_addr) ||
        addr_equal(machdr->addr2, EVSE_addr) ||
        addr_equal(machdr->addr3, EVSE_addr) ||
        addr_equal(machdr->addr4, EVSE_addr)
    ){
        return 3;
    }
    return 0;
}

u8 mac_header_length(const u_char *ieee80211_frame){
    int len = 0;
    static __le16 *fc;
    fc = (__le16*)ieee80211_frame;
    /*************************************************************************************************************************************************
     * NOTE
     * management frame format: |Frame control|Duration|Address 1|Address 2|Address 3|Sequence Control|HT Control|Frame Body|FCS|
     * 
     * The Frame Control, Duration, Address 1, Address 2, Address 3, and Sequence Control fields are present in all management frame subtypes.
     * 
     * The presence of the HT Control field is determined by the Order subfield of the Frame Control field
     * 
     * Address 4 is included only in the Mesh Control Field
     * ***********************************************************************************************************************************************/
    if(ieee80211_is_mgmt(*fc)){
        len = 24;
        if( ieee80211_has_order(*fc) )
            len += IEEE80211_HT_CTL_LEN;
        if( ieee80211_has_protected(*fc) )
            len += PROTECTED_LEN;        
    }
    /**************************************************************************************************************************************************
     * NOTE
     * case control frame
     **************************************************************************************************************************************************/
    else if(ieee80211_is_ctl(*fc)){    
        if(ieee80211_is_rts(*fc))   // Request-to-send - |Frame Control|Duration|RA|TA|FCS|
            len = 16;
        else if(ieee80211_is_cts(*fc))   // Clear-to-send - |Frame Control|Duration|RA|FCS|
            len = 10;
        else if(ieee80211_is_ack(*fc))   // Acknowledge - |Frame Control|Duration|RA|FCS|
            len = 10;
        else if(ieee80211_is_pspoll(*fc))   // PS-Poll frame - |Frame Control|AID|BSSID|TA|FCS|
            len = 16;
        else if(ieee80211_is_cfend(*fc))   // CF-End frame - |Frame Control|Duration|RA|BSSID|FCS|
            len = 16;
        else if(ieee80211_is_cfendack(*fc)) //CF-End + CF-Ack frame - |Frame Control|Duration|RA|BSSID|FCS|
            len = 16;
        else if(ieee80211_is_back(*fc)) // Block Ack frame
            len = 16;
        else if(ieee80211_is_back_req(*fc))   // Block Ack Req frame
            len = 16;
        else    // control wrapper frame
            len = 16;
    }
    /* ****************************************************************************************************************************************************
     * NOTE
     * data frame format - |Frame Control|Duration/ID|Address 1|Address 2|Address 3|Sequence Control|Address 4|QoS Control|HT Control|Frame Body|FCS|
     * The Frame Control, Duration/ID, Address 1, Address 2, Address 3, and Sequence Control fields are present in all data frame subtypes
     * 
     * The presence of the Address 4 field is determined by the setting of the To DS and From DS subfields of the Frame Control field
     * 
     * In data frames, the most significant bit (MSB) of the Subtype field, b7, is defined as the QoS subfield, the QoS Control field is present when the QoS subfield of the Subtype field is set to 1.
     * 
     * The Protected Frame field is set to 1 only within data frames and within management frames of subtype Authentication, indicates a CCMP or TKIP field following the MAC Header in 8
     * octets length
     * 
     * The presence of the HT Control field is determined by the Order subfield of the Frame Control field, it is set to 1 in a QoS data transmitted with a value of HT_GF or HT_MF for the FORMAT parameter of the TXVECTOR to indicate that the frame contains an HT Control field.
     * ****************************************************************************************************************************************************/
    else{
        len = 24;   // die basic length
        if( ieee80211_has_a4(*fc) )
            len += ETH_ALEN;
        if( ieee80211_is_data_qos(*fc) ) {
            len += IEEE80211_QOS_CTL_LEN;
            if( ieee80211_has_order(*fc) )
                len += IEEE80211_HT_CTL_LEN;
        }
        if( ieee80211_has_protected(*fc) )
            len += PROTECTED_LEN;

    }
    return (u8)len;
}

int process_one_host_msg(int socket){
    /* return value: 0 - error parsing the host response, 1 - data ack, 2 - send all data, 3 - send EV/EVSE data, 4 - stop request, 5 - Exit request, 6 - Host error receiving */
    static int count = 0;
    static u8 ftype;
    static u8 flag;
    static u16 length;
    int timer = 0;
    bzero(receive_buffer, RBUF_LEN);
    
    do{
        ioctl(socket, FIONREAD, &count);
        usleep(100000);
        timer++;
        //if( !(timer%50) )
            //printf("waiting for response\n");
    }while(count < 4);
    recv(socket, receive_buffer, 4, MSG_PEEK);  // peek the first 4 byte but not remove them from socket
    ftype = (u8)receive_buffer[0];
    flag = (u8)receive_buffer[1];
    length = (u16)receive_buffer[2];
    length <<= 8;
    length |= (u8)receive_buffer[3];
    if(length > 0){
        do{
            ioctl(socket, FIONREAD, &count);
            usleep(100000);
            timer++;
            if( !(timer%50) )
                printf("waiting for complete frame\n");
        }while(count < (4 + length));
        read(socket, receive_buffer, 4 + length);
    }
    else
        read(socket, receive_buffer, 4);
    /* determine frame type */
    if(ftype == STYPE_CONTROL_DATA_ACK) {return CMD_DATA_ACK;}
    else if(ftype == STYPE_CONTROL_SEND_REQ) {
        if (flag & 0x01)
            return CMD_SEND_REQ_ALL;   // bit 0 of flag is 1, thus request all frame;
        else
            return CMD_SEND_REQ_EV_EVSE;   // bit 0 of flag is 0, request only EV/EVSE frame;
    }
    else if(ftype == STYPE_CONTROL_STOP_REQ)    {return CMD_STOP_REQ;}
    else if(ftype == STYPE_CONTROL_EXIT)    {return CMD_EXIT_REQ;}
    else if(ftype == STYPE_CONTROL_ERROR)   {return CMD_ERROR_TX;}
    return CMD_ERROR;
}

void packet_handler(u_char* user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 0;   // number of captured packets
    count++;
    
    static struct ieee80211_radiotap_header *rt_hdr;
    rt_hdr = (struct ieee80211_radiotap_header *)packet;
    static  __le16 *fc;
    fc = (__le16*)(packet + rt_hdr->it_len);
    /* field of a frame to be sent */
    // windows - linux protocol header

    static u8 ftype;
    static u8 flag;
    static u16 len_total;
    // length field
    static u16 len_radiotap_hdr;
    static u8 len_MAC_hdr;
    static u16 len_frame_body;

    
    /* set value of individual fields */
    ftype = FTYPE_DATA;
    flag = 0x00;
    len_total = (u16)(pkthdr->caplen);
    len_radiotap_hdr = rt_hdr->it_len;
    len_MAC_hdr = mac_header_length(packet + rt_hdr->it_len);
    len_frame_body = (u16)(len_total - len_radiotap_hdr - len_MAC_hdr - 4);
    
    /* valid the OUI or address*/
    struct ieee80211_hdr *machdr = (struct ieee80211_hdr*)(packet + rt_hdr->it_len);
    static int host_resp;
    int from_EV_EVSE = is_from_EV_EVSE(packet + rt_hdr->it_len, pkthdr->caplen - rt_hdr->it_len);
    
    if( from_EV_EVSE > 0 ){
        write(sockfd, &ftype, 1);
        write(sockfd, &flag, 1);
        write(sockfd, &len_total, 2);
        write(sockfd, &len_radiotap_hdr, 2);
        write(sockfd, &len_MAC_hdr, 1);
        write(sockfd, &len_frame_body, 2);
        write(sockfd, pkthdr, 16);
        write(sockfd, packet, pkthdr->caplen);
        
        /* display the frame */
        printf("--------------------------------\npacket %d\tlength %d\t flag %d\n", count, pkthdr->caplen, from_EV_EVSE);
        print_content(packet, pkthdr->caplen);
        
        /* check address fields */
        printf("\nMAC addr 1 - 3:\n");
        print_content(machdr->addr1, ETH_ALEN); printf("\t");
        print_content(machdr->addr2, ETH_ALEN); printf("\t");
        print_content(machdr->addr3, ETH_ALEN); printf("\n");
        printf("Buffer Address:\n");
        printf("EV : "); print_content(EV_addr,ETH_ALEN);
        printf("EVSE : ");print_content(EVSE_addr,ETH_ALEN); printf("\n");
        
        /* check for response  */
        host_resp = process_one_host_msg(sockfd);
        if ( host_resp == CMD_DATA_ACK ) {
            printf("host has received packet\n");
        }
        else if ( host_resp == CMD_ERROR_TX ) {
            printf("error sending packet\n");
        }
        else if ( host_resp == CMD_SEND_REQ_ALL ) { set_filter = false; }
        else if ( host_resp == CMD_SEND_REQ_EV_EVSE ) { set_filter = true; }
        else if ( host_resp == CMD_STOP_REQ ) { printf("host has received packet\n"); pcap_breakloop(handle); }
    }
    else{
        printf("--------------------------------\npacket %d\tlength %d not EV EVSE\n", count, pkthdr->caplen);
    }
    return;
}

int open_socket(struct sockaddr_in serv_addr, char *host_ip, int host_port) {
    /*******************/
    /*** open socket ***/
    /*******************/
    /* create new socket */
    printf("creating socket...");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("failed\n");
        return 1;
    }
    else
        printf("succeed\n");
    
    /* set the fields in serv_addr */
    bzero((char*)&serv_addr, sizeof(serv_addr));
    printf("setting server address...");
    serv_addr.sin_family = AF_INET;
    if(inet_pton(AF_INET, host_ip, &serv_addr.sin_addr) <= 0) { 
        printf("failed, invalid ip address\n"); 
        return 1; 
    }
    serv_addr.sin_port = htons(host_port);
    printf("succeed\n");
    
    /* connect to server */
    printf("connecting...");
    int conn = connect(sockfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr));
    if ( conn != 0) {
        printf("failed\n");
        return 1;
    }
    else
        printf("succeed\n");
    return 0;
}

int open_sniffer(char *dev, char *errbuf, bpf_u_int32 mask, bpf_u_int32 net) {
    /*************************/
    /*** open pcap sniffer ***/
    /*************************/
    printf("preparing sniffer...");
    /* ask pcap for the network address and mask of the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) != 0) {
        printf("Error looking up network: %s\n", errbuf);
        return 1;
    }
    /* create live capture handle */
    handle = pcap_create(dev, errbuf);
    if (handle == NULL) {
        printf("pcap_create error: %s\n",errbuf);
        return 2;
    }
    /* activate the device, and print the warning or error message if there is any */
    int act = pcap_activate(handle);
    if (act > 0)
        printf("pcap_activate warning: %s\n",pcap_statustostr(act));
    else if (act < 0)
    {
        printf("pcap_activate error: %s\n", pcap_statustostr(act));
        return 3;
    }
    printf("done\n");
    return 0;
}

int main(int argc, char* argv[]){
    if (argc < 5) {
        printf("Usage: %s [interface] [capture number] [host ip] [host port]\n", argv[0]);
        return 1;
    }
    //sniffer related variables
    char *dev;
    int capture_number;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    
    // socket related variables
    char *host_ip;
    int host_port;
    struct sockaddr_in serv_addr;

    // initialization
    dev = argv[1];
    capture_number = atoi(argv[2]);
    host_ip = argv[3];
    host_port = atoi(argv[4]);
    

    if ( open_socket(serv_addr, host_ip, host_port) )
        return 1;
    if ( open_sniffer(dev, errbuf, mask, net) )
        return 1; 
    
    /* send ready to send frame*/
    u32 rts = 0x00000000;
    write(sockfd, &rts, 4);
    
    /* get data link layer type */
    int datalink = pcap_datalink(handle);

    
    
    /**********************/
    /*** start sniffing ***/
    /**********************/
    /* send pcap global header */
    u8 glbhdr_type = 0x11;
    u8 glbhdr_flag = 0x00;
    u16 glbhdr_len = 0x0018;
    write(sockfd, &glbhdr_type, 1);
    write(sockfd, &glbhdr_flag, 1);
    write(sockfd, &glbhdr_len, 2);
    // global header contents
    u32 magic = htonl((u32)(0xa1b2c3d4));
    u16 version_major = htons(0x0002); 
    u16 version_minor = htons(0x0004); 
    u32 thiszone = htonl(0x00000000);
    u32 sigfigs = htonl(0x00000000);
    u32 snaplen = htonl(0x0000ffff);
    u32 linktype = htonl((u32)datalink);
    
    write(sockfd, &magic, 4);
    write(sockfd, &version_major, 2);
    write(sockfd, &version_minor, 2);
    write(sockfd, &thiszone, 4);
    write(sockfd, &sigfigs, 4);
    write(sockfd, &snaplen, 4);
    write(sockfd, &linktype, 4);
    int msg = process_one_host_msg(sockfd);
    if (msg == CMD_EXIT_REQ){
        printf("exit\n");
        pcap_close(handle);
        close(sockfd);
        return 0;
    }
    
    // loop to capture packets
    int host_msg;
    while(true){
        // wait for command when sniffing is not running
        printf("\nsniffer pending, waiting for host command...\n");
        host_msg = process_one_host_msg(sockfd);
        
        if ( host_msg == CMD_EXIT_REQ ) {
            printf("exit\n");
            pcap_close(handle);
            close(sockfd);
            break;
        }
        else if( host_msg == CMD_SEND_REQ_ALL ) {
            set_filter = false;
            pcap_loop(handle, capture_number, packet_handler, NULL);
        }
        else if( host_msg == CMD_SEND_REQ_EV_EVSE ) {
            set_filter = true;
            pcap_loop(handle, capture_number, packet_handler, NULL);
        }
        else if (host_msg == CMD_DATA_ACK){
            pcap_loop(handle, capture_number, packet_handler, NULL);
        }
    }
    
    return 0;
}
