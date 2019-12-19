// dflow.c: main program

#include <stdio.h>
//#include <tchar.h>
#include <string.h>
#include "flow1.h"
#include "pcap.h"

//XXX BY PZ #define packet_size 1000
#define packet_size 1000000
// global data structure
//std::map<s_flow, uint32_t> trace_list;
//   std::list<pkt_idsz> id_size_list;
//std::map<s_flow, uint32_t> flow_id_map;
uint32_t g_trace_packet_number;
uint32_t g_trace_flow_number;
//std::map<s_flow, pkt_idsz> flow_map;
//std::list<s_flow> flow_tuple_list;
s_flow flow_tuple_list[packet_size + 10];
pkt_idsz id_size_list[packet_size + 10];
uint32_t flow_tuple_size;
//static Renode *hashtable_tuple[d][N];
//static s_counter_element *hashtable_counter[d][N];
static s_flow HashTable[d][N];
static int HashaddrIndex[d][N];
static s_counter_element HashTableCounter[d][N];
// by PZ static s_flow dflow_shadow_id[8];
// BY PZ static s_counter_element dflow_shadow_array[8];



void load_caida_file(const char* file_name)
{
	// long -> long long, by PZ.
	long long volume = 0;
	int print_cnt = 0;
	uint8_t tmp;
	//printf("INFO: Read file: %s\n", file_nameargv[1]);
	FILE * fp = fopen(file_name, "rb");
	if (!fp)
	{
		printf("ERROR: Error in open pcap file %s\n", file_name);
		return;
	}

	printf("INFO: Read pcap header ...\n");
	pcap_file_header pcap_info;
	readPcapFileHeader(fp, &pcap_info);
	prinfPcapFileHeader(&pcap_info);

	printf("INFO: Read packets ...\n");
	int total_pkts = 0;
	int total_flows = 0;
	s_flow pkt_info;
	pcap_header pkt_hdr;
	IPHeader pkt_ip;
	BasicL4Header pkt_l4;

	pkt_idsz current_pkt;
	while (!readPacketHeader(fp, &pkt_hdr) && total_pkts<packet_size)
	{
		// read pcap header
		//printfPcapHeader(&pkt_hdr);

		// read IP header
		//by PZ int read_size = 0;
		size_t read_size = 0;
		//by PZ. int read_bytes = pkt_hdr.capture_len;
		size_t read_bytes = pkt_hdr.capture_len;
		if (read_bytes >= sizeof(IPHeader))
		{
			read_size = fread(&pkt_ip, sizeof(IPHeader), 1, fp);
			if (read_size < 1)
			{
				pkt_ip.srcIP = 0;
				pkt_ip.dstIP = 0;
				printf("ERROR: Error in reading IP header, packet=%d.\n", total_pkts + 1);
				break;
			}
			else
			{
				read_bytes -= sizeof(IPHeader);
			}


			if (read_bytes >= sizeof(BasicL4Header))
			{
				// read L4 Header
				read_size = fread(&pkt_l4, sizeof(BasicL4Header), 1, fp);
				if (read_size < 1)
				{
					pkt_l4.srcPort = 0;
					pkt_l4.dstPort = 0;
					printf("ERROR: Error in reading L4 header, packet=%d.\n", total_pkts + 1);
					break;
				}
				else
				{
					read_bytes -= sizeof(BasicL4Header);
				}
			}
		}
		ipNumCovert(&(pkt_ip.srcIP));
		ipNumCovert(&(pkt_ip.dstIP));
		ipNumCovert(&(pkt_l4.srcPort));
		ipNumCovert(&(pkt_l4.dstPort));
		ipNumCovert(&(pkt_ip.protocol));

		//packet info
		pkt_info.sip = pkt_ip.srcIP;
		pkt_info.dip = pkt_ip.dstIP;
		pkt_info.dport = pkt_l4.dstPort;
		pkt_info.sport = pkt_l4.srcPort;
		pkt_info.protocol = pkt_ip.protocol;
		/*		std::map<s_flow, uint32_t>::iterator it = flow_id_map.find(pkt_info);
		//std::map<s_flow, s_counter_element>::iterator it = flow_map.find();
		//flow_map.
		if (it == flow_id_map.end())
		{
		//new flow arrival
		flow_id_map.insert(std::map<s_flow, uint32_t>::value_type(pkt_info, total_flows));
		current_pkt.id = total_flows;
		total_flows++;
		}
		else
		{
		current_pkt.id = it->second;
		}*/
		current_pkt.len = pkt_hdr.len;
		current_pkt.id = total_pkts;
		volume = volume + current_pkt.len;
		//flow_tuple_list.push_back(pkt_info);
		flow_tuple_list[total_pkts] = pkt_info;
		id_size_list[total_pkts] = current_pkt;
		//	id_size_list.push_back(current_pkt);



		total_pkts++;
		if ((pkt_hdr.len <= 0) || (pkt_hdr.len > 1600) || (pkt_hdr.capture_len <= 0) || (pkt_hdr.capture_len > pkt_hdr.len))
		{
			//error bytes, need resync
			printf("ERROR: Error capture len, packet number %d, capture_len %d,pkt_len %d\n", total_pkts, pkt_hdr.capture_len, pkt_hdr.len);
			printfPcapHeader(&pkt_hdr);
			break;
		}

		if (read_bytes>0)
		{
			for (size_t i = 0; i < read_bytes; i++)
				read_size = fread(&tmp, sizeof(uint8_t), 1, fp);
		}

		if ((total_pkts / 1000000) > print_cnt)
		{
			printf("INFO: %d packets, %d flows read.\n", total_pkts, total_flows);
			print_cnt++;
		}
	}

	printf("INFO: Total %d packets read, total %d flows found. \n", total_pkts, total_flows);
	printf("volume : %lld\n", volume);
	g_trace_packet_number = total_pkts;
	g_trace_flow_number = total_flows;

	fclose(fp);
}


int include_the_id(uint32_t* array, int length, uint32_t id) {
	int i = 0;
	for (i = 0; i < length; i++)
	{
		if (array[i] == id) return i;
	}
	return 20;
}

int main()
{

	//char * file_name = "equinix-chicago.dirA.20140918-132100.UTC.anon.pcap";
	//char * file_name = "equinix-chicago.dirA.20140918-132100.UTC.anon.pcapid_size_list.txt";
	//char * file_name = "equinix-chicago.dirA.20130919-132600.UTC.anon.pcap";
	//char * file_name = "equinix-sanjose.dirA.20130815-131400.UTC.anon.pcap";
	//char * file_name = "equinix-chicago.dirB.20080319-190700.UTC.anon.pcap";
	//char * file_name = "uni06";
	//char * file_name = "exp06";
	//char * file_name = "par06";
	//char * file_name = "gen_inc1";
	//char * file_name = "I:\\DFlowtest\\equinix-chicago.dirA.20150219-125911.UTC.anon.pcap"; BY PZ
	const char *file_name = "/home/pengzheng/pcap/equinix-chicago.dirA.20150219-125911.UTC.anon.pcap";


	memset(flow_tuple_list, 0, sizeof(s_flow) * (packet_size + 10));
	memset(id_size_list, 0, sizeof(pkt_idsz) * (packet_size + 10));
	// by PZ double dff;
	printf("TEST:: Loading Flow ...\n");

	load_caida_file(file_name);
	/* for (int i = 0; i < d; i++) {
		for (int j = 0; j < N; j++) {
			hashtable_tuple[i][j] = NULL;
			hashtable_counter[i][j] = NULL;
		}
	}*/
	init(HashTable,HashaddrIndex,HashTableCounter);

	printf("TEST: Start DFlow Counting ...  \n");
#if 1
	//	std::list<pkt_idsz>::iterator it_list = id_size_list.begin();
	//	for (std::list<s_flow>::iterator flow_list = flow_tuple_list.begin(); flow_list != flow_tuple_list.end() && it_list != id_size_list.end(); flow_list++)
	for (int i = 0; i<packet_size - 10; i++)
	{
		s_flow flow;
		flow.sip = flow_tuple_list[i].sip;//flow_list->sip;
		flow.dip = flow_tuple_list[i].dip;//flow_list->dip;
		flow.sport = flow_tuple_list[i].sport;//flow_list->sport;
		flow.dport = flow_tuple_list[i].dport;//flow_list->dport;
		flow.protocol = flow_tuple_list[i].protocol;//flow_list->protocol;
		HashInsert(HashTable,HashaddrIndex,HashTableCounter,flow, id_size_list[i].len);
		//it_list++;
	}
#else
	for (int i = 0; i < 1000000; i++)
		cacti.update(cacti.base, i, 1, 500);
#endif
	dflow_measurement_result(g_trace_packet_number);
	printf("list_size: %d\n", flow_tuple_size);

	printf("-end-\n");
	return 0;
}
