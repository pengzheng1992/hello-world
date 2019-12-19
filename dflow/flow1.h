#include <stdio.h>
//#include <tchar.h>
#ifndef __FLOW1_H__
#define __FLOW1_H__
#include <stdint.h>
//#include "hls_math.h"
//#include "ap_int.h"

using namespace std;

#define N 524288//262144
#define d 4

static const int DFlow_SHADOW_SIZE1 = 16;


////#pragma pack(4)
//typedef struct
//{
//	ap_uint<32> id;
//	ap_uint<32> len;
//} pkt_idsz_in_file;
////#pragma pack(pop) BY PZ

typedef struct
{
	uint32_t id;
	uint32_t len;
} pkt_idsz_in_file;

//typedef struct s_flow
//{
///*	uint32_t sip;
//	uint32_t dip;
//	uint16_t sport;
//	uint16_t dport;
//	uint16_t protocol;*/
//	ap_uint<32> sip;
//	ap_uint<32> dip;
//	ap_uint<16> sport;
//	ap_uint<16> dport;
//	ap_uint<8> protocol;
//
//	//	bool operator < (const s_flow& n) const;
//	//	bool operator == (const s_flow& n) const;
//} s_flow; BY PZ

typedef struct s_flow
{
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint8_t protocol;
} s_flow;

/*typedef struct node
{
	s_flow flowtuple;
//	int hashaddrnext;
} Renode;*/

typedef struct
{
	uint32_t id;
	uint32_t len;
} pkt_idsz;


typedef struct counter
{
	uint32_t flow_volume;			// pkt number
	uint32_t flow_size;				// bytes
//	int hashaddrnext;

} s_counter_element;

//typedef struct hash_result
//{
//	ap_int<5> count;
//	bool result;
//}hash_search_result; by PZ

typedef struct hash_result
{
	uint8_t count;
	bool result;
} hash_search_result;


uint32_t myhash(s_flow &flow_tuple, int seed);
uint32_t myhash1(s_flow &flow_tuple, int seed);
uint32_t myhash2(s_flow &flow_tuple, int seed);
uint32_t myhash3(s_flow &flow_tuple, int seed);
uint32_t disco_Add(uint32_t flowCounter, uint32_t packetSize);
uint32_t disco_Add_volume(uint32_t flowCounter, uint32_t packetSize);
int HashInsert(s_flow HashTable[d][N], int HashaddrIndex[d][N], s_counter_element HashTableCounter[d][N], s_flow &flowtuple, uint32_t packetsize); // ,s_flow dflow_shadow_id[DFlow_SHADOW_SIZE1],s_counter_element dflow_shadow_array[DFlow_SHADOW_SIZE1]);
void init(s_flow HashTable[d][N], int HashaddrIndex[d][N], s_counter_element HashTableCounter[d][N]); // s_flow dflow_shadow_id[DFlow_SHADOW_SIZE1],s_counter_element dflow_shadow_array[DFlow_SHADOW_SIZE1]);
// void init();
int ShadowSearch(s_flow &flowtuple, uint32_t packetsize, s_flow dflow_shadow_id_out[DFlow_SHADOW_SIZE1], s_counter_element dflow_shadow_array_out[DFlow_SHADOW_SIZE1]);
void dflow_measurement_result(uint32_t pkt_num);
// void HashInsert(Renode *HashTable[N], s_flow &flowtuple);
#endif
