#ifndef _PCSA_H
#define _PCSA_H

#include <iostream>
#include <cmath>
#include <ctime>
#include <set>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>

#include "./lib/MurmurHash3.h"
using namespace std;

class PCSA
{
private:
    uint32_t num_pysical_registers;
    uint32_t num_virtual_registers;
    uint32_t num_leading_bits;
    uint32_t hash_seed;
    uint32_t* seeds;
    uint32_t* registers;
    set<uint32_t> flows;
public:
    PCSA(uint32_t num_registers, uint32_t num_registers2);
    uint32_t ip_to_int(string ip_addr);
    void update(string flow_id, string ele_id);
    double query(uint64_t flow_id);
    ~PCSA();
};

PCSA::PCSA(uint32_t num_registers, uint32_t num_registers2)
{
    set<uint32_t> seed_set;
    hash_seed = uint32_t(rand());
    uint32_t count = 0;
    this->num_pysical_registers = num_registers;
    this->num_virtual_registers = num_registers2;
    srand(time(NULL));
    this->seeds = new uint32_t[num_virtual_registers];
    for (int i = 0; i < this->num_virtual_registers; i++)
    {
        seed_set.insert(uint32_t(rand()));
    }
    this->seeds = new uint32_t[num_virtual_registers];
    for (auto iter = seed_set.begin(); iter != seed_set.end(); iter++)
    {
        this->seeds[count] = *iter;
        count += 1;
    }
    num_leading_bits = floor(log10(double(num_virtual_registers)) / log10(2.0));
    registers = new uint32_t[num_pysical_registers];
    memset(registers, 0, sizeof(uint32_t) * num_pysical_registers);
}

uint32_t PCSA::ip_to_int(string ip_addr)
{
    vector<string> segments;
    string temp;
    char split = '.';
    stringstream ss(ip_addr);
    while (getline(ss, temp, split))
    {
        segments.push_back(temp);
    }
    uint32_t segment1 = atoi(segments[0].c_str()) << 24;
    uint32_t segment2 = atoi(segments[1].c_str()) << 16;
    uint32_t segment3 = atoi(segments[2].c_str()) << 8;
    uint32_t segment4 = atoi(segments[3].c_str());
    uint32_t res = segment1 + segment2 + segment3 + segment4;
    return res;
}

void PCSA::update(string flow_id, string ele_id)
{
    uint32_t flow_id_integer = this->ip_to_int(flow_id);
    uint32_t ele_id_integer = this->ip_to_int(ele_id);
    uint32_t ele_hash_val = 0;
    flows.insert(flow_id_integer);
    char hash_input_str[5] = {0};
    memcpy(hash_input_str, &ele_id_integer, sizeof(uint32_t));
    MurmurHash3_x86_32(hash_input_str, 4, hash_seed, &ele_hash_val);
    uint32_t pPart = ele_hash_val >> (sizeof(uint32_t) * 8 - num_leading_bits);
    uint32_t qPart = ele_hash_val - (pPart << (sizeof(uint32_t) * 8 - num_leading_bits));
    uint32_t leftmost = 0;
    while (qPart)
    {
        leftmost += 1;
        qPart = qPart >> 1;
    }
    leftmost = sizeof(uint32_t) * 8 - num_leading_bits - leftmost + 1;
    uint32_t xor_val = flow_id_integer ^ seeds[pPart];
    memcpy(hash_input_str, &xor_val, sizeof(uint32_t));
    uint32_t pysical_register_index = 0;
    MurmurHash3_x86_32(hash_input_str, 4, hash_seed, &pysical_register_index);
    pysical_register_index = pysical_register_index % num_pysical_registers;
    registers[pysical_register_index] = max(registers[pysical_register_index], leftmost);
}

double PCSA::query(uint64_t flow_id)
{
    double estimate;
    if(flows.count(flow_id))
    {
        double estimate_exp_part = 0.0;
        for (int i = 0; i < num_virtual_registers; i++)
        {
            uint32_t seed = seeds[i];
            char hash_input_str[5] = {0};
            uint32_t xor_val = uint32_t(flow_id) ^ seed;
            memcpy(hash_input_str, &xor_val, sizeof(uint32_t));
            uint32_t pysical_register_index = 0;
            MurmurHash3_x86_32(hash_input_str, 4, seed, &pysical_register_index);
            pysical_register_index = pysical_register_index % num_pysical_registers;
            estimate_exp_part += registers[pysical_register_index];
        }
        estimate = (1 / 0.77351) * pow(2, estimate_exp_part / num_virtual_registers);
    }else
    {
        estimate = 0.0;
    }
    return estimate;
}

PCSA::~PCSA()
{
    delete[] seeds;
}
#endif // _PCSA_H