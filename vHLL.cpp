#include <iostream>
#include "./lib/MurmurHash3.h"
#include <unordered_map>
#include <unordered_set>
#include "vHLL.h"
#include <fstream>
#include <cstring>
#include <sstream>
#include <vector>
#include <algorithm>
#include <string>
using namespace std;
#define KEY_SIZE 16
const int per_register_bits = 5;

struct Cmp {
	bool operator()(const uint64_t a, const uint64_t b) const {
		return a - b == 0;
	}
};
struct HashFunc {
	unsigned int operator()(const uint64_t key) const {
		unsigned int hashValue = 0;
		MurmurHash3_x86_128(&key, 64, 0, &hashValue);
		return hashValue;
	}
};

void processPackets(vHLL& vhll, vector<pair<string, string>>& dataset) {
	//int count = 0;
	clock_t start = clock();
	for (unsigned int i = 0; i < dataset.size(); i++) {
		vhll.update(dataset[i].first, dataset[i].second);
	}
	clock_t current = clock();
	cout << dataset.size() << " lines: have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
	double throughput = (dataset.size() / 1000000.0) / (((double)current - start) / CLOCKS_PER_SEC);
	cout << "throughput: " << throughput << "Mpps" << endl;
}

void SaveAsText(vHLL& vhll, unordered_map<uint64_t, unordered_set<uint64_t, HashFunc, Cmp>, HashFunc, Cmp>& realflows)
{
    double estimate, real;
    string save_file_name = "vhll_estimate.txt";
    ofstream fout(save_file_name, ios::ate);
    for (auto iter = realflows.begin(); iter != realflows.end(); iter++)
    {
        estimate = vhll.query(iter->first);
        real = 1.0 * (iter->second).size();
        fout << real << " " << estimate << endl;
    }
    if (!fout.is_open()) {
		cout << " closed unexpectedlly";
	}
	else {
		fout.close();
	}
}

int main()
{
	unordered_map<uint64_t, unordered_set<uint64_t, HashFunc, Cmp>, HashFunc, Cmp> realflows;
    char split = '.';
    vector<pair<string, string>> dataset;
    string source, destination, line;
    string data_file_name = R"(./data/00.txt)";
    const uint32_t memory_kb = 320;
    uint32_t pysical_registers = (uint32_t) memory_kb * 1024 * 8 * 32 / per_register_bits / 3;
    uint32_t virtual_registers = 32;
    vHLL vhll = vHLL(pysical_registers, virtual_registers);
    fstream fin(data_file_name, ios::in | ios::binary);
    clock_t start = clock();
    cout << "starting..." << endl;
    while (fin.is_open() && fin.peek() != EOF) {
        string temp;
        getline(fin, line);
		while (line.find(":") != -1)
        {
            getline(fin, line);
        }
		stringstream ss(line.c_str());
        ss >> source >> destination;
        dataset.push_back(make_pair(source, destination));
		uint64_t flow_id_integer = (uint64_t) vhll.ip_to_int(source);
		uint64_t ele_id_integer = (uint64_t) vhll.ip_to_int(destination);
		realflows[flow_id_integer].insert(ele_id_integer);
		//testing the spread of destination address
		if (dataset.size() % 5000000 == 0) {//output someting to check the procedure
			clock_t current = clock();
			cout << "have added " << dataset.size() << " packets, have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds." << endl;
		}
	}
	if (!fin.is_open()) {
		cout << "dataset file" << data_file_name << "closed unexpectedlly"<<endl;
		exit(-1);
	}
	else {
		fin.close();
	}
    processPackets(vhll, dataset);
	SaveAsText(vhll, realflows);
    return 0;
}