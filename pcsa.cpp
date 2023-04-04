#include <iostream>
#include "pcsa.h"
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include "./lib/MurmurHash3.h"

using namespace std;
#define KEY_SIZE 16
struct Cmp {
	bool operator()(const string a, const string b) const {
		return a == b;
	}
};
struct HashFunc {
	unsigned int operator()(const string key) const {
		unsigned int hashValue = 0;
		MurmurHash3_x86_32(key.c_str(), KEY_SIZE, 0, &hashValue);
		return hashValue;
	}
};

void processPackets(PCSA& pcsa, vector<pair<string, string>>& dataset) {
	//int count = 0;
	clock_t start = clock();
	for (unsigned int i = 0; i < dataset.size(); i++) {
		pcsa.update(dataset[i].first, dataset[i].second);
	}
	clock_t current = clock();
	cout << dataset.size() << " lines: have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
	double throughput = (dataset.size() / 1000000.0) / (((double)current - start) / CLOCKS_PER_SEC);
	cout << "throughput: " << throughput << "Mpps" << endl;
}

void SaveAsText(PCSA& pcsa, unordered_map<string, unordered_set<string, HashFunc, Cmp>, HashFunc, Cmp>& realflows)
{
    uint64_t flow_id_integer;
    double estimate, real;
    string save_file_name = "pcsa_estimate.txt";
    ofstream fout(save_file_name, ios::ate);
    for (auto iter = realflows.begin(); iter != realflows.end(); iter++)
    {
        flow_id_integer = (uint64_t) pcsa.ip_to_int((*iter).first);
        estimate = pcsa.query(flow_id_integer);
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
    unordered_map<string, unordered_set<string, HashFunc, Cmp>, HashFunc, Cmp> realFlowInfo;
    string line, source_addr, destination_addr;
    char split = '.';
    uint32_t pysical_register_nums = 1000000;
    uint32_t virtual_register_nums = 16;
    string data_file_name = R"(./data/00.txt)";
    PCSA pcsa = PCSA(pysical_register_nums, virtual_register_nums);
    fstream fin(data_file_name, ios::in | ios::binary);
    vector<pair<string, string>> dataset;
    clock_t start = clock();
    cout << "starting..." << endl;
    while (fin.is_open() && fin.peek() != EOF)
    {
        getline(fin, line);
        while (line.find(":") != -1)
        {
            getline(fin, line);
        }
        stringstream ss(line.c_str());
        ss >> source_addr >> destination_addr;
        realFlowInfo[source_addr].insert(destination_addr);
        dataset.push_back(make_pair(source_addr, destination_addr));
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

    processPackets(pcsa, dataset);
    SaveAsText(pcsa, realFlowInfo);
    return 0;
}