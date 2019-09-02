#include "topo.h"
#include <cstdio>
#include <cassert>
#include <iostream>
#include <fstream>

using namespace std;

const int &INF = 100000000;

ifstream& open_file(ifstream &in, const string &file) {
	in.close();
	in.clear();
	in.open(file.c_str());
	return in;
}

void floyd(vector<vector<int>> &adjacencyMatrix, vector<vector<int>> &nextHop) {
	const int &NODE = adjacencyMatrix.size();
	//nextHop.assign(NODE, vector<int>(NODE, -1));
	for (int k = 0; k != NODE; ++k)
		for (int i = 0; i != NODE; ++i)
			for (int j = 0; j != NODE; ++j)
				if (adjacencyMatrix[i][j] > adjacencyMatrix[i][k] + adjacencyMatrix[k][j]) {
					adjacencyMatrix[i][j] = adjacencyMatrix[i][k] + adjacencyMatrix[k][j];
					nextHop[i][j] = nextHop[i][k];
				}
}

//void print_path(vector<vector<int>> nextHop, int n_num) {
//	for (int i = 0; i < n_num; ++i) {
//		for (int j = 0;j < n_num; ++j) {
//			cout << nextHop[i][j] << " ";
//		}
//		cout << endl;
//	}
//}

void init_path(vector<vector<int>> &nextHop, int n_num) {
	for (int i = 0; i < n_num; ++i) {
		for (int j = 0; j < n_num; ++j) {
			nextHop[i][j] = j;
		}
	}
}

//void test(vector<vector<int>> distmap, vector<vector<int>> nextHop, int n) {
//	/*for (int i = 0; i < n; i++)
//		for (int j = 0; j < i; j++)
//			if (i != j) printf("%d->%d:%d\n", i, j, adjacencyMatrix[i][j]);*/
//	while (1) {
//		int f, en;
//		cin >> f >> en;
//		/*scanf("%d%d", &f, &en);*/
//		while (f != en) {
//			printf("%d->", f);
//			f = nextHop[f][en];
//		}
//		printf("%d\n", en);
//	}
//}

void topo(const string &filename, vector<vector<int>> &nextHop) {
	//string filename/* = "cernet.txt"*/;
	ifstream topo_file;
	//cout << "Please input topology filename: ";
	//cin >> filename;
	open_file(topo_file, filename);
	int n_num, e_num;
// （不处理负权回路）输入点数、边数
	topo_file >> n_num >> e_num;
	vector<vector<int>> distmap(n_num, vector<int>(n_num, INF)); //默认初始化邻接矩阵
	//vector<vector<int>> nextHop(n_num, vector<int>(n_num));
	init_path(nextHop, n_num);
	/*print_path(nextHop, n_num);*/
	for (int i = 0, p, q; i != e_num; ++i) {
		//第i + 1条边的起点、终点
		topo_file >> p >> q;
		if (p == q) {
			assert(false);
		}
		distmap[p][q] = distmap[q][p] = 1;
	}
	topo_file.close();
	floyd(distmap, nextHop);
	//print_path(nextHop, n_num);
	//test(adjacencyMatrix, nextHop, n_num);
	return;
}