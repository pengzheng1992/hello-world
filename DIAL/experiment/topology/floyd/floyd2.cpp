// ConsoleApplication1.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <string>
#include <cstdio>

using namespace std;

const int &INF = 100000000;

ifstream& open_file(ifstream &in, const string &file) {
	in.close();
	in.clear();
	in.open(file.c_str());
	return in;
}

void floyd(vector<vector<int>> &distmap, vector<vector<int>> &path) {
	const int &NODE = distmap.size();
	//path.assign(NODE, vector<int>(NODE, -1));
	for (int k = 0; k != NODE; ++k)
		for (int i = 0; i != NODE; ++i)
			for (int j = 0; j != NODE; ++j)
				if (distmap[i][j] > distmap[i][k] + distmap[k][j]) {
					distmap[i][j] = distmap[i][k] + distmap[k][j];
					path[i][j] = path[i][k];
				}
}

void print_path(vector<vector<int>> path, int n_num) {
	for (int i = 0; i < n_num; ++i) {
		for (int j = 0;j < n_num; ++j) {
			cout << path[i][j] << " ";
		}
		cout << endl;
	}
}

void init_path(vector<vector<int>> &path, int n_num) {
	for (int i = 0; i < n_num; ++i) {
		for (int j = 0; j < n_num; ++j) {
			path[i][j] = j;
		}
	}
}

void test(vector<vector<int>> distmap, vector<vector<int>> path, int n) {
	/*for (int i = 0; i < n; i++)
		for (int j = 0; j < i; j++)
			if (i != j) printf("%d->%d:%d\n", i, j, distmap[i][j]);*/
	while (1) {
		int f, en;
		cin >> f >> en;
		/*scanf("%d%d", &f, &en);*/
		while (f != en) {
			printf("%d->", f);
			f = path[f][en];
		}
		printf("%d\n", en);
	}
}

int main() {
	string filename/* = "cernet.txt"*/;
	ifstream topo_file;
	cout << "Please input topology filename: ";
	cin >> filename;
	open_file(topo_file, filename);
	int n_num, e_num;
// （不处理负权回路）输入点数、边数
	topo_file >> n_num >> e_num;
	vector<vector<int>> distmap(n_num, vector<int>(n_num, INF)); //默认初始化邻接矩阵
	vector<vector<int>> path(n_num, vector<int>(n_num));
	init_path(path, n_num);
	/*print_path(path, n_num);*/
	for (int i = 0, p, q; i != e_num; ++i) {
		//第i + 1条边的起点、终点
		topo_file >> p >> q;
		/*if (p == q) {
			assert(false);
		}*/
		distmap[p][q] = distmap[q][p] = 1;
	}
	topo_file.close();
	floyd(distmap, path);
	print_path(path, n_num);
	test(distmap, path, n_num);
}
