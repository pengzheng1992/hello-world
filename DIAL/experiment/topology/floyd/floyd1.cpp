// ConsoleApplication1.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>

using namespace std;

const int &INF = 100000000;

ifstream& open_file(ifstream &in, const string &file) {
	in.close();
	in.clear();
	in.open(file.c_str());
	return in;
}

void floyd(vector<vector<int> > &distmap,     //可被更新的邻接矩阵，更新后不能确定原有边
	vector<vector<int> > &path)               //路径上到达该点的中转点
{
	const int &NODE = distmap.size();         //用邻接矩阵的大小传递顶点个数，减少参数传递
	path.assign(NODE, vector<int>(NODE, -1)); //初始化路径数组 
	for (int k = 0; k != NODE; ++k)           //对于每一个中转点
		for (int i = 0; i != NODE; ++i)       //枚举源点
			for (int j = 0; j != NODE; ++j)   //枚举终点
				if (distmap[i][j] > distmap[i][k] + distmap[k][j])//不满足三角不等式
				{
					distmap[i][j] = distmap[i][k] + distmap[k][j];//更新
					path[i][j] = k;//记录路径
				}
}

void print(const int &begin, const int &end,
	const vector<vector<int> > &path)         //传引用，避免拷贝，不占用内存空间
									          //也可以用栈结构先进后出的特性来代替函数递归 
{
	if (path[begin][end] >= 0) {
		print(begin, path[begin][end], path);
		print(path[begin][end], end, path);
	}
	else cout << "->" << end;
}

int main() {
	string filename = "cernet.txt";
	ifstream topo_file;
	open_file(topo_file, filename);
	int n_num, e_num, begin, end;//含义见下
// （不处理负权回路）输入点数、边数
	topo_file >> n_num >> e_num;
	vector<vector<int>> path, distmap(n_num, vector<int>(n_num, INF));//默认初始化邻接矩阵

	for (int i = 0; i < n_num;++i) {
		distmap[i][i] = 0;
	}
	for (int i = 0, p, q; i != e_num; ++i) {
		//第i + 1条边的起点、终点
		topo_file >> p >> q;
		if (p == q) {
			assert(false);
		}
		distmap[p][q] = distmap[q][p] = 1;
	}
	topo_file.close();
	floyd(distmap, path);
	for (int i = 0; i < n_num; ++i) {
		for (int j = 0;j < n_num; ++j) {
			cout << path[i][j] << " ";
		}
		cout << endl;
	}
	while (1) {
		cin >> begin >> end;
		cout << "最短距离为" << distmap[begin][end] << "，打印路径：" << begin;
		print(begin, end, path);
		cout << endl;
	}
	/*for (begin = 0;begin < n_num;++begin) {
		for (end = 0;end < n_num;++end) {
			cout << "最短距离为" << distmap[begin][end] << "，打印路径：" << begin;
			print(begin, end, path);
			cout << endl;
		}
	}*/
}