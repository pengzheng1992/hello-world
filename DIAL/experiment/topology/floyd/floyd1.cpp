// ConsoleApplication1.cpp : �������̨Ӧ�ó������ڵ㡣
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

void floyd(vector<vector<int> > &distmap,     //�ɱ����µ��ڽӾ��󣬸��º���ȷ��ԭ�б�
	vector<vector<int> > &path)               //·���ϵ���õ����ת��
{
	const int &NODE = distmap.size();         //���ڽӾ���Ĵ�С���ݶ�����������ٲ�������
	path.assign(NODE, vector<int>(NODE, -1)); //��ʼ��·������ 
	for (int k = 0; k != NODE; ++k)           //����ÿһ����ת��
		for (int i = 0; i != NODE; ++i)       //ö��Դ��
			for (int j = 0; j != NODE; ++j)   //ö���յ�
				if (distmap[i][j] > distmap[i][k] + distmap[k][j])//���������ǲ���ʽ
				{
					distmap[i][j] = distmap[i][k] + distmap[k][j];//����
					path[i][j] = k;//��¼·��
				}
}

void print(const int &begin, const int &end,
	const vector<vector<int> > &path)         //�����ã����⿽������ռ���ڴ�ռ�
									          //Ҳ������ջ�ṹ�Ƚ���������������溯���ݹ� 
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
	int n_num, e_num, begin, end;//�������
// ��������Ȩ��·���������������
	topo_file >> n_num >> e_num;
	vector<vector<int>> path, distmap(n_num, vector<int>(n_num, INF));//Ĭ�ϳ�ʼ���ڽӾ���

	for (int i = 0; i < n_num;++i) {
		distmap[i][i] = 0;
	}
	for (int i = 0, p, q; i != e_num; ++i) {
		//��i + 1���ߵ���㡢�յ�
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
		cout << "��̾���Ϊ" << distmap[begin][end] << "����ӡ·����" << begin;
		print(begin, end, path);
		cout << endl;
	}
	/*for (begin = 0;begin < n_num;++begin) {
		for (end = 0;end < n_num;++end) {
			cout << "��̾���Ϊ" << distmap[begin][end] << "����ӡ·����" << begin;
			print(begin, end, path);
			cout << endl;
		}
	}*/
}