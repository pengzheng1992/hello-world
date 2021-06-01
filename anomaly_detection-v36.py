# 使用方式： $ryu-manager --observe-links simple_switch_13.py anomaly_detection-v31.py ofctl_rest.py global_vars.py ......
# 必须先开控制器再开网络连接控制器,然后网络pingall才行，否则host可能无法正常获取。
# XXX 测量对接的时候若流量传输过程中可能包数不一样，会误检测丢包、黑洞路由路径等。若加入阈值允许误差存在，可能影响正常功能。数据最好保证可用性就行。
# 因此测量数据最好严格一致可用。

import os
import time
import socket
import struct
import urllib.request
import json
import requests

from math import log

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_host, get_all_link, get_all_switch
from ryu.base.app_manager import lookup_service_brick

# import global_vars

table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")} # print(table[i]) import socket，可根据协议号找协议名字

# 各个测量周期
# DISCOVERY_PERIOD = 1           # 拓扑发现周期，然后进行丢包检测和黑洞检测
# HEAVY_PERIOD = 1               # 读Heavy Hitter Heavy Change周期
# ROUTING_PATH_TEST_PERIOD = 1   # 路由路径检测周期(也是下载流表、做路由表的周期)
DDOS_TEST_PERIOD = 1           # DDoS检测周期

# 各个测量阈值
HEAVY_HITTER_THREASHOLD = 1000000000     # 大流判定比特数>阈值
HEAVY_CHANGE_THREASHOLD = 1000000000     # 频繁改变流比特数>阈值
DDOS_ENTROPY_THREASHOLD = 1.1            # DDoS判定信息熵<阈值，两个节点占据全部带宽算攻击
DDOS_PACKET_NO_THREASHOLD = 10000       # 每1秒1万包算攻击
DDOS_FLOW_NO_THREASHOLD = 10000          # 流数目>阈值10000条流

MANAGER_URL = "http://localhost:8080/builtinapplog"  # 异常检测结果报告url

class AnomalyDetection13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnomalyDetection13, self).__init__(*args, **kwargs)
        self.logger.info('AnomalyDetection13.__init__')

        self.topology_api_app = self
        self.controller_thread = lookup_service_brick('controller_thread')
        self.api = lookup_service_brick('path_dectection13')
        
        self.datapaths = {}     # 交换机id
        self.neighbors = {}     # 本交换机id：邻居交换机id集合
        self.host2switch = {}   # XXX：本host的ip地址：本host对应的交换机id ip_str->id_int
        # XXX 上面如果host有ipv4地址，则按第一个ipv4地址录入其连接的交换机，否则按ipv6地址，都没有就不录入(ip存的是字符串)
        self.flow_entries = {} # 存流表
        self.route_table = {} # 存路由表
        self.port_no_to_neighbor_id = {} # 存交换机的端口号码到邻近交换机id的映射
        self.ddosed = {}

        self.ddos_inspect_thread = hub.spawn(self._ddos_inspect_test)              # 周期检测DDoS
        
        self.logger.info('AnomalyDetection13.__init__ end')

    # 获取保存datapaths
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        print("state_change")
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                print('register datapath up:', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                print('unregister datapath down:', datapath.id)
                del self.datapaths[datapath.id]

    # 周期更新一次流表，为了得到正确路由信息，然后进行路由错误检测
    def discover_flow_entries(self):
        ret = self.get_flow_entries_ev(None)
        if ret == 0:
            self.get_route_table()
            self.routing_path_test()
        elif ret == -1:
            print('get flow entries failed, so I do not get route table and not test routing path')
        else:
            assert(False)

    # 周期性获取拓扑相关信息，然后获取流表，为路由错误、黑洞和丢包检测应用作准备
    def discover_topo(self):
        self.get_topology(None)
        self.discover_flow_entries()
        for dpid in self.datapaths.keys() & self.controller_thread.flow_stat.keys() & self.ddosed.keys():
            if not self.ddosed[dpid] and not self.route_err:
                self.pkt_loss_test(dpid)

    # 周期检测HH
    def heavy_hitter(self):
        # self.logger.info('AnomalyDetection13._heavy_hitter')
        ii = self.controller_thread.new_stat_i
        while ii < 0:
            hub.sleep(0.5)
            ii = self.controller_thread.new_stat_i
        for dpid in self.datapaths.keys() & self.controller_thread.flow_stat.keys() & self.ddosed.keys():
            if self.ddosed[dpid]:
                continue
            for flow in self.controller_thread.flow_stat[dpid][ii].keys() & self.controller_thread.flow_stat[dpid][ii-1].keys():
                current_bit_count = self.controller_thread.flow_stat[dpid][ii][flow][1] - self.controller_thread.flow_stat[dpid][ii-1][flow][1]
                # print('self.controller_thread.flow_stat[dpid][ii][flow][1] and self.controller_thread.flow_stat[dpid][ii-1][flow][1]',self.controller_thread.flow_stat[dpid][ii][flow][1], self.controller_thread.flow_stat[dpid][ii-1][flow][1])
                # self.logger.info('In _heavy_hitter(): datapath_id: %s, SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d, Protocol: %s, bit_count: %d, HEAVY_HITTER_THREASHOLD: %d\n',
                #                     str(dpid),
                #                     socket.inet_ntoa(struct.pack('I',socket.htonl(flow[0]))),
                #                     socket.inet_ntoa(struct.pack('I',socket.htonl(flow[1]))),
                #                     flow[2],
                #                     flow[3],
                #                     table[flow[4]],
                #                     current_bit_count,
                #                     HEAVY_HITTER_THREASHOLD)
                if current_bit_count > HEAVY_HITTER_THREASHOLD:
                    # 数字IP转点分十进制
                    hh_result = '从交换机' + str(dpid) + '上报的流数据中检测到Heavy Hitter异常流量-从' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow[0]))) \
                        + '的' + str(flow[2]) + '端口发到' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow[1]))) \
                        + '的' + str(flow[3]) + '端口的' \
                        + table[flow[4]] + '包的流量超过阈值' + str(HEAVY_HITTER_THREASHOLD) + '。'
                    hh_create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    self.logger.info('result: %s\ncreate_time: %s\n', hh_result, hh_create_time)
                    if 'Heavy Hitter' in self.api.g_enabled_apps:
                        requests.post(url=MANAGER_URL,data=json.dumps({'app_name':'Heavy Hitter','result':hh_result,'create_time':hh_create_time}),headers={'Content-Type':'application/json'})

    # 周期检测HC
    def heavy_change(self):
        # self.logger.info('AnomalyDetection13._heavy_change')
        ii = self.controller_thread.new_stat_i
        while ii < 0:
            hub.sleep(0.5)
            ii = self.controller_thread.new_stat_i
        if len(self.datapaths) > 1000:
        	return
        for dpid in self.datapaths.keys() & self.controller_thread.flow_stat.keys() & self.ddosed.keys():
            if self.ddosed[dpid]:
                continue
            if len(self.controller_thread.flow_stat[dpid][ii].keys()) > 1000:
            	return
            if len(self.controller_thread.flow_stat[dpid][ii-2].keys()) > 1000:
            	return
            if len(self.controller_thread.flow_stat[dpid][ii-1].keys()) > 1000:
            	return
            for flow in self.controller_thread.flow_stat[dpid][ii].keys() | (self.controller_thread.flow_stat[dpid][ii-2].keys() & self.controller_thread.flow_stat[dpid][ii-1].keys()):
                if flow in (self.controller_thread.flow_stat[dpid][ii-2].keys() & self.controller_thread.flow_stat[dpid][ii-1].keys()) - self.controller_thread.flow_stat[dpid][ii].keys():
                    bit_change = self.controller_thread.flow_stat[dpid][ii-1][flow][1] - self.controller_thread.flow_stat[dpid][ii-2][flow][1]
                    heavychange = True
                elif flow in self.controller_thread.flow_stat[dpid][ii].keys():
                    if flow in self.controller_thread.flow_stat[dpid][ii-2].keys() - self.controller_thread.flow_stat[dpid][ii-1].keys():
                        bit_change = self.controller_thread.flow_stat[dpid][ii][flow][1] - self.controller_thread.flow_stat[dpid][ii-2][flow][1]
                        heavychange = True
                    elif flow in self.controller_thread.flow_stat[dpid][ii-1].keys() - self.controller_thread.flow_stat[dpid][ii-2].keys():
                        bit_change = self.controller_thread.flow_stat[dpid][ii][flow][1] - self.controller_thread.flow_stat[dpid][ii-1][flow][1]
                        heavychange = True
                    elif flow in self.controller_thread.flow_stat[dpid][ii-1].keys() & self.controller_thread.flow_stat[dpid][ii-2].keys():
                        thisbit = self.controller_thread.flow_stat[dpid][ii][flow][1] - self.controller_thread.flow_stat[dpid][ii-1][flow][1]
                        lastbit = self.controller_thread.flow_stat[dpid][ii-1][flow][1] - self.controller_thread.flow_stat[dpid][ii-2][flow][1]
                        bit_change = abs(thisbit - lastbit)
                        heavychange = True
                    else:
                        heavychange = False
                else:
                    heavychange = False
                if not heavychange:
                    continue
                assert(heavychange)
                if bit_change > HEAVY_CHANGE_THREASHOLD:
                    # self.logger.info('\nHeavy_Change detected!  datapath_id: %s,\nSrcIP: %d, DstIP: %d, SrcPort: %d, DstPort: %d, Protocol: %d\nlast_bit_count: %d, current_bit_count: %d,\nbit_change: %d, HEAVY_CHANGE_THREASHOLD: %d\n',
                    #                 str(dpid), flow_tuple.SrcIP, flow_tuple.DstIP, flow_tuple.SrcPort, flow_tuple.DstPort, flow_tuple.Protocol,
                    #                 last_bit_count,
                    #                 current_bit_count,
                    #                 bit_change,
                    #                 HEAVY_CHANGE_THREASHOLD)
                    hc_result = '从交换机' + str(dpid) + '上报的流数据中检测到Heavy Change异常流量-在时间' \
                        + str(DDOS_TEST_PERIOD * 2) + '秒内从' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow[0]))) \
                        + '的' + str(flow[2]) + '端口发到' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow[1]))) \
                        + '的' + str(flow[3]) + '端口的' \
                        + table[flow[4]] + '包的流量变化超过阈值' + str(HEAVY_CHANGE_THREASHOLD) + '。'
                    hc_create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    self.logger.info('result: %s\ncreate_time: %s\n', hc_result, hc_create_time)
                    if 'Heavy Change' in self.api.g_enabled_apps:
                        requests.post(url=MANAGER_URL,data=json.dumps({'app_name':'Heavy Change','result':hc_result,'create_time':hc_create_time}),headers={'Content-Type':'application/json'})
        # print("-------------end heavy change------------")

    def _ddos_inspect_test(self):
        self.logger.info('AnomalyDetection13._ddos_inspect_test starts')
        while True:
            ddosed = {}
            for dpid in self.datapaths.keys() & self.controller_thread.flow_stat.keys():
                ret = self.ddos_inspect_test(dpid)
                if ret == None or ret == 0:
                    ddosed[dpid] = False
                elif ret == 1:
                    ddosed[dpid] = True
            self.ddosed = ddosed
            self.discover_topo()
            self.heavy_hitter()
            self.heavy_change()
            hub.sleep(DDOS_TEST_PERIOD)

    def get_flow_entries(self, dpid):
        # print('get_flow_entries')
        try:
            url = "http://127.0.0.1:8080/stats/flow/" + str(dpid)
            req = urllib.request.Request(url)
            res_data = urllib.request.urlopen(req)
            res = res_data.read()
            res = json.loads(res)
            return res
        except Exception as e:
            print(e)
            return None

    # 获取流表
    # @set_ev_cls([ofp_event.EventOFPFlowRemoved, ofp_event.EventOFPFlowMod], MAIN_DISPATCHER)
    def get_flow_entries_ev(self, ev):
        flow_entries = {}
        #FIXME：可能有changed size问题，也许能用list()解决，不知道行不行
        for dpid in self.datapaths.keys() & self.controller_thread.flow_stat.keys(): 
            res = self.get_flow_entries(dpid)
            if res == None:
                return -1
            for dpid_str in res:
                flow_entries[int(dpid_str)] = res[dpid_str]
        self.flow_entries = flow_entries
        return 0

    # TODO:FIXME: 从流表变路由表
    def get_route_table(self):
        route_table = {}
        for dpid_int in self.flow_entries:
            route_table[dpid_int] = {}
            flow_entry_list = self.flow_entries[dpid_int]
            for flow_enrty in flow_entry_list:
                # print(flow_enrty, type(flow_enrty))
                port_no_int = 0
                nw_dst_str = ""

                if "actions" in flow_enrty:
                    action_list = flow_enrty["actions"]
                    for action in action_list:
                        if isinstance(action, str):
                            x = action.split(":", 2)
                            if x[0] == 'OUTPUT' and x[1] != 'CONTROLLER':
                                port_no_int = int(x[1]) # 转发端口
                                break
                        elif isinstance(action, dict):
                            if action["type"] == "OUTPUT" and action["port"] != 'CONTROLLER':
                                port_no_int = int(action["port"])
                                break
                else:
                    continue

                if "match" in flow_enrty:
                    match_dict = flow_enrty["match"]
                    if "nw_dst" in match_dict:
                        nw_dst_str = match_dict["nw_dst"]
                        route_table[dpid_int][nw_dst_str] = port_no_int # 根据dpid和目的ip决定其转发端口(int)
        
        self.route_table = route_table

    # List the event list should be listened.
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    @set_ev_cls(events)
    def get_topology(self, ev):
        """
            Get topology info.
        """
        # print('----------------')

        # print('get_topology')
        neighbors = {}
        port_no_to_neighbor_id = {}

        switch_list = get_all_switch(self.topology_api_app)
        for sw in switch_list:
            #print (sw.dp.id) #int
            neighbors[sw.dp.id] = set()
            port_no_to_neighbor_id[sw.dp.id] = {}

        links = get_all_link(self.topology_api_app)
        for link in links:
            # print(link)
            # print(link.src.port_no, link.dst.dpid)#int int
            neighbors[link.src.dpid].add(link.dst.dpid)
            port_no_to_neighbor_id[link.src.dpid][link.src.port_no] = link.dst.dpid
        
        #print(neighbors)
        self.neighbors = neighbors
        self.port_no_to_neighbor_id = port_no_to_neighbor_id
        #print(self.neighbors)
        hosts = get_all_host(self.topology_api_app)
        # print(type(hosts))
        for host in hosts:
            # print('host')
            # print(host.mac, type(host.mac))#str
            # print(host.port.dpid, type(host.port.dpid))#int
            if host.ipv4:
                self.host2switch[host.ipv4[0]] = host.port.dpid
            # XXX 上面如果host有ipv4地址，则按第一个ipv4地址录入其连接的交换机，否则按ipv6地址，都没有就不录入(ip存的是点分十进制字符串)
            elif host.ipv6:
                self.host2switch[host.ipv6[0]] = host.port.dpid
            else:
                pass

    def get_neighbors(self, switch_id):
        '''
        获得邻居交换机节点号码
        '''
        return self.neighbors[switch_id]
        
    def get_first_switch(self, flow_tuple):
        srcip = socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[0])))
        if srcip not in self.host2switch:
            return None
        else:
            # print(self.host2switch[srcip])
            return self.host2switch[srcip]
        
    def get_last_switch(self, flow_tuple):
        dstip = socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[1])))
        if dstip not in self.host2switch:
            return None
        else:
            # print(self.host2switch[dstip])
            return self.host2switch[dstip]
        
    def pkt_loss_inspect(self, switch_id):
        '''
        输出这个交换机丢包数
        '''
        # self.logger.info('\npkt_loss_inspect\n')
        ii = self.controller_thread.new_stat_i
        while ii < 0:
            hub.sleep(0.5)
            ii = self.controller_thread.new_stat_i
        drop_num = {}
        for neighbor_id in self.get_neighbors(switch_id):
            if neighbor_id not in self.controller_thread.flow_stat.keys():
                continue
            for flow_tuple in self.controller_thread.flow_stat[switch_id][ii].keys() & self.controller_thread.flow_stat[neighbor_id][ii].keys() & self.controller_thread.flow_stat[switch_id][ii-1].keys() & self.controller_thread.flow_stat[neighbor_id][ii-1].keys():
                num = self.controller_thread.flow_stat[switch_id][ii][flow_tuple][0] - self.controller_thread.flow_stat[switch_id][ii-1][flow_tuple][0]
                num_nb = self.controller_thread.flow_stat[neighbor_id][ii][flow_tuple][0] - self.controller_thread.flow_stat[neighbor_id][ii-1][flow_tuple][0]
                if num > num_nb and (num-num_nb)*10 > num and num > 10000: # 设一个丢包率阈值，避免误报
                    drop_num[flow_tuple] = num - num_nb
        return drop_num

    def pkt_loss_test(self, dp_id):
        # print('pkt_loss_test')
        loss = self.pkt_loss_inspect(dp_id)
        for flow_tuple in loss:
            # self.logger.info('\nPacket_Loss detected!  datapath_id: %s,\nSrcIP: %d, DstIP: %d, SrcPort: %d, DstPort: %d, Protocol: %d\nloss_number: %d packets\n',
            #     str(dp_id), flow_tuple.SrcIP, flow_tuple.DstIP, flow_tuple.SrcPort, flow_tuple.DstPort, flow_tuple.Protocol,
            #     loss[flow_tuple])
            db_result = '检测到丢包-从' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[0]))) \
                        + '的' + str(flow_tuple[2]) + '端口发到' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[1]))) \
                        + '的' + str(flow_tuple[3]) + '端口的' \
                        + table[flow_tuple[4]] + '包中发现丢包。'
            db_create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            self.logger.info('result: %s\ncreate_time: %s\n', db_result, db_create_time)
            if '丢包' in self.api.g_enabled_apps:
                requests.post(url=MANAGER_URL,data=json.dumps({'app_name':'丢包','result':db_result,'create_time':db_create_time}),headers={'Content-Type':'application/json'})

        # XXX 在不再丢包的情况下停止警报。但继续丢包的情况则继续报警。

    def routing_path_test(self):
        # print('routing_path_test')
        # 先找真实路径，找完再比对
        # 检测全部流
        self.route_err = False
        route_err = False
        ii = self.controller_thread.new_stat_i
        while ii < 0:
            hub.sleep(0.5)
            ii = self.controller_thread.new_stat_i
        for dpid in self.datapaths.keys() & self.controller_thread.flow_stat.keys() & self.ddosed.keys():
            # print('dpid',dpid)
            if self.ddosed[dpid]:
                continue
            for flow_tuple in self.controller_thread.flow_stat[dpid][ii].keys():
                # print('flow_tuple',flow_tuple)
                prev_id = self.get_first_switch(flow_tuple)
                # print('prev_id',prev_id)
                correct_prev_id = prev_id
                if prev_id not in self.datapaths.keys() & self.controller_thread.flow_stat.keys():
                    # print('prev_id not in self.datapaths.keys() & self.controller_thread.flow_stat.keys()')
                    break
                if flow_tuple not in self.controller_thread.flow_stat[prev_id][ii]:
                    # print('flow_tuple not in self.controller_thread.flow_stat[prev_id][ii]')
                    continue
                prev_bit_size = self.controller_thread.flow_stat[prev_id][ii][flow_tuple][1]
                # print('1prev_bit_size', prev_bit_size)
                last_id = self.get_last_switch(flow_tuple)
                # print('last_id', last_id)
                correct_last_id = last_id
                path = [prev_id]#真实路径
                # print('path',path)
                stop = False
                hops = 1
                while not stop and prev_id != last_id and hops<20:       #XXX： 如果路由错误，导致数据包没有走到最后一个交换机，报黑洞错误不报路由错误
                    stop = True
                    for neighbor_id in self.get_neighbors(prev_id):
                        # print('neighbor_id',neighbor_id)
                        if neighbor_id in path:
                            # print('neighbor_id in path')
                            continue
                        if neighbor_id not in self.controller_thread.flow_stat.keys():
                            # print('neighbor_id not in self.controller_thread.flow_stat.keys():')
                            continue
                        # if flow_tuple in self.controller_thread.flow_stat[neighbor_id][ii]:
                        #     print('neighbor_id_bit_size', self.controller_thread.flow_stat[neighbor_id][ii][flow_tuple][1])
                        # else:
                        #     print('flow_tuple', flow_tuple)
                        # print('neighbor_id', neighbor_id)
                        # print('flow_tuple', flow_tuple)
                        if flow_tuple in self.controller_thread.flow_stat[neighbor_id][ii].keys() and abs((self.controller_thread.flow_stat[neighbor_id][ii][flow_tuple][1]-prev_bit_size)/(float)(prev_bit_size)) < 0.3 and prev_bit_size > 1000000:
                            path.append(neighbor_id)
                            # print('path',path)
                            prev_id = neighbor_id
                            prev_bit_size = self.controller_thread.flow_stat[neighbor_id][ii][flow_tuple][1]
                            stop = False
                            hops += 1
                            break
                # # got real path
                
                # find correct path
                nw_dst_str = socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[1])))
                correct_path = [correct_prev_id]#正确路径
                # print('flow_tuple', flow_tuple.__dict__)
                # print('flow_tuple.DstIP', socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple.DstIP))))
                special_ip = False
                while correct_prev_id != correct_last_id:       # FIXME： 如果路由错误，导致数据包没有走到最后一个交换机怎么办？？(黑洞错误不报路由错误)
                    # print('route_table', self.route_table)
                    # print('nw_dst_str', nw_dst_str, 'correct_prev_id', correct_prev_id)
                    if nw_dst_str not in self.route_table[correct_prev_id].keys():
                        special_ip = True
                        break
                    correct_next_port_no_int = self.route_table[correct_prev_id][nw_dst_str]
                    # print('correct_prev_id', correct_prev_id, 'correct_next_port_no_int', correct_next_port_no_int)
                    # print('port_no_neighbor_id', self.port_no_to_neighbor_id)
                    if correct_next_port_no_int not in self.port_no_to_neighbor_id[correct_prev_id].keys():
                        special_ip = True
                        break
                    correct_next_dpid = self.port_no_to_neighbor_id[correct_prev_id][correct_next_port_no_int]
                    correct_path.append(correct_next_dpid)
                    correct_prev_id = correct_next_dpid
                # got correct path


                if special_ip:
                    continue
                if path == correct_path:
                    continue
                route_err = False
                if hops > 15:
                    route_err = True
                pathlen = len(path)
                cpathlen = len(correct_path)
                blace_hole_err = False
                if pathlen > cpathlen:
                    route_err = True
                else:
                    assert(pathlen <= cpathlen)
                    for i in range(pathlen):
                        if path[i] != correct_path[i]:
                            route_err = True
                        else:
                            continue
                    blace_hole_err = True
                    
                if route_err:
                    ly_result = '检测到路由错误-交换机' + str(dpid) + '中存在路由表错误-从' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[0]))) \
                        + '的' + str(flow_tuple[2]) + '端口发到' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[1]))) \
                        + '的' + str(flow_tuple[3]) + '端口的' \
                        + table[flow_tuple[4]] + '包的路径为交换机' + str(path) + '是错误的，正确的路径应该为交换机' \
                        + str(correct_path)
                    ly_create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                    self.logger.info('result: %s\ncreate_time: %s\n', ly_result, ly_create_time)
                    if '路由错误' in self.api.g_enabled_apps:
                        requests.post(url=MANAGER_URL,data=json.dumps({'app_name':'路由错误','result':ly_result,'create_time':ly_create_time}),headers={'Content-Type':'application/json'})
                    self.route_err = True
                else:
                    assert(not self.route_err)
                    if stop and self.controller_thread.flow_stat[dpid][ii][flow_tuple][0] > 10000 and blace_hole_err:
                        # 报告黑洞 XXX
                        hd_result = '检测到黑洞-从' \
                            + socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[0]))) \
                            + '的' + str(flow_tuple[2]) + '端口发到' \
                            + socket.inet_ntoa(struct.pack('I',socket.htonl(flow_tuple[1]))) \
                            + '的' + str(flow_tuple[3]) + '端口的' \
                            + table[flow_tuple[4]] + '包发生黑洞。'
                        hd_create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        self.logger.info('result: %s\ncreate_time: %s\n', hd_result, hd_create_time)
                        if '黑洞' in self.api.g_enabled_apps:
                            requests.post(url=MANAGER_URL,data=json.dumps({'app_name':'黑洞','result':hd_result,'create_time':hd_create_time}),headers={'Content-Type':'application/json'})
                        continue
                        

    def ddos_inspect(self, dpid):
        # print("----------ddos inspect---------")
        '''
        DDoS检测
        '''
        ii = self.controller_thread.new_stat_i
        while ii < 0:
            hub.sleep(0.5)
            ii = self.controller_thread.new_stat_i
        # 计算香农熵
        num_entries = 0.0   # 总包数
        label_counts = {}
        flow_count = 0
        # print('self.controller_thread.flow_stat[dpid][ii].keys()', self.controller_thread.flow_stat[dpid][ii].keys())
        for flow in self.controller_thread.flow_stat[dpid][ii].keys():
            # print('self.controller_thread.flow_stat[dpid][ii][flow][0]',self.controller_thread.flow_stat[dpid][ii][flow][0])
            if self.controller_thread.flow_stat[dpid][ii][flow][0] > 0:
                flow_count += 1
                current_label = flow[1]           # 对目的IP进行熵计算。
                if current_label not in label_counts.keys():
                    label_counts[current_label] = 0
                if flow in self.controller_thread.flow_stat[dpid][ii-1].keys():
                    packetcount = self.controller_thread.flow_stat[dpid][ii][flow][0] - self.controller_thread.flow_stat[dpid][ii-1][flow][0]
                else:
                    packetcount = self.controller_thread.flow_stat[dpid][ii][flow][0]
                label_counts[current_label] += packetcount
                num_entries += packetcount
        if num_entries == 0:
            return None
        shannon_ent = 0.0   # 香农熵
        for key in label_counts:
            if label_counts[key] > 0:
                prob = float(label_counts[key]) / num_entries   # 该目的ip的概率
                shannon_ent -= prob * log(prob, 2)              # 香农熵
        # print(label_counts)
        attacked_ip = max(label_counts, key=label_counts.get)   # 将作为dstIP最多的包的IP标记为被ddos攻击IP
        return (shannon_ent, num_entries, flow_count, attacked_ip)
        
    # ddos加上流数目阈值，防止误报正常流量。
    def ddos_inspect_test(self, dp_id):
        ddos = self.ddos_inspect(dp_id)
        if ddos == None:
            return None
        self.logger.info('\nddos_inspect_test...  datapath_id: %s, entropy: %f, total packets: %d, #flow: %d， attacked_ip: %d, time: %s\n',
                str(dp_id),
                ddos[0],
                ddos[1],
                ddos[2],
                ddos[3],
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
        # 信息熵如果小于阈值，包数大于阈值，流数大于阈值，则判定发生了DDoS攻击
        if ddos[0] < DDOS_ENTROPY_THREASHOLD and ddos[1] > DDOS_PACKET_NO_THREASHOLD and ddos[2] > DDOS_FLOW_NO_THREASHOLD:
            # self.logger.info('|_--->DDoS detected!<---_|')
            dd_result = '从交换机' + str(dp_id) + '上报的流数据中检测到DDoS攻击-主机' \
                        + socket.inet_ntoa(struct.pack('I',socket.htonl(ddos[3]))) \
                        + '遭到DDoS攻击。'
            dd_create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            self.logger.info('result: %s\ncreate_time: %s\n', dd_result, dd_create_time)
            if 'DDoS攻击' in self.api.g_enabled_apps:
                requests.post(url=MANAGER_URL,data=json.dumps({'app_name':'DDoS攻击','result':dd_result,'create_time':dd_create_time}),headers={'Content-Type':'application/json'})
            return 1
        else:
            return 0
