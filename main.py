# coding=utf-8

#----------------------------------------------------------
# import module:
# 1.tkinter to make GUI
# 2.scapy to make packet and send it out
#----------------------------------------------------------

import tkinter
from tkinter import *
from tkinter.constants import *
from tkinter.ttk import Treeview, Style

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


#---------------------------------------------------------
# INITIAL STUCTURE MODULE
# initial basic frame of the GUI with tkinter
# we name the frame ‘tk’
#---------------------------------------------------------

tk = tkinter.Tk()
tk.title("自制发包器")
# 将用户界面最大化
tk.state("zoomed")
# 左右分隔窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5)
# 协议编辑区窗体
protocol_editor_panedwindow = PanedWindow(orient=VERTICAL, sashrelief=RAISED, sashwidth=5)
# 给出导航树定义
protocols_tree = Treeview()
# 获得当前网卡的默认网关
# os.popen('route print').readlines() 打开了一个系统文件并读取了所有行，构成list ，在list里搜索网关
default_gateway = [a for a in os.popen('route print').readlines() if ' 0.0.0.0 ' in a][0].split()[-3]
# 用来终止数据包发送线程的线程事件
stop_sending = threading.Event()



#------------------------------------------------------------
# CREATE STRUCTURE MODULE
# here we get to shape the structure of main_panedwindow
# 1:status bar at the bottom
# 2:guide tree of protocols on the left
# 3:protocol editor on the right
#------------------------------------------------------------

class statusBar(Frame):
    """
    this is the status stated at the botton of the window,
    which can show us some status of our sender
    """
    def __init__(self,master):
        Frame.__init__(self ,master)
        self.label = Label(self ,bd =1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()

# 状态栏
# 状态栏里面用于显示一些目前正在进行的活动信息，比如发包数，发包速率
status_bar = statusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
status_bar.set("%s", '开始')

def create_protocols_guide_tree():
    """
    创建协议导航树，目前就是IP,TCP,UDP,ICMP,ARP
    :return:protocols_tree
    """
    protocols_tree.heading ('#0',text = '选择协议', anchor = 'w')
    transfer_entry = protocols_tree.insert("",0,"传输层",text = "传输层")
    network_entry = protocols_tree.insert("",1,"网络层",text = "网络层")

    tcp_entry = protocols_tree.insert(transfer_entry, 0, "TCP", text="TCP包")
    upd_entry = protocols_tree.insert(transfer_entry, 1, "UDP", text="UDP包")

    ip_entry = protocols_tree.insert(network_entry,0,"IP",text = "IP包")
    icmp_entry = protocols_tree.insert(network_entry,1,"ICMP",text = "ICMP包")
    arp_entry = protocols_tree.insert(network_entry,2,"ARP",text = "ARP包")

    #这是一个绑定事件的函数bind(事件类型，回调函数),当TreeviewSelect事件发生时，自动调用回调函数
    protocols_tree.bind('<<TreeviewSelect>>', on_click_protocols_tree)
    style = Style(tk)
    # get disabled entry colors
    disabled_bg = style.lookup("TEntry", "fieldbackground", ("disabled",))
    style.map("Treeview",
              fieldbackground=[("disabled", disabled_bg)],
              foreground=[("disabled", "gray")],
              background=[("disabled", disabled_bg)])
    protocols_tree.pack()
    return protocols_tree

def create_protocol_editor(root,feild_names):
    """
    创建协议字段编辑区，按照传入d feild_names在root下
    生成对应的编辑条目entrys
    :param root: 根窗格，在这个根窗格下创建
    :param feild_names: 要创建的字段list
    :return entries: 返回创建的条目集
    """
    entries = []
    for feild in feild_names:
        row = Frame(root)
        label = Label(row,width=15, text=feild, anchor = 'e')
        entry = Entry(row, font= ('Courier','12','bold'),state='normal')
        row.pack(side=TOP, fill=X, padx=5, pady=2)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT,expand=YES,fill=X)
        entries.append(entry)
    return entries

def create_bottom_buttons(root):
    """
    创建发送按钮,重置按钮,生成默认包头按钮
    :param root: 编辑编辑区
    :return: 发送按钮和清空按钮
    """
    bottom_buttons = Frame(root)
    #在窗口botton_buttons下创建那三个按钮
    send_packet_button = Button(bottom_buttons, width=20, text="连续发送")
    default_packet_button = Button(bottom_buttons, width=20, text="默认值")
    reset_button = Button(bottom_buttons, width=20, text="重置")
    send_packet_once_button = Button(bottom_buttons,width=20,text="发送一次")


    #把按钮窗口放在底下，并把按钮按grind排列
    bottom_buttons.pack(side=BOTTOM, fill=X, padx=5, pady=5)
    send_packet_button.grid(row=0, column=0, padx=5, pady=5)
    default_packet_button.grid(row=0, column=1, padx=5, pady=5)
    reset_button.grid(row=0, column=2, padx=5, pady=5)
    send_packet_once_button.grid(row=0, column=3, padx=5, pady=5)

    bottom_buttons.columnconfigure(0, weight=1)
    bottom_buttons.columnconfigure(1, weight=1)
    bottom_buttons.columnconfigure(2, weight=1)
    bottom_buttons.columnconfigure(3, weight=1)

    return send_packet_button, reset_button, default_packet_button,send_packet_once_button

#------------------------------------------------------------
# HELPER FUNCTION MODULE
# all of the helper function will be declared here
#------------------------------------------------------------

def clear_protocol_editor(entries):
    """
    清空协议编辑器里面的值
    :param entries:
    :return:
    """
    for entry in entries:
        state = entry['state']
        entry['state'] = 'normal'
        entry.delete(0,END)#0~end表示删除输入框所有内容
        entry['state'] = state #恢复权限，有的输入框不允许输入，有的允许，要引入第三参数state

def on_click_protocols_tree(event):
    """
    协议导航树里面单击协议后的响应函数，打开相应协议的编辑器
    :param event: Treeview 单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    # winfo_children方法得到该窗口下所有控件，清空protocol_editor_panedwindow上现有的控件
    for widget in protocol_editor_panedwindow.winfo_children():
        widget.destroy()
    # 设置状态栏
    status_bar.set("%s", selected_item[0])

    if selected_item[0] == "TCP":
        create_tcp_sender()
    elif selected_item[0] == "UDP":
        create_udp_sender()
    elif selected_item[0] == "IP":
        create_ip_sender()
    elif selected_item[0] == "ARP":
        create_arp_sender()
    elif selected_item[0] == "ICMP":
        create_icmp_sender()
    elif selected_item[0] == "ARP":
        create_arp_sender()

def toggle_protocols_tree_state():
    """
    切换导航树的状态：可用<->不可用
    :rtype: None
    """
    if "disabled" in protocols_tree.state():
        protocols_tree.state(("!disabled",))
        # re-enable item opening on click
        protocols_tree.unbind('<Button-1>')
    else:
        protocols_tree.state(("disabled",))
        #和时间break关系起来，则每次在导航树点击左键都会直接break
        protocols_tree.bind('<Button-1>', lambda event: 'break')

def send_packet_continously(packet_sending):
    """
    连续发包函数，连续发包并在状态栏显示发包数和发包速率
    :param packet_sending: 传入待发送的包
    :return:
    """
    n = 0
    stop_sending.clear()

    #包大小，包协议类型获取
    packet_size = len(packet_sending)
    protocol_names =['TCP','UDP','ICMP','IP','ARP','Unkown']
    packet_protocol = ''
    for a in protocol_names:
        if a in packet_sending:
            packet_protocol = a
            break

    # 开始发送时间点
    start_time = datetime.now()
    while not stop_sending.is_set():
        if isinstance(packet_sending,Ether):
            sendp(packet_sending, verbose=0)
        else:
            send(packet_sending, verbose=0)

        n += 1
        stop_time = datetime.now()
        total_byte = packet_size * n
        total_time = (stop_time - start_time).total_seconds()
        if total_time == 0:
            total_time = 2.23E-308 #防止发送过快而总时间为0，这样除法出错
        bytes_persec = (total_byte/total_time)/1024
        #状态栏显示
        status_bar.set('已经发送%d个%s数据包, 已经发送%d bytes，发送速率: %0.2fK字节/秒',
                       n, packet_protocol, total_byte, bytes_persec)

def send_packet_once(packet_sending):
    """
    发送包一次
    :param packet_sending:
    :return:
    """
    # 包大小，包协议类型获取
    packet_size = len(packet_sending)
    protocol_names = ['TCP', 'UDP', 'ICMP','IP', 'ARP', 'Unkown']#注意要把ICMP放在IP前面，不然ICMP包会被检测为IP包
    packet_protocol = ''
    for a in protocol_names:
        if a in packet_sending:
            packet_protocol = a
            break
    send(packet_sending, verbose=0)
    # 状态栏显示
    status_bar.set('已经发送%s数据包',packet_protocol)

#------------------------------------------------------------
# IP SEND MODULE
#------------------------------------------------------------

def create_ip_sender():
    """
    生成IP包编辑器
    :return:
    """
    #pass
    ip_head = 'IP版本：','头长度：','服务类型：','总长度：','标识：',\
              '标志(0-2)DF,MF：','分段偏移量:','生存期:','上层协议:',\
              '头校验和:','源IP地址:','目的IP地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, ip_head)
    send_packet_button ,reset_buttun,default_packet_button,\
    send_packet_once_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送IP包
    tk.bind('<Return>', (lambda event: send_ip_packet(entries, send_packet_button)))  # <Return>代表回车键
    # 为"连续发送"按钮的单击事件编写事件响应代码，发送IP包
    # 为"重置"按钮的单击事件编写事件响应代码，清除所有字段
    # 为"默认值"按钮的单击事件编写事件响应代码，填入IP包默认字段
    # <Button-1>代表鼠标左键单击
    send_packet_button.bind('<Button-1>', (lambda event: send_ip_packet_continuously(entries, send_packet_button)))
    reset_buttun.bind('<Button-1>',(lambda event:clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_ip_packet(entries)))
    send_packet_once_button.bind('<Button-1>',(lambda event: send_ip_packet_once(entries)))

def create_default_ip_packet(entries):
    """
    协议发包编辑器每一个条目里生成默认的IP字段值
    :param entries:
    :return:None
    """

    clear_protocol_editor(entries)
    default_ip_packet = IP()
    """参考字段如下，一共12个字段
    ###[ IP ]### 
    version   = 4
    ihl       = None
    tos       = 0x0
    len       = None
    id        = 1
    flags     = 
    frag      = 0
    ttl       = 64
    proto     = ip
    chksum    = None
    src       = 192.168.1.107
    dst       = 127.0.0.1
    \options   
    """
    entries[0].insert(0, int(default_ip_packet.version))
    entries[1].insert(0,5)#头长度默认为5*4=20字节，假设没有任何其他的内容
    entries[2].insert(0, hex(default_ip_packet.tos))
    entries[3].insert(0,20)#默认总长为20*4=80字节
    entries[4].insert(0, int(default_ip_packet.id))
    entries[5].insert(0, int(default_ip_packet.flags))
    entries[6].insert(0, int(default_ip_packet.frag))
    entries[7].insert(0, int(default_ip_packet.ttl))
    entries[8].insert(0, int(default_ip_packet.proto))
    entries[9]['state'] = NORMAL #打开操作权限
    entries[9].insert(0,"发送时自动计算")
    entries[9]['state'] = DISABLED#关闭操作权限

    entries[10].insert(0,default_ip_packet.src)
    default_ip_packet = IP(dst=entries[11].get())
    entries[11].insert(0,default_gateway)

def send_ip_packet_continuously(entries, send_packet_button):
    """
    连续发送IP包
    :param entries: 待发送的条目，即输入框内目前的值
    :param send_packet_button: 触发按钮
    :return:
    """
    if send_packet_button['text'] == '连续发送':
        ip_version = int (entries[0].get())
        ip_ihl = int (entries[1].get())
        ip_tos = int(entries[2].get(), 16)#16进制
        ip_len = int(entries[3].get())
        ip_id = int(entries[4].get())
        ip_flags = int(entries[5].get())
        ip_frag = int(entries[6].get())
        ip_ttl = int(entries[7].get())
        ip_proto = int(entries[8].get())
        ip_src = entries[10].get()
        ip_dst = entries[11].get()

        packet_sending = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id,
                            frag=ip_frag, flags=ip_flags, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)
        packet_sending = IP(raw(packet_sending)) #转化为bytes流串
        entries[9]['state'] = NORMAL  # 重新激活
        entries[9].delete(0, END)
        entries[9].insert(0, hex(packet_sending.chksum))
        entries[9]['state'] = DISABLED  # 不可操作
        #开线程 发包
        sending = threading.Thread(target=send_packet_continously,args=(packet_sending,))
        sending.setDaemon(True)
        sending.start()
        # 开启线程后，禁用导航树
        toggle_protocols_tree_state()
        # 将发送按钮切换为停止按钮
        send_packet_button['text'] = '停止'
    else:#如果是按钮”停止“，则停止发送
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '连续发送'

def send_ip_packet_once(entries):
    """
    发送一次IP包
    :param entries: 传入输入框内的目前的输入值
    :return:
    """
    ip_version = int(entries[0].get())
    ip_ihl = int(entries[1].get())
    ip_tos = int(entries[2].get(), 16)  # 16进制
    ip_len = int(entries[3].get())
    ip_id = int(entries[4].get())
    ip_flags = int(entries[5].get())
    ip_frag = int(entries[6].get())
    ip_ttl = int(entries[7].get())
    ip_proto = int(entries[8].get())
    ip_src = entries[10].get()
    ip_dst = entries[11].get()

    packet_sending = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id,
                        frag=ip_frag, flags=ip_flags, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)
    packet_sending = IP(raw(packet_sending))  # 转化为bytes流串
    entries[9]['state'] = NORMAL  # 重新激活
    entries[9].delete(0, END)
    entries[9].insert(0, hex(packet_sending.chksum))#checksum可以自动计算校验和
    entries[9]['state'] = DISABLED  # 不可操作
    #只发送一次
    send_packet_once(packet_sending)

#------------------------------------------------------------
# TCP SEND MODULE
#------------------------------------------------------------
def create_tcp_sender():
    """
    生成TCP包编辑器
    :return:
    """
    #pass
    """
    ###[ TCP ]### 一共8项需要构建
    sport = ftp_data
    dport = http
    seq = 0
    ack = 0
    dataofs = None
    reserved = 0 #保留位，entry不需要构建
    flags = S
    window = 8192
    chksum = None
    urgptr = 0 #紧急指针，默认值为0
    options = []
    """
    tcp_head ='源端口：','目的端口：','序号：','确认号：','数据偏移：',\
              '标志位：','窗口：','TCP校验和：','紧急指针','IP版本：',\
              '头长度：','服务类型：','总长度：','标识：','标志(0-2)DF,MF：',\
              '分段偏移量:','生存期:','上层协议:','头校验和:','源IP地址:',\
              '目的IP地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, tcp_head)
    send_packet_button ,reset_buttun,default_packet_button,\
    send_packet_once_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送IP包
    tk.bind('<Return>', (lambda event: send_tcp_packet_once(entries)))  # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送IP包
    # 为"重置"按钮的单击事件编写事件响应代码，清除所有字段
    # 为"默认值"按钮的单击事件编写事件响应代码，填入IP包默认字段
    # <Button-1>代表鼠标左键单击
    send_packet_button.bind('<Button-1>', (lambda event: send_tcp_packet_continuously(entries, send_packet_button)))
    reset_buttun.bind('<Button-1>',(lambda event:clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_tcp_packet(entries)))
    send_packet_once_button.bind('<Button-1>',(lambda event: send_tcp_packet_once(entries)))

def create_default_tcp_packet(entries):
    """
     在协议字段编辑框中填入默认TCP包的字段值
     :param entries: 协议字段编辑框列表
     :return:
    """
    clear_protocol_editor(entries)
    default_tcp_packet = IP()/TCP()
    entries[0].insert(0, int(default_tcp_packet.sport))
    entries[1].insert(0, int(default_tcp_packet.dport))
    entries[2].insert(0, int(default_tcp_packet.seq))
    entries[3].insert(0, int(default_tcp_packet.ack))
    entries[4].insert(0, str(default_tcp_packet.dataofs))
    entries[5].insert(0, 'S')
    entries[6].insert(0, int(default_tcp_packet.window))
    entries[7]['state'] = NORMAL # 可操作
    entries[7].insert(0, "单机发送时自动计算")
    entries[7]['state'] = DISABLED  # 不可操作
    entries[8].insert(0, int(default_tcp_packet.urgptr))
    entries[9].insert(0, int(default_tcp_packet.version))
    entries[10].insert(0, 5)
    entries[11].insert(0, hex(default_tcp_packet.tos))
    entries[12].insert(0, 20)
    entries[13].insert(0, int(default_tcp_packet.id))
    entries[14].insert(0, int(default_tcp_packet.flags))
    entries[15].insert(0, int(default_tcp_packet.frag))
    entries[16].insert(0, int(default_tcp_packet.ttl))
    entries[17].insert(0, int(default_tcp_packet.proto))
    entries[18]['state'] = NORMAL # 可操作
    entries[18].insert(0, "单机发送时自动计算")
    entries[18]['state'] = DISABLED  # 不可操作
    # 目标IP地址设成本地默认网关
    entries[20].insert(0, default_gateway)
    default_ip_packet = IP(dst=entries[11].get())#可以省略
    entries[19].insert(0, default_ip_packet.src)

def send_tcp_packet_continuously(entries, send_packet_button):
    """
    连续发TCP包
    :param entries:待发送的条目，用于构造包
    :param send_packet_button:
    :return:
    """
    if send_packet_button['text'] == '连续发送':
        tcp_sport = int(entries[0].get())
        tcp_dport = int(entries[1].get())
        tcp_seq = int(entries[2].get())
        tcp_ack = int(entries[3].get())
        if entries[4].get() != 'None':
            tcp_dataofs = int(entries[4].get())
        tcp_flags = str(entries[5].get())
        tcp_window = int(entries[6].get())
        tcp=TCP(sport=tcp_sport,dport=tcp_dport,seq=tcp_seq,ack=tcp_ack,flags=tcp_flags,window=tcp_window)

        if entries[4].get() != 'None':
            tcp.dataofs = tcp_dataofs
        #tcp.show()
        #ip_urgptr = int(entries[8].get())
        ip_version = int(entries[9].get())
        ip_ihl = int(entries[10].get())
        ip_tos = int(entries[11].get(), 16)
        #ip_len = int(entries[12].get()) 这里出错了，不应该人为指定 ip包大小，而是应该自动生成
        ip_id = int(entries[13].get())
        ip_flags = int(entries[14].get())
        ip_frag = int(entries[15].get())
        ip_ttl = int(entries[16].get())
        ip_proto = int(entries[17].get())
        ip_src = entries[19].get()
        ip_dst = entries[20].get()
        ip= IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, id=ip_id,
                            frag=ip_frag, flags=ip_flags, ttl=ip_ttl,src=ip_src, dst=ip_dst,proto = ip_proto)
        raw_packet=raw(ip/tcp)
        packet_to_send=IP(raw_packet)
        packet_to_send.show()
        #packet_to_send = IP(raw(packet_to_send))
        #tcp校验和
        #tcp=TCP(raw_packet[20:])
        tcp=packet_to_send[TCP]
        entries[7]['state'] = NORMAL  # 重新激活
        entries[7].delete(0, END)
        entries[7].insert(0, hex(tcp.chksum))
        entries[7]['state'] = DISABLED  # 不可操作
        #ip首部校验和
        entries[18]['state'] = NORMAL  # 重新激活
        entries[18].delete(0, END)
        entries[18].insert(0, hex(packet_to_send.chksum))
        entries[18]['state'] = DISABLED  # 不可操作
        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet_continously, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '连续发送'

def send_tcp_packet_once(entries):
    """
    发送一次TCP包
    :param entries: 待发送的条目，用于构造TCP包
    :return:
    """
    tcp_sport = int(entries[0].get())
    tcp_dport = int(entries[1].get())
    tcp_seq = int(entries[2].get())
    tcp_ack = int(entries[3].get())
    if entries[4].get() != 'None':
        tcp_dataofs = int(entries[4].get())
    tcp_flags = str(entries[5].get())
    tcp_window = int(entries[6].get())
    tcp = TCP(sport=tcp_sport, dport=tcp_dport, seq=tcp_seq, ack=tcp_ack, flags=tcp_flags, window=tcp_window)

    if entries[4].get() != 'None':
        tcp.dataofs = tcp_dataofs
    #tcp.show()
    # ip_urgptr = int(entries[8].get())
    ip_version = int(entries[9].get())
    ip_ihl = int(entries[10].get())
    ip_tos = int(entries[11].get(), 16)
    # ip_len = int(entries[12].get()) 这里出错了，不应该人为指定 ip包大小，而是应该自动生成
    ip_id = int(entries[13].get())
    ip_flags = int(entries[14].get())
    ip_frag = int(entries[15].get())
    ip_ttl = int(entries[16].get())
    ip_proto = int(entries[17].get())
    ip_src = entries[19].get()
    ip_dst = entries[20].get()
    ip = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, id=ip_id,
            frag=ip_frag, flags=ip_flags, ttl=ip_ttl, src=ip_src, dst=ip_dst, proto=ip_proto)
    raw_packet = raw(ip / tcp)
    packet_to_send = IP(raw_packet)
    packet_to_send.show()
    # packet_to_send = IP(raw(packet_to_send))
    # tcp校验和
    # tcp=TCP(raw_packet[20:])
    tcp = packet_to_send[TCP]
    entries[7]['state'] = NORMAL  # 重新激活
    entries[7].delete(0, END)
    entries[7].insert(0, hex(tcp.chksum))
    entries[7]['state'] = DISABLED  # 不可操作
    # ip首部校验和
    entries[18]['state'] = NORMAL  # 重新激活
    entries[18].delete(0, END)
    entries[18].insert(0, hex(packet_to_send.chksum))
    entries[18]['state'] = DISABLED  # 不可操作
    send_packet_once(packet_to_send)
#------------------------------------------------------------
# UDP SEND MODULE
#------------------------------------------------------------
def create_udp_sender():
    """
    创建UDP包编辑器
    :return: None
    """
    # UDP帧编辑区
    udp_head = '源端口','目的端口','长度(最小值为8)','检验和',\
               'IP协议的版本：', '首部长度：', '区分服务：','标识：', '标志(0-2)DF,MF：',\
               '片偏移：', '生存时间：','首部校验和：', '源IP地址：', '目的IP地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, udp_head)
    send_packet_button, reset_buttun, default_packet_button, \
    send_packet_once_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送UDP包
    tk.bind('<Return>', (lambda event: send_udp_packet_once(entries)))  # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送UDP包
    # 为"重置"按钮的单击事件编写事件响应代码，清除所有字段
    # 为"默认值"按钮的单击事件编写事件响应代码，填入UDP包默认字段
    # <Button-1>代表鼠标左键单击
    send_packet_button.bind('<Button-1>', (lambda event: send_udp_packet_continuously(entries, send_packet_button)))
    reset_buttun.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_udp_packet(entries)))
    send_packet_once_button.bind('<Button-1>', (lambda event: send_udp_packet_once(entries)))

def create_default_udp_packet(entries):
    """
    在协议字段编辑框中填入默认UDP包的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_udp_packet = IP()/UDP()
    entries[0].insert(0, int(default_udp_packet.sport))
    entries[1].insert(0, int(default_udp_packet.dport))
    entries[2].insert(0,8)
    entries[3]['state'] = NORMAL # 可操作
    entries[3].insert(0, "单机发送时自动计算")
    entries[3]['state'] = DISABLED  # 不可操作

    entries[4].insert(0, int(default_udp_packet.version))
    entries[5].insert(0, 5)
    entries[6].insert(0, hex(default_udp_packet.tos))
    entries[7].insert(0, int(default_udp_packet.id))
    entries[8].insert(0, int(default_udp_packet.flags))
    entries[9].insert(0, int(default_udp_packet.frag))
    entries[10].insert(0, int(default_udp_packet.ttl))
    entries[11]['state'] = NORMAL # 可操作
    entries[11].insert(0, "单机发送时自动计算")
    entries[11]['state'] = DISABLED  # 不可操作
    # 目标IP地址设成本地默认网关
    entries[13].insert(0, default_gateway)
    default_ip_packet = IP(dst=entries[13].get())#可以省略
    entries[12].insert(0, default_ip_packet.src)

def send_udp_packet_continuously(entries, send_packet_button):
    """
    构造、发UDP包
    :param entries:待构造成UDP包的条目
    :param send_packet_button:发送按钮状态
    :return:
    """
    if send_packet_button['text'] == '连续发送':
        udp_sport = int(entries[0].get())
        udp_dport = int(entries[1].get())
        udp_len = int(entries[2].get())
        udp=UDP(sport=udp_sport,dport=udp_dport,len=udp_len)

        ip_version = int(entries[4].get())
        ip_ihl = int(entries[5].get())
        ip_tos = int(entries[6].get(), 16)
        ip_id = int(entries[7].get())
        ip_flags = int(entries[8].get())
        ip_frag = int(entries[9].get())
        ip_ttl = int(entries[10].get())
        ip_src = entries[12].get()
        ip_dst = entries[13].get()
        ip= IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, id=ip_id,
                            frag=ip_frag, flags=ip_flags, ttl=ip_ttl,src=ip_src, dst=ip_dst)
        raw_packet=raw(ip/udp)
        packet_to_send=IP(raw_packet)
        packet_to_send.show()
        udp=packet_to_send[UDP]
        entries[3]['state'] = NORMAL  # 重新激活
        entries[3].delete(0, END)
        entries[3].insert(0, hex(udp.chksum))
        entries[3]['state'] = DISABLED  # 不可操作
        #ip首部校验和
        entries[11]['state'] = NORMAL  # 重新激活
        entries[11].delete(0, END)
        entries[11].insert(0, hex(packet_to_send.chksum))
        entries[11]['state'] = DISABLED  # 不可操作
        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet_continously, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '连续发送'

def send_udp_packet_once(entries):
    """
    构造并发送一次UDP包
    :param entries: 待发送的条目
    :return:
    """
    udp_sport = int(entries[0].get())
    udp_dport = int(entries[1].get())
    udp_len = int(entries[2].get())
    udp = UDP(sport=udp_sport, dport=udp_dport, len=udp_len)

    ip_version = int(entries[4].get())
    ip_ihl = int(entries[5].get())
    ip_tos = int(entries[6].get(), 16)
    ip_id = int(entries[7].get())
    ip_flags = int(entries[8].get())
    ip_frag = int(entries[9].get())
    ip_ttl = int(entries[10].get())
    ip_src = entries[12].get()
    ip_dst = entries[13].get()
    ip = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, id=ip_id,
            frag=ip_frag, flags=ip_flags, ttl=ip_ttl, src=ip_src, dst=ip_dst)
    raw_packet = raw(ip / udp)
    packet_to_send = IP(raw_packet)
    packet_to_send.show()
    udp = packet_to_send[UDP]
    entries[3]['state'] = NORMAL  # 重新激活
    entries[3].delete(0, END)
    entries[3].insert(0, hex(udp.chksum))
    entries[3]['state'] = DISABLED  # 不可操作
    # ip首部校验和
    entries[11]['state'] = NORMAL  # 重新激活
    entries[11].delete(0, END)
    entries[11].insert(0, hex(packet_to_send.chksum))
    entries[11]['state'] = DISABLED  # 不可操作
    send_packet_once(packet_to_send)
#------------------------------------------------------------
# ICMP SEND MODULE
#------------------------------------------------------------
def create_icmp_sender():
    """
    生成ICMP包编辑器
    :return: None
    """
    # ICMP包编辑区
    icmp_fields = 'IP版本：','头长度：','服务类型：','总长度：','标识：',\
                  '标志(0-2)DF,MF：','分段偏移量:','生存期:','上层协议:','头校验和:',\
                  '源IP地址:','目的IP地址：',\
                  'ICMP类型','ICMP代码','校验和','标识符','序列号'

    entries = create_protocol_editor(protocol_editor_panedwindow, icmp_fields)
    send_packet_button, reset_button, default_packet_button,send_packet_once_button \
        = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送ARP包
    tk.bind('<Return>', (lambda event: send_icmp_packet_once(entries)))  # <Return>代表回车键
    # 为"连续发送"按钮的单击事件编写事件响应代码，发送ICMP包
    # 为"重置"按钮的单击事件编写事件响应代码，清除所有字段
    # 为"默认值"按钮的单击事件编写事件响应代码，填入ICMP包默认字段
    # 为"发送"按钮的单击事件编写事件响应代码，发送ICMP包
    # <Button-1>代表鼠标左键单击
    send_packet_button.bind('<Button-1>', (lambda event: send_icmp_packet_continuously(entries, send_packet_button)))
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_icmp_packet(entries)))
    send_packet_once_button.bind('<Button-1>', (lambda event: send_icmp_packet_once(entries)))

def create_default_icmp_packet(entries):
    """
     在协议字段编辑框中填入默认ICMP包的字段值
     :param entries: 协议字段编辑框列表
     :return: None
    """
    clear_protocol_editor(entries)
    default_ip_packet = IP()/ICMP()
    default_ip_packet.show()
    entries[0].insert(0, int(default_ip_packet.version))
    entries[1].insert(0, 5)  # 头长度默认为5*4=20字节，假设没有任何其他的内容
    entries[2].insert(0, hex(default_ip_packet.tos))
    entries[3].insert(0, 28)  # 多次尝试后发现这个长度合适，我也不知道为啥hhh
    entries[4].insert(0, int(default_ip_packet.id))
    entries[5].insert(0, int(default_ip_packet.flags))
    entries[6].insert(0, int(default_ip_packet.frag))
    entries[7].insert(0, int(default_ip_packet.ttl))
    entries[8].insert(0, int(default_ip_packet.proto))
    entries[9]['state'] = NORMAL  # 打开操作权限
    entries[9].insert(0, "发送时自动计算")
    entries[9]['state'] = DISABLED  # 关闭操作权限

    entries[10].insert(0, default_ip_packet.src)
    #default_ip_packet = IP(dst=entries[11].get())
    entries[11].insert(0, default_gateway)

    entries[12].insert(0, 8)
    entries[13].insert(0, 0)
    #entries[14].insert(0, int(default_ip_packet.flags))
    entries[15].insert(0, 0)
    entries[16].insert(0, default_ip_packet.seq)
   # entries[17].insert(0, int(default_ip_packet.proto))
    entries[14]['state'] = NORMAL # 可操作
    entries[14].insert(0, "单机发送时自动计算")
    entries[14]['state'] = DISABLED  # 不可操作

def send_icmp_packet_continuously(entries, send_packet_button):
    """
    发送ICMP包
    :param entries: 待发送的条目
    :param send_packet_button: 触发按钮
    :return:
    """
    if send_packet_button['text'] == '连续发送':
        ip_version = int (entries[0].get())
        ip_ihl = int (entries[1].get())
        ip_tos = int(entries[2].get(), 16)#16进制
        ip_len = int(entries[3].get())
        ip_id = int(entries[4].get())
        ip_flags = int(entries[5].get())
        ip_frag = int(entries[6].get())
        ip_ttl = int(entries[7].get())
        ip_proto = int(entries[8].get())
        ip_chksum = 0
        ip_src = entries[10].get()
        ip_dst = entries[11].get()

        icmp_type = int(entries[12].get())
        icmp_code = int(entries[13].get())
        icmp_id = int(entries[15].get())
        icmp_seq = int(entries[16].get())

        #packet_sending_ip = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id,
         #                   frag=ip_frag, flags=ip_flags, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst,
           #                 )
        packet_sending_icmp=ICMP(type = icmp_type,code = icmp_code ,id=icmp_id,seq = icmp_seq)
        packet_sending = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id,chksum = ip_chksum,
                            frag=ip_frag, flags=ip_flags, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst,)\
                         /ICMP(raw(packet_sending_icmp))
        packet_sending.show()
        entries[9]['state'] = NORMAL  # 重新激活
        entries[9].delete(0, END)
        entries[9].insert(0, 0)
        entries[9]['state'] = DISABLED  # 不可操作
        entries[14]['state'] = NORMAL  # 重新激活
        entries[14].delete(0, END)
        entries[14].insert(0, hex(packet_sending[1].chksum))
        entries[14]['state'] = DISABLED  # 不可操作
        #开线程 发包
        sending = threading.Thread(target=send_packet_continously,args=(packet_sending,))
        sending.setDaemon(True)
        sending.start()
        # 开启线程后，禁用导航树
        toggle_protocols_tree_state()
        # 将发送按钮切换为停止按钮
        send_packet_button['text'] = '停止'
    else:#如果是按钮”停止“，则停止发送
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '连续发送'

def send_icmp_packet_once(entries):
    """
    构造、发送ICMP包
    :param entries: 待发送的条目
    :return:
    """
    ip_version = int(entries[0].get())
    ip_ihl = int(entries[1].get())
    ip_tos = int(entries[2].get(), 16)  # 16进制
    ip_len = int(entries[3].get())
    ip_id = int(entries[4].get())
    ip_flags = int(entries[5].get())
    ip_frag = int(entries[6].get())
    ip_ttl = int(entries[7].get())
    ip_proto = int(entries[8].get())
    ip_chksum = 0
    ip_src = entries[10].get()
    ip_dst = entries[11].get()

    icmp_type = int(entries[12].get())
    icmp_code = int(entries[13].get())
    icmp_id = int(entries[15].get())
    icmp_seq = int(entries[16].get())

    # packet_sending_ip = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id,
    #                   frag=ip_frag, flags=ip_flags, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst,
    #                 )
    packet_sending_icmp = ICMP(type=icmp_type, code=icmp_code, id=icmp_id, seq=icmp_seq)
    packet_sending = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id, chksum=ip_chksum,
                        frag=ip_frag, flags=ip_flags, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst, ) \
                     / ICMP(raw(packet_sending_icmp))
    packet_sending.show()
    entries[9]['state'] = NORMAL  # 重新激活
    entries[9].delete(0, END)
    entries[9].insert(0, 0)
    entries[9]['state'] = DISABLED  # 不可操作
    entries[14]['state'] = NORMAL  # 重新激活
    entries[14].delete(0, END)
    entries[14].insert(0, hex(packet_sending[1].chksum))
    entries[14]['state'] = DISABLED  # 不可操作
    send_packet_once(packet_sending)
#------------------------------------------------------------
# ARP SEND MODULE
#------------------------------------------------------------
def create_arp_sender():
    """
    生成ARP包编辑器
    :return: None
    """
    # ARP包编辑区
    arp_fields = '硬件类型：', '协议类型：', '硬件地址长度：', '协议长度：', '操作码：', \
                 '源MAC地址：', '源IP地址：', '目标MAC地址：', '目标IP地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, arp_fields)
    send_packet_button, reset_button, default_packet_button,send_packet_once_button \
        = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送ARP包
    tk.bind('<Return>', (lambda event: send_udp_packet_once(entries)))  # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送ARP包
    # 为"重置"按钮的单击事件编写事件响应代码，清除所有字段
    # 为"默认值"按钮的单击事件编写事件响应代码，填入ARP包默认字段
    # <Button-1>代表鼠标左键单击
    send_packet_button.bind('<Button-1>', (lambda event: send_arp_packet_continuously(entries, send_packet_button)))
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    default_packet_button.bind('<Button-1>', (lambda event: create_default_arp_packet(entries)))
    send_packet_once_button.bind('<Button-1>', (lambda event: send_arp_packet_once(entries)))

def create_default_arp_packet(entries):
    """

    :param entries:
    :return:
    """
    """
    ###[ ARP ]### 
    hwtype    = 0x1 硬件类型
    ptype     = IPv4 协议类型
    hwlen     = None 硬件地址长度 6
    plen      = None 协议长度 4
    op        = who-has 操作类型
    hwsrc     = 4c:1d:96:50:a7:76 发送方MAC地址
    psrc      = 192.168.1.106 发送方 IP地址
    hwdst     = 00:00:00:00:00:00 接收方MAC地址
    pdst      = 0.0.0.0 接收方IP地址
    """
    clear_protocol_editor(entries)
    default_arp_packet = ARP()
    entries[0].insert(0, default_arp_packet.hwtype)
    entries[1].insert(0, hex(default_arp_packet.ptype))
    entries[2].insert(0, 6)
    entries[3].insert(0, 4)
    entries[4].insert(0, default_arp_packet.op)
    entries[5].insert(0, default_arp_packet.hwsrc)
    entries[6].insert(0, default_arp_packet.psrc)
    entries[7].insert(0, default_arp_packet.hwdst)
    # 目标IP地址设成本地默认网关
    entries[8].insert(0, default_gateway)

def send_arp_packet_continuously(entries, send_packet_button):
    """
    构造、并连续发送ARP包
    :param entries: 待发送的条目
    :param send_packet_button: 发送按钮状态
    :return:
    """
    if send_packet_button['text'] == '连续发送':
        arp_hwtype = int(entries[0].get())
        arp_ptype = int(entries[1].get(), 16)
        arp_hwlen = int(entries[2].get())
        arp_plen = int(entries[3].get())
        arp_op = int(entries[4].get())
        arp_hwsrc = entries[5].get()
        arp_psrc = entries[6].get()
        arp_hwdst = entries[7].get()
        arp_pdst = entries[8].get()
        packet_to_send = ARP(hwtype=arp_hwtype, ptype=arp_ptype, hwlen=arp_hwlen, plen=arp_plen,
                             op=arp_op, hwsrc=arp_hwsrc, psrc=arp_psrc, hwdst=arp_hwdst, pdst=arp_pdst)

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet_continously, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '连续发送'

def send_arp_packet_once(entries):
    """
    构造并发送一次ARP包
    :param entries: 待发送的条目
    :return:
    """
    arp_hwtype = int(entries[0].get())
    arp_ptype = int(entries[1].get(), 16)
    arp_hwlen = int(entries[2].get())
    arp_plen = int(entries[3].get())
    arp_op = int(entries[4].get())
    arp_hwsrc = entries[5].get()
    arp_psrc = entries[6].get()
    arp_hwdst = entries[7].get()
    arp_pdst = entries[8].get()
    packet_to_send = ARP(hwtype=arp_hwtype, ptype=arp_ptype, hwlen=arp_hwlen, plen=arp_plen,
                         op=arp_op, hwsrc=arp_hwsrc, psrc=arp_psrc, hwdst=arp_hwdst, pdst=arp_pdst)
    send_packet_once(packet_to_send)

#------------------------------------------------------------
# WELCOME PAGE
#------------------------------------------------------------
def create_welcome_page(root):
    welcome_string = '封面\n\n计算机通信网大作业\n网络发包器\n\n学号：518030910107\n姓名：梁昌友'
    Label(root, justify=CENTER, padx=10, pady=150, text=welcome_string,
          font=('楷书', '30', 'bold')).pack()
#------------------------------------------------------------
# ENTRANCE
#------------------------------------------------------------

if __name__ == '__main__':
    # 创建协议导航树并放到左右分隔窗体的左侧
    main_panedwindow.add(create_protocols_guide_tree())
    # 将协议编辑区窗体放到左右分隔窗体的右侧
    main_panedwindow.add(protocol_editor_panedwindow)
    # 创建欢迎界面
    #a = IP()/ICMP()
    #a.show()
    create_welcome_page(protocol_editor_panedwindow)
    main_panedwindow.pack(fill=BOTH, expand=1)#按添加的顺序排列组件
    # 启动消息处理
    tk.mainloop()