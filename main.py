# coding=utf-8

#----------------------------------------------------------
# import module:
# tkinter to make GUI
# scapy to make packet and send it out
#----------------------------------------------------------

import tkinter
from tkinter import *
from tkinter.constants import *
from tkinter.ttk import Treeview, Style

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


#---------------------------------------------------------
# initial basic frame of the GUI with tkinter
# we name it tk
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
# os.popen('route print').readlines() 打开了一个系统文件并读取了所有行，构成list ？
default_gateway = [a for a in os.popen('route print').readlines() if ' 0.0.0.0 ' in a][0].split()[-3]
# 用来终止数据包发送线程的线程事件
stop_sending = threading.Event()



#------------------------------------------------------------
# STRUCTURE MODULE
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
        row.pack(side=TOP, fill=X, padx=5, pady=5)
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
    send_packet_once_button = Button(bottom_buttons,width=20,text = "发送一次")


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
# all of the helper function will be declare here
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
    协议导航树里面单击协议后响应函数，打开相应协议的编辑器
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
        pass
    elif selected_item[0] == "UDP":
        pass
    elif selected_item[0] == "IP":
        #pass
        create_ip_sender()
    elif selected_item[0] == "ARP":
        pass
    elif selected_item[0] == "ICMP":
        pass
    elif selected_item[0] == "ARP":
        pass

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
    n = 0
    stop_sending.clear()

    #包大小，包协议类型获取
    packet_size = len(packet_sending)
    protocol_names =['TCP','UDP','IP','ICMP','ARP','Unkown']
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
    # 包大小，包协议类型获取
    packet_size = len(packet_sending)
    protocol_names = ['TCP', 'UDP', 'IP', 'ICMP', 'ARP', 'Unkown']
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
    # 为"发送"按钮的单击事件编写事件响应代码，发送IP包
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
    发送IP包
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
    entries[9].insert(0, hex(packet_sending.chksum))
    entries[9]['state'] = DISABLED  # 不可操作
    #只发送一次
    send_packet_once(packet_sending)
#------------------------------------------------------------
# TCP SEND MODULE
#------------------------------------------------------------

#------------------------------------------------------------
# UDP SEND MODULE
#------------------------------------------------------------

#------------------------------------------------------------
# ICMP SEND MODULE
#------------------------------------------------------------

#------------------------------------------------------------
# ARP SEND MODULE
#------------------------------------------------------------

#------------------------------------------------------------
# ENTRANCE
#------------------------------------------------------------

if __name__ == '__main__':
    # 创建协议导航树并放到左右分隔窗体的左侧
    main_panedwindow.add(create_protocols_guide_tree())
    # 将协议编辑区窗体放到左右分隔窗体的右侧
    main_panedwindow.add(protocol_editor_panedwindow)
    # 创建欢迎界面
    #create_welcome_page(protocol_editor_panedwindow)
    main_panedwindow.pack(fill=BOTH, expand=1)#按添加的顺序排列组件
    # 启动消息处理
    tk.mainloop()