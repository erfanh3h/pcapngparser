from __future__ import print_function
import argparse
import sys
import io
import re
import ctypes
from scapy.all import *
from struct import *
import time
import os.path
import wx
import time
from threading import Thread

import ctypes

def terminate_thread(thread):#baraye bastane Thread
    if not thread.isAlive():
        return
    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread.ident), exc)
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

class Panel(wx.Panel):
    def __init__(self,parent):
        wx.Panel.__init__(self,parent)
        self.log = wx.TextCtrl(self,pos=(350,60),size=(349,478),style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.state = 0;#Pause And Resume flag
        self.status = 1
        self.couter_all = 0
        self.counter_pack_all = 0
        self.clog=str(5000)#neshan dadan log bar asase in tedad packet dide shode
        self.BtnSearch = wx.Button(self,label="Search",pos=(0, 440),size=(175, 50))
        self.Bind(wx.EVT_BUTTON, self.Execute, self.BtnSearch)
        self.BtnPause = wx.Button(self, label="Pause", pos=(176, 440), size=(175, 50))
        self.Bind(wx.EVT_BUTTON, self.Pause, self.BtnPause)
        self.BtnPause.Disable()
        self.BtnAbout = wx.Button(self, label="About", pos=(0, 490), size=(175, 50))
        self.Bind(wx.EVT_BUTTON, self.About, self.BtnAbout)
        self.BtnExit = wx.Button(self, label="Exit", pos=(176, 490),size = (175,50))
        self.Bind(wx.EVT_BUTTON, self.Leave, self.BtnExit)
        self.lblifile = wx.StaticText(self, label="Input File :", pos=(20, 60))
        self.lblofile = wx.StaticText(self, label="Output File :", pos=(20, 110))
        self.lblprot = wx.StaticText(self, label="Protocol(s) :", pos=(20, 160))
        self.lblport = wx.StaticText(self, label="Port(s) :", pos=(20, 210))
        self.lblword = wx.StaticText(self, label="Word(s) :", pos=(20, 260))
        self.lblpack = wx.StaticText(self, label="Packet", pos=(300, 325))
        self.lbllog = wx.StaticText(self, label="Log Table", pos=(460, 30))
        font = wx.Font(18, wx.DECORATIVE, wx.ITALIC, wx.NORMAL)
        self.lbllog.SetFont(font)
        self.cslog = ['5000', '10000', '50000', '100000']
        self.Input = wx.TextCtrl(self, value="", pos=(120, 55), size=(140, -1))
        self.Output = wx.TextCtrl(self, value="", pos=(120, 105), size=(140, -1))
        self.Prot = wx.TextCtrl(self, value="", pos=(120, 155), size=(140, -1))
        self.Port = wx.TextCtrl(self, value="", pos=(120, 205), size=(140, -1))
        self.Word = wx.TextCtrl(self, value="", pos=(120, 255), size=(140, -1))
        self.slog = wx.RadioBox(self,label = "Log Every :",choices = self.cslog, majorDimension = 4, style = wx.RA_SPECIFY_COLS,pos=(20, 305))
        self.Bind(wx.EVT_RADIOBOX, self.setcount, self.slog)

    def search_port_f(self,pack,counter):
        b = counter
        sa = open(str(self.Port.Value))
        for s in sa:
            if pack.haslayer(TCP):
                if pack.getlayer(TCP).dport == int(s[0:(len(s) - 1)]) or pack.getlayer(TCP).sport == int(s[0:(len(s) - 1)]):
                    wrpcap(self.Output.Value, pack, append=True)
                    b+=1
                    return b
            elif pack.haslayer(UDP):
                if pack.getlayer(UDP).dport == int(s[0:(len(s) - 1)]) or pack.getlayer(UDP).sport == int(s[0:(len(s) - 1)]):
                    wrpcap(self.Output.Value, pack, append=True)
                    b += 1
                    return b
        return b

    def Pause(self,event):
        if self.state==0:
            self.state=1
            self.BtnPause.Label='Resume'
        elif self.state==1:
            self.BtnPause.Label = 'Pause'
            self.state =0
    
    def setcount(self,event):
        self.clog = event.GetString()

    def search_port(self,pack,counter):
        b = counter
        if pack.haslayer(TCP):
            if pack.getlayer(TCP).dport == int(self.Port.Value) or pack.getlayer(TCP).sport == int(self.Port.Value):
                wrpcap(self.Output.Value, pack, append=True)
                b += 1
                return b
        elif pack.haslayer(UDP):
            if pack.getlayer(UDP).dport == int(self.Port.Value) or pack.getlayer(UDP).dport == int(self.Port.Value):
                wrpcap(self.Output.Value, pack, append=True)
                b += 1
                return b
        return b

    def Execute(self,event):
        if(self.BtnSearch.Label=='Search'):
            self.BtnSearch.Label='Cancel'
            self.Input.Disable()
            self.Output.Disable()
            self.Prot.Disable()
            self.Port.Disable()
            self.Word.Disable()
            self.slog.Disable()
            self.BtnPause.Enable()
            self.startThread()
        elif (self.BtnSearch.Label == 'Cancel'):
            if self.msgbox("Are You Sure?","Stop"):
                self.BtnSearch.Label = 'Search'
                self.BtnPause.Disable()
                self.Input.Enable()
                self.Output.Enable()
                self.Prot.Enable()
                self.Port.Enable()
                self.Word.Enable()
                self.slog.Enable()
                terminate_thread(self.thread)

    def pcapng(self,name):
        start_time = time.time()
        counter = 0
        counter_pack = 0
        print(name)
        if name == '' or self.Output.Value == '':
            pass
        else:
            self.log.AppendText('Searching '+name+':\n')
            with PcapNgReader(str(name)) as packets:  # baz kardan file asli
                for pack in packets:  # barresi tak take pack ha
                    if self.status==1:
                        while self.state==1:
                            time.sleep(0.5)
                        if (str(self.Prot.Value)) != "" and (str(self.Word.Value)) != "" and (
                        str(self.Port.Value)) != "":  # vojood har se dastoor
                            va = counter  # jelogiri az tekrare bi mored
                            if os.path.exists((str(self.Prot.Value))) and os.path.exists(
                                    (str(self.Word.Value))) and os.path.exists(str(Port)):
                                sa = open((str(self.Prot.Value)))
                                sb = open((str(self.Word.Value)))
                                for a in sa:
                                    if pack.haslayer(a[0:(len(a) - 1)]):
                                        for s in sb:
                                            sch = re.findall(s[0:(len(s) - 1)], str(pack))
                                            if sch:
                                                counter = self.search_port_f(pack, counter)
                                                if va != counter:
                                                    break
                                    if va != counter:
                                        break
                            elif os.path.exists((str(self.Prot.Value))) and os.path.exists((str(self.Word.Value))):
                                sa = open((str(self.Prot.Value)))
                                sb = open((str(self.Word.Value)))
                                for a in sa:
                                    if pack.haslayer(a[0:(len(a) - 1)]):
                                        for s in sb:
                                            sch = re.findall(s[0:(len(s) - 1)], str(pack))
                                            if sch:
                                                counter = self.search_port(pack, counter)
                                                if va != counter:
                                                    break
                                    if va != counter:
                                        break
                            elif os.path.exists((str(self.Prot.Value))) and os.path.exists(str((str(self.Port.Value)))):
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                sa = open((str(self.Prot.Value)))
                                for a in sa:
                                    if pack.haslayer(a[0:(len(a) - 1)]) and sch:
                                        counter = self.search_port_f(pack, counter)
                                        if va != counter:
                                            break
                            elif os.path.exists((str(self.Word.Value))) and os.path.exists(str((str(self.Port.Value)))):
                                sa = open((str(self.Word.Value)))
                                for a in sa:
                                    sch = re.findall(a[0:(len(a) - 1)], str(pack))
                                    if pack.haslayer((str(self.Prot.Value))) and sch:
                                        counter = self.search_port_f(pack, counter)
                                        if va != counter:
                                            break
                            elif os.path.exists((str(self.Prot.Value))):
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                sa = open((str(self.Prot.Value)))
                                for s in sa:
                                    if pack.haslayer(s[0:(len(s) - 1)]) and sch:
                                        counter = self.search_port(pack, counter)
                                        if va != counter:
                                            break
                            elif os.path.exists((str(self.Word.Value))):
                                sa = open((str(self.Word.Value)))
                                for s in sa:
                                    sch = re.findall(s[0:(len(s) - 1)], str(pack))
                                    if pack.haslayer((str(self.Prot.Value))) and sch:
                                        counter = self.search_port(pack, counter)
                                        if va != counter:
                                            break
                            elif os.path.exists(str((str(self.Port.Value)))):
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                if sch and pack.haslayer((str(self.Prot.Value))):
                                    counter = self.search_port_f(pack, counter)
                            else:
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                if sch and pack.haslayer((str(self.Prot.Value))):
                                    counter = self.search_port(pack, counter)
                        elif ((str(self.Prot.Value)) != "" and (
                        str(self.Word.Value)) != ""):  # vojood do dastoor prot va word
                            fl = False  # aadame tekrar bi mored loghat mojood dar list
                            if (os.path.exists((str(self.Prot.Value))) and os.path.exists((str(self.Word.Value)))):
                                sa = open((str(self.Prot.Value)))
                                sb = open((str(self.Word.Value)))
                                for a in sa:
                                    if pack.haslayer(a[0:(len(a) - 1)]):
                                        for s in sb:
                                            sch = re.findall(s[0:(len(s) - 1)], str(pack))
                                            if sch:
                                                counter += 1
                                                wrpcap(self.Output.Value, pack, append=True)
                                                fl = True
                                                break
                                    if fl:
                                        fl = False
                                        break
                            elif os.path.exists((str(self.Prot.Value))):
                                sa = open((str(self.Prot.Value)))
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                for s in sa:
                                    if pack.haslayer(s[0:(len(s) - 1)]) and sch:
                                        counter += 1
                                        wrpcap(self.Output.Value, pack, append=True)
                                        break
                            elif os.path.exists((str(self.Word.Value))):
                                sa = open((str(self.Word.Value)))
                                for s in sa:
                                    sch = re.findall(s[0:(len(s) - 1)], str(pack))
                                    if sch and pack.haslayer((str(self.Prot.Value))):
                                        counter += 1
                                        wrpcap(self.Output.Value, pack, append=True)
                                        break
                            else:
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                if (pack.haslayer((str(self.Prot.Value))) and sch):
                                    counter += 1
                                    wrpcap(self.Output.Value, pack, append=True)
                        elif (str(self.Prot.Value)) != "" and (
                        str(self.Port.Value)) != "":  # vojood do dastoor (str(self.Prot.Value)) va port
                            va = counter
                            if (os.path.exists((str(self.Prot.Value))) and os.path.exists(str((str(self.Port.Value))))):
                                sa = open((str(self.Prot.Value)))
                                for a in sa:
                                    if pack.haslayer(a[0:(len(a) - 1)]):
                                        counter = self.search_port_f(pack, counter)
                                        if (va != counter):
                                            break
                            elif os.path.exists((str(self.Prot.Value))):
                                sa = open((str(self.Prot.Value)))
                                for s in sa:
                                    if pack.haslayer(s[0:(len(s) - 1)]):
                                        counter = self.search_port(pack, counter)
                                        if (va != counter):
                                            break
                            elif os.path.exists(str((str(self.Port.Value)))):
                                if pack.haslayer((str(self.Prot.Value))):
                                    counter = self.search_port_f(pack, counter)
                            else:
                                if pack.haslayer((str(self.Prot.Value))):
                                    counter = self.search_port(pack, counter)
                        elif (str(self.Port.Value)) != "" and (
                        str(self.Word.Value)) != "":  # vojood do dastoor port va word
                            vl = counter
                            if (os.path.exists((str(self.Word.Value))) and os.path.exists(str((str(self.Port.Value))))):
                                sa = open((str(self.Word.Value)))
                                sb = open((str(self.Port.Value)))
                                for a in sa:
                                    sch = re.findall(a[0:(len(a) - 1)], str(pack))
                                    if sch:
                                        for s in sb:
                                            counter = self.search_port_f(pack, counter)
                                            if (vl != counter):
                                                break
                                        if (vl != counter):
                                            break
                            elif os.path.exists((str(self.Word.Value))):
                                sa = open((str(self.Word.Value)))
                                for s in sa:
                                    sch = re.findall(s[0:(len(s) - 1)], str(pack))
                                    if sch:
                                        counter = self.search_port(pack, counter)
                                        if (vl != counter):
                                            break
                            elif os.path.exists(str((str(self.Port.Value)))):
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                if sch:
                                    counter = self.search_port_f(pack, counter)
                            else:
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                if sch:
                                    counter = self.search_port(pack, counter)
                        elif ((str(self.Prot.Value))) != "":  # vojood dastoor prot
                            if os.path.exists((str(self.Prot.Value))):  # File mode
                                sa = open((str(self.Prot.Value)))
                                for s in sa:
                                    if pack.haslayer(s[0:(len(s) - 1)]):
                                        counter += 1
                                        wrpcap(self.Output.Value, pack, append=True)
                                        break
                            else:  # (str(self.Prot.Value))ocol mode
                                if pack.haslayer((str(self.Prot.Value))):
                                    counter += 1
                                    wrpcap(self.Output.Value, pack, append=True)
                        elif ((str(self.Word.Value)) != ""):  # vojood dastoor word
                            if os.path.exists((str(self.Word.Value))):  # File mode
                                sa = open((str(self.Word.Value)))
                                for s in sa:
                                    sch = re.findall(s[0:(len(s) - 1)], str(pack))
                                    if sch:
                                        counter += 1
                                        wrpcap(self.Output.Value, pack, append=True)
                                        break
                            else:  # Word mode
                                sch = re.findall((str(self.Word.Value)), str(pack))
                                if sch:
                                    counter += 1
                                    wrpcap(self.Output.Value, pack, append=True)
                        elif ((str(self.Port.Value)) != ""):  # vojood dastoor port
                            if os.path.exists(str((str(self.Port.Value)))):  # FIle mode
                                counter = self.search_port_f(pack, counter)
                            else:  # Port mode
                                counter = self.search_port(pack, counter)
                        else:
                            exit()
                        counter_pack += 1
                        if counter_pack % int(self.clog) == 0:
                            self.log.AppendText('Found ' + str(counter) + ' from ' + str(counter_pack) + '\n')
                    else:
                        self.log.AppendText('Search Stoped!!\n')
                        return
                self.log.AppendText('Found ' + str(counter) + ' from ' + str(counter_pack)+ ' in '+str(int(time.time()-start_time))+ ' Second.\n')
                self.couter_all+=counter
                self.counter_pack_all+=counter_pack

                time.sleep(1)
            #self.log.AppendText('Not A Valid File!!!')

    def About(self,event):
        dialog = wx.MessageDialog(self, 'PCAPNG Parser\nVersion 1.0', 'PCAPNG', wx.OK_DEFAULT)
        dialog.ShowModal()
        dialog.Destroy()

    def msgbox(self,s,t):
        dialog = wx.MessageDialog(self, s, t, wx.CANCEL)
        val = dialog.ShowModal()
        if val == wx.ID_OK:
            return True
        dialog.Destroy()
        return False

    def Leave(self,event):
        if self.msgbox("Are You Sure?","Exit"):
            exit()

    def threadMethod(self):
        self.log.Clear()
        try:
            os.remove(self.Output.Value)  # hazf file maghsad dar soorate vojood
        except:
            pass
        if os.path.isdir(self.Input.Value):
            lsts = os.listdir(str(self.Input.Value))
            for s in lsts:
                self.pcapng(str(self.Input.Value)+'/'+s)
        elif os.path.exists(self.Input.Value):
            self.pcapng(self.Input.Value)
        self.BtnSearch.Label = "Search"
        self.BtnPause.Disable()
        self.Input.Enable()
        self.Output.Enable()
        self.Prot.Enable()
        self.Port.Enable()
        self.Word.Enable()
        self.slog.Enable()
        #self.msgboxn("Found"+str(self.couter_all)+" Packet From "+str(self.counter_pack_all),"Report")
    def startThread(self):
        self.thread = Thread(target=self.threadMethod)
        self.thread.daemon = True
        self.thread.start()

class Frame(wx.Frame):
    def __init__(self, filename='PcapNG'):
        super(Frame, self).__init__(None, size=(700,600),style=wx.FIXED_LENGTH,title=filename)
        self.panel = Panel(self)
        self.filename = filename
        self.dirname = '.'
        self.CreateStatusBar()

def main():
    app = wx.App(False)
    frame = Frame()
    frame.Show()
    app.MainLoop()

if __name__=='__main__':
    main()