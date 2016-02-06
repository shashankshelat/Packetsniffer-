'''
Created on Apr 18, 2015

@author: Archana
'''

# import first_try
# import arp
import Tkinter
from Tkinter import *
from Tkinter import Scrollbar
import ttk
from ttk import *
from ScrolledText import ScrolledText
import tktable
import tkMessageBox
import time

window_width = 700
window_height = 400
rec = 0

def apply_program(var):
    #Code here
    print "You selected " + str(var.get())


def create_frame1():
    root.title("Frame 1")

    frame1 = Frame(root, width = window_width, height = window_height, relief = "sunken")
    frame1.grid(column = 0, row = 0, padx = "20px", pady = "5px", sticky = (Tkinter.W, Tkinter.N, Tkinter.E))
    
    first_window_label = Label(frame1, text="Choose one of the following interfaces:")
    first_window_label.grid(column = 0, row = 1, pady = "10px", padx = "10px", sticky = (Tkinter.N))
    
    listBox1 = Listbox(frame1, relief ="groove", selectmode ="browse", height ="5", yscrollcommand = Scrollbar(root).set)
    listBox1.insert(1, "LAN")
    listBox1.insert(2, "WiFi")
    listBox1.insert(3, "Virtualhost")
    listBox1.grid(column = 0, row = 2, pady = "5px", sticky = (Tkinter.N))
    
    first_window_quit_button = Tkinter.Button(frame1, text = "Exit", command = exit_program)
    first_window_quit_button.grid(column = 0, row = 3, padx = "5px", pady = "5px", sticky = (Tkinter.N))
    first_window_next_button = Tkinter.Button(frame1, text = "Next", command = create_frame2)
    first_window_next_button.grid(column = 1, row = 3, padx = "5px", pady = "5px", sticky = (Tkinter.N))
    
def create_frame2():
    root.title("Frame 2")
   
    frame1.destroy()
    
    frame2 = Frame(root, width = window_width, height = window_height, relief = "sunken")
    frame2.grid(column = 0, row = 0, padx = "20px", pady = "5px", sticky = (Tkinter.W+N+E))
    
    menubar = Menu(root)
    filemenu = Menu(menubar, tearoff=0)
    filemenu.add_command(label="New")
    filemenu.add_command(label="Open")
    filemenu.add_command(label="Save")
    filemenu.add_command(label="Save as...")
    filemenu.add_command(label="Close")
    
    filemenu.add_separator()
    
    filemenu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=filemenu)
    editmenu = Menu(menubar, tearoff=0)
    editmenu.add_command(label="Undo")
    
    editmenu.add_separator()
    
    editmenu.add_command(label="Cut")
    editmenu.add_command(label="Copy")
    editmenu.add_command(label="Paste")
    editmenu.add_command(label="Delete")
    editmenu.add_command(label="Select All")
    
    menubar.add_cascade(label="Edit", menu=editmenu)
    analyzemenu = Menu(menubar, tearoff=0)
    analyzemenu.add_command(label="Graph", command = display_graph)
#     analyzemenu.add_command(label="About...")
    menubar.add_cascade(label="Analyze", menu=analyzemenu)
    
    helpmenu = Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Help Index")
    helpmenu.add_command(label="About...")
    menubar.add_cascade(label="Help", menu=helpmenu)
    root.config(menu=menubar)
    
    var = StringVar()
    var.set(1)
    R1 = Radiobutton(frame2, text="TCP", variable=var, value=1)
    R1.grid(column = 0, row =1, sticky = (Tkinter.W))

    R2 = Radiobutton(frame2, text="IP", variable=var, value=2)
    R2.grid(column =1, row = 1, sticky = (Tkinter.W))

    R3 = Radiobutton(frame2, text="ICMP", variable=var, value=3)
    R3.grid(column = 0, row = 2, sticky = (Tkinter.W))
    
    R4 = Radiobutton(frame2, text="ARP", variable=var, value=4)
    R4.grid(column = 1, row = 2, sticky = (Tkinter.W))
    
    apply_button = Button(frame2, text = "Apply")
    apply_button.grid(column = 0, row = 3, sticky = (Tkinter.W), padx = "5px", pady = "5px", command = apply_program(var))
    
    start_time = time.time()
    
    headers = ["No.", "Source", "Time", "Destination", "Protocol", "Length"]
    rows = []
    col = []
    j= 0
    for i in range(4,5):
        for k in headers:
            e = Entry(frame2, justify = "center")
            e.grid(row=i, column= j, sticky=N+S+E+W)
            e.insert(END, k)
            j = j+1
            
#     values = [autoIncrement(), str(s_addr), time.time()- start_time,  str(d_addr), str(protocol), str(tcph_length)]
    j = 0  
    for i in range(5,15):
        for v in range(6):
            e = Entry(frame2, justify = "center")
            e.grid(row=i, column= v, sticky=N+S+E+W)
            e.insert(END, "")

            
            
    text2 = ScrolledText(frame2, width = 50, height = 10)
    text2.insert(0.0, "frame details here")
    text2.grid(columnspan = 2, sticky = (Tkinter.W+E+N), padx = "5px", pady = "5px")
    
    
def exit_program():
    root.destroy()

def clear_entry(entry1):
    entry1.focus_set()
    entry1.delete(0, END)

def display_graph():
    top = Toplevel()
    top.title("Graphical Representation")
    
    button = Button(top, text="Dismiss", command=top.destroy)
    button.pack()
    
##############################
#    Main Program            #
##############################

root = Tk()
root.title("Our Packet Sniffer")

frame1 = Frame(root, width = window_width, height = window_height, relief = "sunken")
frame1.grid(column=0, row=0, padx="20px", pady="5px", sticky=(Tkinter.W, Tkinter.N, Tkinter.E))

frame2 = Frame(root, width = window_width, height = window_height, relief = "sunken")
frame2.grid(column=0, row=0, padx="20px", pady="5px", sticky=(Tkinter.W, Tkinter.N, Tkinter.E))



create_frame1()


root.mainloop()