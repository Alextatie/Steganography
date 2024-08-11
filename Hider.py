from tkinter import *
from tkinter import filedialog
import tkinter as tk
from PIL import Image,ImageTk
import os
from stegano import lsb
import ctypes as ct
from cryptography.fernet import Fernet


def open_image():
    global filename

    filename=filedialog.askopenfilename(initialdir=os.getcwd()+"/Images",
                                        title="Select Image",
                                        filetype=(("All files","*"),
                                                  ("JPG files","*.jpg"),
                                                  ("JPEG files","*.jpeg"),
                                                  ("PNG files","*.png")))
    try:
        img = Image.open(filename)
        while img.width>392:
            img = img.resize((int(img.width*0.99), int(img.height*0.99)))
        while img.height > 352:
            img = img.resize((int(img.width * 0.99), int(img.height * 0.99)))
        img = ImageTk.PhotoImage(img)
        l1.configure(image=img, width=392, height=352)
        l1.image = img
        t1.delete(1.0, END)
        t1.insert(END, "")
    except:
        print("File picker closed.")

def save_image():
    try:
        secret.save("Images/Output/secret.png")
    except:
        print("No image is open.")

def hide():
    try:
        global secret
        message = t1.get(1.0,END)
        t1.delete(1.0, END)
        t1.insert(END, "")
        #print("message: ",message,"\n")
        secret=lsb.hide(str(filename),message)
        #print("secret: ", secret, "\n")
    except:
        print("No image is open.")

def show():
    try:
        global decrypted_message
        decrypted_message = lsb.reveal(filename)
        #print("decrypted message: ", decrypted_message)
        t1.delete(1.0, END)
        t1.insert(END, decrypted_message)
    except:
        t1.delete(1.0, END)
        t1.insert(END, "")

def encrypt():
    def generate():
        try:
            global key
            global encrypted_message
            key = Fernet.generate_key()
            te.delete(1.0, END)
            te.insert(END, key)
            message = t1.get(1.0, END)
            #print("Decrypted message:",message)
            #print("key:",key)
            fernet = Fernet(key)
            encrypted_message = fernet.encrypt(message.encode())
            #print("Encrypted Message:", encrypted_message)
            t1.delete(1.0, END)
            t1.insert(END, encrypted_message)
        except:
            print("Failed to generate", "\n")

    def savekey():
        try:
            #print(key)
            open('Images/Output/keys.txt', 'a').write(key.decode()+"\n")
        except:
            print("Failed to save", "\n")

    try:
        Password = Toplevel(app)
        Password.geometry("430x72")
        Password.resizable(False, False)
        Password.configure(bg="#b6d7da")
        Password.title("Password")
        Label(Password, bg="#b6d7da", fg="#679190", text="Encription key:",
              font=('Robote 10 bold')).place(x=5, y=5)
        fe = Frame(Password, bg="white", width=416, height=35, relief=GROOVE, bd=3)
        fe.place(x=7, y=30)
        te = Text(fe, font="Robote 10", bg="White", fg="#679190", bd=0)
        generate()
        te.place(x=5, y=5, width=400, height=20)
        Button(Password, text="Save", width=10, height=2, font="arial 10 bold",
               bg="White", fg="#679190", activeforeground="#679190", command=savekey).place(x=373, y=5, width=50,
                                                                                          height=20)
    except:
        print("Failed to encrypt", "\n")

def decrypt():
    def de():
        try:
            mykey = te.get(1.0, END).rstrip()
            fernet = Fernet(mykey)
            #print("key:",mykey.encode())
            message = t1.get(1.0, END)
            d = fernet.decrypt(message).decode()
            #print("Decrypted message:", d)
            t1.delete(1.0, END)
            t1.insert(END, d)
        except:
            print("Wrong key", "\n")
    try:
        Password = Toplevel(app)
        Password.geometry("430x72")
        Password.resizable(False, False)
        Password.configure(bg="#b6d7da")
        Password.title("Password")
        Label(Password, bg="#b6d7da", fg="#679190", text="Enter encryption key:",
              font=('Robote 10 bold')).place(x=5, y=5)
        fe = Frame(Password, bg="white", width=416, height=35, relief=GROOVE, bd=3)
        fe.place(x=7, y=30)
        te = Text(fe, font="Robote 10", bg="White", fg="#679190", bd=0)
        te.place(x=5, y=5, width=400, height=20)
        Button(Password, text="Decrypt", width=10, height=2, font="arial 10 bold",
               bg="White", fg="#679190", activeforeground="#679190", command=de).place(x=363, y=5, width=60,
                                                                                         height=20)
    except:
        print("Failed to decrypt", "\n")

#main window
app = Tk()
app.title("Message Hider 1.0")
app.geometry("860x495")
app.resizable(False,False)
app.configure(bg="#b6d7da")
image_icon=PhotoImage(file="Assets/eye.png")
app.iconphoto(False,image_icon)

#frame 1
f1=Frame(app,bg="white",width=400,height=360,relief=GROOVE,bd=3)
f1.place(x=20,y=20)
l1=Label(f1,bg="White")
l1.place(x=-1,y=-1)

#frame 2
f2=Frame(app,bg="white",width=400,height=360,relief=GROOVE,bd=3)
f2.place(x=440,y=20)
t1=Text(f2,font="Robote 16",bg="White",fg="#679190",wrap=WORD,bd=0)
t1.place(x=10,y=10,width=360,height=334)
sb1=Scrollbar(f2)
sb1.place(x=376,y=0,height=354)
t1.configure(yscrollcommand=sb1.set)

#frame 3
f3=Frame(app,bg="#b6d7da",width=220,height=76,relief=GROOVE,bd=3)
f3.place(x=20,y=400)
Label(f3,text="File",bg="#b6d7da",fg="#8fb0b3",font="Robote 12 bold").place(x=90,y=0)
Button(f3,text="Open",width=10,height=2,font="arial 14 bold",
       bg="White",fg="#679190",activeforeground="#679190",command=open_image).place(x=5,y=25,width=100,height=40)
Button(f3,text="Save",width=10,height=2,font="arial 14 bold"
       ,bg="White",fg="#679190",activeforeground="#679190",command=save_image).place(x=110,y=25,width=100,height=40)
#frame 4
f4=Frame(app,bg="#b6d7da",width=220,height=76,relief=GROOVE,bd=3)
f4.place(x=320,y=400)
Label(f4,text="Stegano",bg="#b6d7da",fg="#8fb0b3",font="Robote 12 bold").place(x=72,y=0)
Button(f4,text="Show",width=10,height=2,font="arial 14 bold",
       bg="White",fg="#679190",activeforeground="#679190",command=show).place(x=5,y=25,width=100,height=40)
Button(f4,text="Hide",width=10,height=2,font="arial 14 bold"
       ,bg="White",fg="#679190",activeforeground="#679190",command=hide).place(x=110,y=25,width=100,height=40)
#frame 5
f5=Frame(app,bg="#b6d7da",width=220,height=76,relief=GROOVE,bd=3)
f5.place(x=621,y=400)
Label(f5,text="Encryption",bg="#b6d7da",fg="#8fb0b3",font="Robote 12 bold").place(x=65,y=0)
Button(f5,text="Encrypt",width=10,height=2,font="arial 14 bold",
       bg="White",fg="#679190",activeforeground="#679190",command=encrypt).place(x=5,y=25,width=100,height=40)
Button(f5,text="Decrypt",width=10,height=2,font="arial 14 bold"
       ,bg="White",fg="#679190",activeforeground="#679190",command=decrypt).place(x=110,y=25,width=100,height=40)
app.mainloop()