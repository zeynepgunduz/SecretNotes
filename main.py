
import tkinter as tk
from tkinter import messagebox
import os
import base64

pFILENAME = "MySecretNotes.txt"


# functions ######################
def fnk_Saveand_EncryptNote():
    fPWD = entKey.get()
    fTitle = entTitle.get()
    fNote = txtNote.get("1.0", tk.END)

    if fPWD == "" or fTitle == "" or fNote == "":
        tk.messagebox.showinfo(title="Error", message="Enter Title, Note and Key")
    else:
        try:
            path = "./" + pFILENAME
            check_file = os.path.isfile(path)
            if check_file == True:
                file = open(pFILENAME, "a")
                file.write(f"{fTitle}\n{fnkEncode(fPWD, fNote)}")
                file.write("\n")
        except:
            print("Error occurred while encoding!")
        finally:
            fnkClearScreen()


def fnk_DecryptNote():
    fKey = entKey.get()
    fNote = txtNote.get("1.0", tk.END)
    print(fKey,"***",fNote)
    if len(fKey) == 00 or len(fNote) == 0:
        tk.messagebox.showinfo(title="Error", message="Enter Note and Key")
    else:
        try:
            noteDecrypted = fnkDecode(fKey, fNote)
            txtNote.delete("1.0", tk.END)
            txtNote.insert("1.0", noteDecrypted)

        except:
            print("Error occured while decoding !")
        finally:
            pass
    pass

#apply cryptography with vigenere ciphher
#https://stackoverflow.com/a/38223403
def fnkEncode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def fnkDecode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def fnkClearScreen():
    entKey.delete(0, tk.END)
    entTitle.delete(0, tk.END)
    txtNote.delete("1.0", tk.END)


# exit function
def fnkExit():
    w.destroy()
##################################


# UI #################################
w = tk.Tk()
w.title("Secret Notes")
w.config(padx=77, pady=77)

# For changing the icon of the title bar
pic = tk.PhotoImage(file="notes.png")
w.iconphoto(False, pic)

canvas = tk.Canvas(height=200, width=200)  # Canvas is a rectangular area where we can place our text and widgets.
logo = tk.PhotoImage(file="topsecret.png")
canvas.create_image(100, 100, image=logo)
canvas.pack()

lblTitle = tk.Label(text="Enter your title")
lblTitle.pack()
entTitle = tk.Entry(width=35)
entTitle.pack()

lblNote = tk.Label(text="Enter your secret")
lblNote.pack()
txtNote = tk.Text(width=35, height=20)
txtNote.pack()

lblKey = tk.Label(text="Enter master key", font=('Helvetica', 8))
lblKey.config(fg="red")
lblKey.pack()
entKey = tk.Entry(width=35)
entKey.pack()

btnSave = tk.Button(text="Save & Encrypt", command=fnk_Saveand_EncryptNote)
btnSave.pack()
btnDecrypt = tk.Button(text="Decrypt", command=fnk_DecryptNote)
btnDecrypt.pack()

btnExit = tk.Button(text="Exit", bg="red", command=fnkExit)
btnExit.pack()

# #################################

w.mainloop()
