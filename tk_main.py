import tkinter as tk
from tkinter import CENTER, END, TOP, messagebox, filedialog
from tkinter import NS, NSEW, W, E, ttk
from pgpy import PGPKey, PGPUID, PGPKeyring, PGPMessage
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm,
)
from pgpy.pgp import PGPDecryptionError
from os import path
import os
import sys


if not sys.warnoptions:
    import warnings

    warnings.simplefilter("ignore")


class PGPManager:
    USER_KEY_PATH = "./data/user.asc"
    USER_PUBLIC_KEY_PATH = "./public.asc"
    CONTACT_PATH = "./data/contacts/"

    def __init__(self, parent):
        self.parent = parent
        self.userKey = None
        self.userPassword = None
        self.contacts = None
        if self.isRegistered():
            self.userKey = self.loadKey()
        self.loadContacts()

    def isRegistered(self) -> bool:
        return path.exists(self.USER_KEY_PATH) and path.isfile(self.USER_KEY_PATH)

    def loadKey(self) -> PGPKey:
        res = PGPKey.from_file(self.USER_KEY_PATH)
        match res:  # handle both possible return types
            case PGPKey():
                return res
            case [PGPKey(), _]:
                return res[0]

    def saveKey(self):
        with open(self.USER_KEY_PATH, "w") as f:
            f.write(str(self.userKey))

    def checkPassword(self, password: str) -> bool:
        if not self.userKey:
            return False
        with self.userKey.unlock(password):
            return True

    def login(self, password: str) -> bool:
        try:
            correct = self.checkPassword(password)
        except PGPDecryptionError:
            return False
        if correct:
            self.userPassword = password
            self.parent.doUpdates()
            return True
        return False

    def register(self, name: str, email: str, password: str):
        self.userKey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        self.userPassword = password

        uid = PGPUID.new(name, comment="", email=email)
        usage = {KeyFlags.Certify, KeyFlags.EncryptCommunications, KeyFlags.Sign}
        hashes = [
            HashAlgorithm.SHA256,
            HashAlgorithm.SHA384,
            HashAlgorithm.SHA512,
            HashAlgorithm.SHA224,
        ]
        ciphers = [
            SymmetricKeyAlgorithm.AES256,
            SymmetricKeyAlgorithm.AES192,
            SymmetricKeyAlgorithm.AES128,
        ]
        compression = [
            CompressionAlgorithm.ZLIB,
            CompressionAlgorithm.BZ2,
            CompressionAlgorithm.ZIP,
            CompressionAlgorithm.Uncompressed,
        ]
        self.userKey.add_uid(
            uid, usage=usage, hashes=hashes, ciphers=ciphers, compression=compression
        )
        self.userKey.protect(
            password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256
        )
        self.saveKey()
        self.parent.doUpdates()

    def loadContacts(self):
        # load contact keys from dir
        if os.listdir(self.CONTACT_PATH):
            self.contacts = PGPKeyring()
            for f in os.listdir(self.CONTACT_PATH):
                self.contacts.load(self.CONTACT_PATH + f)

    def saveContacts(self):
        # save contact keys to dir
        if self.contacts:
            for fingerprint in self.contacts.fingerprints():
                with self.contacts.key(fingerprint) as key:
                    with open(
                        self.CONTACT_PATH + key.userids[0].name + ".asc", "w"
                    ) as f:
                        f.write(str(key))

    def registerContact(self, key: str):
        if not self.contacts:
            self.contacts = PGPKeyring()
        result = PGPKey.from_blob(key)
        match result:
            case PGPKey():
                contact = result
            case [PGPKey(), _]:
                contact = result[0]
        self.contacts.load(contact)
        self.saveContacts()
        self.parent.doUpdates()
        return contact.userids[0].name

    def getContact(self, name: str) -> PGPKey:
        assert self.contacts
        with self.contacts.key(name) as k:
            return k

    def getContacts(self) -> list[str]:
        contact_names = []
        assert self.contacts
        for f in self.contacts.fingerprints():
            with self.contacts.key(f) as k:
                contact_names.append(k.userids[0].name)
        return sorted(contact_names)

    def shareContact(self) -> PGPKey:
        assert self.userKey
        assert self.userKey.pubkey
        return self.userKey.pubkey

    def encryptFor(self, contact: PGPKey, cleartext: str) -> PGPMessage:
        assert self.userKey
        message = PGPMessage.new(cleartext)
        with self.userKey.unlock(self.userPassword):
            message |= self.userKey.sign(message)
        message = contact.encrypt(message)
        return message

    def decrypt(self, ciphertext: str) -> PGPMessage:
        message = PGPMessage.from_blob(ciphertext)
        assert self.userKey
        with self.userKey.unlock(self.userPassword):
            message = self.userKey.decrypt(message)
        return message

    def verify(self, contact, message) -> bool:
        return contact.verify(message)


# Tkinter classes, for the ui
class PGPApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.pgpManager = PGPManager(self)
        self.updaters = []
        # establish frames
        self.mainFrames: dict[str, tk.Frame] = {
            "Login": Login(self, self),
            "Register": Register(self, self),
            "Messaging": Messaging(self, self),
        }
        self.currentFrame = None
        self.headerFrame = Header(self, self)
        self.statusFrame = StatusBar(self, self)
        if self.pgpManager.userKey:
            self.headerFrame.setFrame("Login")
        else:
            self.headerFrame.setFrame("Register")

    def changeFrame(self, new: str):
        if self.headerFrame:
            self.headerFrame.pack_forget()
        if self.currentFrame:
            self.currentFrame.pack_forget()
        if self.statusFrame:
            self.statusFrame.pack_forget()
        self.currentFrame = self.mainFrames[new]
        self.headerFrame.pack(side=TOP, anchor=CENTER)
        self.currentFrame.pack(side=TOP, anchor=CENTER)
        self.statusFrame.pack(side=TOP, anchor=CENTER)

    def addUpdater(self, callback):
        self.updaters.append(callback)

    def doUpdates(self):
        for callback in self.updaters:
            callback()

    def uploadText(self, target: ttk.Entry | tk.Text):
        fname = filedialog.askopenfilename()
        if fname:
            with open(fname, "r") as f:
                match target:
                    case ttk.Entry():
                        target.delete(0, END)
                        target.insert(0, f.read())
                    case tk.Text():
                        target.delete("1.0", END)
                        target.insert("1.0", f.read())

    def saveText(self, target: ttk.Entry | tk.Text):
        fname = filedialog.asksaveasfilename()
        if fname:
            with open(fname, "w") as f:
                match target:
                    case ttk.Entry():
                        f.write(target.get())
                    case tk.Text():
                        f.write(target.get("1.0", END))

    def setStyles(self):
        styles = {""}


class Header(tk.Frame):
    def __init__(self, parent: PGPApp, controller: PGPApp):
        super().__init__(parent)
        # add widgets
        self.controller = controller
        self.titleLabel = ttk.Label(self, text="Title")
        self.pageButtons = []
        self.loginButton = ttk.Button(
            self,
            text="Login",
            command=self.setLogin,
        )
        self.registerButton = ttk.Button(
            self,
            text="Register",
            command=self.setRegister,
        )
        self.messagingButton = ttk.Button(
            self,
            text="Messaging",
            command=self.setMessaging,
        )

        # add to grid
        self.titleLabel.grid(column=0, row=0, padx=5)
        self.loginButton.grid(column=1, row=0, padx=2)
        self.registerButton.grid(column=2, row=0, padx=2)
        self.messagingButton.grid(column=3, row=0, padx=2)
        self.updateVariables()
        self.controller.addUpdater(self.updateVariables)

    def setFrame(self, frame: str):
        self.controller.changeFrame(frame)
        self.titleLabel.configure(text=frame)

    def setLogin(self):
        self.setFrame("Login")

    def setRegister(self):
        self.setFrame("Register")

    def setMessaging(self):
        self.setFrame("Messaging")

    def loginImpossible(self):
        messagebox.showwarning(message="There is no account to log in to.")

    def messageLoggedOut(self):
        messagebox.showwarning(message="You need to log in to message")

    def messageNotRegistered(self):
        messagebox.showwarning(message="You need to Register first")

    def updateVariables(self):
        if not self.controller.pgpManager.userKey:
            self.loginButton.configure(command=self.loginImpossible)
            self.messagingButton.configure(command=self.messageNotRegistered)
        elif not self.controller.pgpManager.userPassword:
            self.messagingButton.configure(command=self.messageLoggedOut)
            self.loginButton.configure(command=self.setLogin)
        else:
            self.messagingButton.configure(command=self.setMessaging)
            self.loginButton.configure(command=self.setLogin)


class StatusBar(tk.Frame):
    def __init__(self, parent: PGPApp, controller: PGPApp):
        super().__init__(parent)
        self.controller = controller
        # create widgets
        self.statusLabel = ttk.Label(self)
        # add to layout
        self.statusLabel.grid(column=0, row=0)

        self.updateVariables()
        self.controller.addUpdater(self.updateVariables)

    def updateVariables(self):
        registered = False
        username = None
        loggedIn = False
        if self.controller.pgpManager.userKey:
            registered = True
            username = self.controller.pgpManager.userKey.userids[0].name
        if self.controller.pgpManager.userPassword:
            loggedIn = True

        message = ""

        match (registered, username, loggedIn):
            case (True, str(), False):
                message = f"User {username} Registered, but not logged in"
            case (False, _, _):
                message = "Not Registered"
            case (True, str(), True):
                message = f"User {username} logged in"

        self.statusLabel.config(text=message)


class Login(tk.Frame):
    def __init__(self, parent: PGPApp, controller: PGPApp):
        super().__init__(parent)
        self.controller = controller
        # create widgets
        self.welcomeLabel = ttk.Label(self)
        self.passwordLabel = ttk.Label(self, text="Password:")
        self.passwordInput = ttk.Entry(self, show="*")
        self.passwordInput.bind("<Return>", self.handleLogin)
        self.submitButton = ttk.Button(self, text="Submit", command=self.handleLogin)

        # add them to the grid
        self.welcomeLabel.grid(column=0, row=1, columnspan=2)
        self.passwordLabel.grid(column=0, row=2)
        self.passwordInput.grid(column=1, row=2)
        self.submitButton.grid(column=0, row=3, columnspan=2)

        self.updateVariables()
        self.controller.addUpdater(self.updateVariables)

    def updateVariables(self):
        if self.controller.pgpManager.userKey:
            username = self.controller.pgpManager.userKey.userids[0].name
            self.welcomeLabel.config(text=f"Welcome, {username}")
        else:
            self.welcomeLabel.config(text="Welcome, User.")

    def handleLogin(self, *_):
        result = self.controller.pgpManager.login(self.passwordInput.get())
        if result:
            messagebox.showinfo(message="Login Successful")
        else:
            messagebox.showwarning(message="Login Failed.")
        self.passwordInput.delete(0, END)


class Register(tk.Frame):
    def __init__(self, parent: PGPApp, controller: PGPApp):
        super().__init__(parent)
        self.controller = controller
        # create widgets
        self.usernameLabel = ttk.Label(self, text="Username:")
        self.usernameEntry = ttk.Entry(self)
        self.emailLabel = ttk.Label(self, text="Email:")
        self.emailEntry = ttk.Entry(self)
        self.passwordLabel = ttk.Label(self, text="Password:")
        self.passwordEntry = ttk.Entry(self, show="*")
        self.passwordConfirmLabel = ttk.Label(self, text="Confirm Password:")
        self.passwordConfirmEntry = ttk.Entry(self, show="*")
        self.submitButton = ttk.Button(self, text="Submit", command=self.handleRegister)

        # add to layout
        self.usernameLabel.grid(column=0, row=0, sticky=E)
        self.usernameEntry.grid(column=1, row=0)
        self.emailLabel.grid(column=0, row=1, sticky=E)
        self.emailEntry.grid(column=1, row=1)
        self.passwordLabel.grid(column=0, row=2, sticky=E)
        self.passwordEntry.grid(column=1, row=2)
        self.passwordConfirmLabel.grid(column=0, row=3, sticky=E)
        self.passwordConfirmEntry.grid(column=1, row=3)
        self.submitButton.grid(column=0, row=4, columnspan=2)

    def handleRegister(self):
        if self.passwordEntry.get() != self.passwordConfirmEntry.get():
            messagebox.showwarning(message="Passwords do not match.")
            return
        if self.controller.pgpManager.userKey:
            overwrite = messagebox.askyesno(
                message="This will overwrite the existing account, are you sure you want to re-register?",
                title="Overwrite",
            )
            if not overwrite:
                return
        self.controller.pgpManager.register(
            self.usernameEntry.get(), self.emailEntry.get(), self.passwordEntry.get()
        )
        messagebox.showinfo(message="Registered Successfully.")
        self.usernameEntry.delete(0, END)
        self.emailEntry.delete(0, END)
        self.passwordEntry.delete(0, END)
        self.passwordConfirmEntry.delete(0, END)


class AddContact(tk.Toplevel):
    def __init__(self, parent: "Contacts", controller: PGPApp):
        super().__init__(parent)
        self.parent = parent
        self.controller = controller
        # add widgets
        self.addContactLabel = ttk.Label(self, text="Add a Contact")
        self.keyText = tk.Text(self, width=64, height=30)
        self.textScroll = ttk.Scrollbar(self, command=self.keyText.yview)
        self.keyText["yscrollcommand"] = self.textScroll.set
        self.keyUpload = ttk.Button(self, text="Upload key", command=self.uploadKey)
        self.submitButton = ttk.Button(self, text="Submit", command=self.submitContact)
        # add them to layout
        self.addContactLabel.grid(column=0, row=0, columnspan=3)
        self.keyText.grid(column=0, row=1, columnspan=2)
        self.textScroll.grid(column=2, row=1, sticky=NS)
        self.keyUpload.grid(column=0, row=2)
        self.submitButton.grid(column=1, row=2, columnspan=2)

        self.bind("<Destroy>", self.parent.closeAddContact)

    def submitContact(self):
        name = self.controller.pgpManager.registerContact(self.keyText.get("1.0", END))
        messagebox.showinfo(message=f"Contact {name} registered.")
        self.parent.closeAddContact()

    def uploadKey(self):
        self.controller.uploadText(self.keyText)


class ShareContact(tk.Toplevel):
    def __init__(self, parent: "Contacts", controller: PGPApp):
        super().__init__(parent)
        self.parent = parent
        self.controller = controller
        # add widgets
        self.addContactLabel = ttk.Label(self, text="Share your contact")
        self.keyText = tk.Text(self, width=64, height=30)
        self.textScroll = ttk.Scrollbar(self, command=self.keyText.yview)
        self.keyText["yscrollcommand"] = self.textScroll.set
        self.keyText.insert("1.0", str(self.controller.pgpManager.shareContact()))
        self.keyText["state"] = "disabled"
        self.keySave = ttk.Button(self, text="Save key", command=self.saveKey)
        self.closeButton = ttk.Button(self, text="Close", command=self.close)
        # add them to layout
        self.addContactLabel.grid(column=0, row=0, columnspan=3)
        self.keyText.grid(column=0, row=1, columnspan=2)
        self.textScroll.grid(column=2, row=1, sticky=NS)
        self.keySave.grid(column=0, row=2)
        self.closeButton.grid(column=1, row=2, columnspan=2)

        self.bind("<Destroy>", self.parent.closeShareContact)

    def close(self):
        self.parent.closeShareContact()

    def saveKey(self):
        self.controller.saveText(self.keyText)


class Contacts(tk.Frame):
    def __init__(self, parent: "Messaging", controller: PGPApp):
        super().__init__(parent)
        self.controller = controller
        self.addContactWindow = None
        self.shareContactWindow = None
        # create the widgets
        self.contactsListbox = tk.Listbox(self)
        self.contactsScrollbar = ttk.Scrollbar(
            self, orient="vertical", command=self.contactsListbox.yview
        )
        self.addContactButton = ttk.Button(
            self, text="Add a Contact", command=self.spawnAddContact
        )
        self.shareContactButton = ttk.Button(
            self, text="Share your contact", command=self.spawnShareContact
        )
        # add them to layout
        self.contactsListbox.grid(column=0, row=0, sticky=NSEW)
        self.contactsScrollbar.grid(column=1, row=0, sticky=NS)
        self.addContactButton.grid(column=0, row=1, columnspan=2, sticky=NSEW)
        self.shareContactButton.grid(column=0, row=2, columnspan=2, sticky=NSEW)
        self.rowconfigure(0, weight=1)

        self.updateVariables()
        self.controller.addUpdater(self.updateVariables)

    def updateVariables(self):
        self.contactsListbox.delete(0, END)
        if self.controller.pgpManager.contacts:
            contactNames = self.controller.pgpManager.getContacts()
            for contact in contactNames:
                self.contactsListbox.insert(END, contact)

    def spawnAddContact(self):
        if not self.addContactWindow:
            self.addContactWindow = AddContact(self, self.controller)

    def spawnShareContact(self):
        if not self.shareContactWindow:
            self.shareContactWindow = ShareContact(self, self.controller)

    def closeAddContact(self, *_):
        assert self.addContactWindow
        self.addContactWindow.destroy()
        self.addContactWindow = None

    def closeShareContact(self, *_):
        assert self.shareContactWindow
        self.shareContactWindow.destroy()
        self.shareContactWindow = None


class Convert(tk.Frame):
    def __init__(self, parent: "Messaging", controller: PGPApp):
        super().__init__(parent)
        self.parent = parent
        self.controller = controller
        # add widgets
        self.cleartextLabel = ttk.Label(self, text="Cleartext")
        self.cleartextUploadButton = ttk.Button(
            self, text="Upload", command=self.uploadClear
        )
        self.cleartextText = tk.Text(self, width=64, height=10)
        self.cleartextScroll = ttk.Scrollbar(self, command=self.cleartextText.yview)
        self.cleartextText["yscrollcommand"] = self.cleartextScroll.set
        self.cleartextDownloadButton = ttk.Button(
            self, text="Save", command=self.saveClear
        )
        self.ciphertextLabel = ttk.Label(self, text="Ciphertext")
        self.ciphertextUploadButton = ttk.Button(
            self, text="Upload", command=self.uploadCipher
        )
        self.ciphertextText = tk.Text(self, width=64, height=30)
        self.ciphertextScroll = ttk.Scrollbar(self, command=self.ciphertextText.yview)
        self.ciphertextText["yscrollcommand"] = self.ciphertextScroll.set
        self.ciphertextDownloadButton = ttk.Button(
            self, text="Save", command=self.saveCipher
        )
        self.convertButton = ttk.Button(self, text="Convert", command=self.convert)

        # add them to layout
        self.cleartextLabel.grid(column=0, row=0, columnspan=4)
        self.cleartextUploadButton.grid(column=0, row=1)
        self.cleartextText.grid(column=1, row=1, sticky=NSEW)
        self.cleartextScroll.grid(column=2, row=1, sticky=NS)
        self.cleartextDownloadButton.grid(column=3, row=1)
        self.ciphertextLabel.grid(column=0, row=2, columnspan=4)
        self.ciphertextUploadButton.grid(column=0, row=3)
        self.ciphertextText.grid(column=1, row=3)
        self.ciphertextScroll.grid(column=2, row=3, sticky=NS)
        self.ciphertextDownloadButton.grid(column=3, row=3)
        self.convertButton.grid(column=0, row=4, columnspan=4)

    def uploadCipher(self):
        self.controller.uploadText(self.ciphertextText)

    def saveCipher(self):
        self.controller.saveText(self.ciphertextText)

    def uploadClear(self):
        self.controller.uploadText(self.cleartextText)

    def saveClear(self):
        self.controller.saveText(self.cleartextText)

    def convert(self):
        selectedIndex = self.parent.contactsFrame.contactsListbox.curselection()
        if selectedIndex:
            contactName = self.parent.contactsFrame.contactsListbox.get(
                selectedIndex[0]
            )
            contact = self.controller.pgpManager.getContact(contactName)
            cipher = self.ciphertextText.get("1.0", END).strip()
            clear = self.cleartextText.get("1.0", END).strip()
            if cipher:
                new_clear = self.controller.pgpManager.decrypt(cipher)
                verified = self.controller.pgpManager.verify(contact, new_clear)
                if verified:
                    messagebox.showinfo(message="Signature was verified for contact.")
                else:
                    messagebox.showwarning("Signature was unable to be verified.")
                self.cleartextText.delete("1.0", END)
                self.cleartextText.insert("1.0", str(new_clear))
            if clear:
                new_cipher = self.controller.pgpManager.encryptFor(contact, clear)
                self.ciphertextText.delete("1.0", END)
                self.ciphertextText.insert("1.0", str(new_cipher))
        else:
            messagebox.showerror(
                message="You must select a contact to send to or recieve from."
            )


class Messaging(tk.Frame):
    def __init__(self, parent: PGPApp, controller: PGPApp):
        super().__init__(parent)
        self.controller = controller
        # create widgets
        self.contactsLabel = ttk.Label(self, text="Contacts")
        self.contactsFrame = Contacts(self, self.controller)
        self.convertLabel = ttk.Label(self, text="Convert")
        self.convertFrame = Convert(self, self.controller)
        # add them to layout
        self.contactsLabel.grid(column=0, row=0)
        self.convertLabel.grid(column=1, row=0)
        self.contactsFrame.grid(column=0, row=1, sticky=NSEW)
        self.convertFrame.grid(column=1, row=1, sticky=NSEW)
        self.columnconfigure(1, pad=5)


app = PGPApp()
app.mainloop()
