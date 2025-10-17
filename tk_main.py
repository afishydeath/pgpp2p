import tkinter as tk
from tkinter import ttk


class PGPApp(tk.Tk):
    def __init__(self):
        super().__init__()
        # establish frames
        self.header = Header(self)
        self.authenticate = Authenticate(self)
        self.login = Login(self)

        # assign layout
        self.header.grid(column=0, row=0)
        self.login.grid(column=0, row=1)


class Header(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        # add widgets
        self.titleLabel = ttk.Label(self, text="Title")
        self.loginButton = ttk.Button(self, text="Login")

        # add to grid
        self.titleLabel.grid(column=0, row=0)
        self.loginButton.grid(column=2, row=0)


class Login(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        # create widgets
        self.welcomeLabel = ttk.Label(self, text="Welcome, {username}")  # TODO
        self.passwordLabel = ttk.Label(self, text="Password:")
        self.passwordInput = ttk.Entry(self, show="*")
        self.submitButton = ttk.Button(self, text="Submit")

        # add them to the grid
        self.welcomeLabel.grid(column=0, row=1, columnspan=2)
        self.passwordLabel.grid(column=0, row=2)
        self.passwordInput.grid(column=1, row=2)
        self.submitButton.grid(column=0, row=3, columnspan=2)


class Register(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)


class Messaging(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)


class Authenticate(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        # create widgets
        self.passwordLabel = ttk.Label(self, text="Password:")
        self.passwordInput = ttk.Entry(self, show="*")
        self.submitButton = ttk.Button(self, text="Submit")

        # add them to the grid
        self.passwordLabel.grid(column=0, row=0)
        self.passwordInput.grid(column=1, row=0)
        self.submitButton.grid(column=0, row=1, columnspan=2)


app = PGPApp()
app.mainloop()
