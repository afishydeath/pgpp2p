from pgpy import PGPKey, PGPUID, PGPKeyring
from pgpy.errors import PGPError
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm,
)
from os import path
import os

USER_KEY_PATH = "./data/user.asc"


# Errors
class LoginFailed(Exception):
    pass


# Helper Functions
def isRegistered() -> bool:
    return path.exists(USER_KEY_PATH) and path.isfile(USER_KEY_PATH)


def login() -> PGPKey:
    user_key = None
    # fetch key from file
    res = PGPKey.from_file(USER_KEY_PATH)
    match res:  # handle both possible return types
        case PGPKey():
            user_key = res
        case [PGPKey(), _]:
            user_key = res[0]
    if not user_key.is_protected:
        return user_key  # return the key if there's no password
    print("Verifying key.\n Input Password:")
    verified = False
    with user_key.unlock(input("> ")):  # test authentication of key
        verified = True
    if verified:
        return user_key  # return key when done
    raise LoginFailed()  # raise an error if auth failed


def register() -> PGPKey:
    # generate key
    user_key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    # assign user id
    print("Creating user ID")
    name = input("Set a display name.\n> ")
    comment = input("Add a comment to the ID.\n> ")
    email = input("List your contact email.\n> ")
    uid = PGPUID.new(name, comment=comment, email=email)
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
    user_key.add_uid(
        uid, usage=usage, hashes=hashes, ciphers=ciphers, compression=compression
    )
    # protect key
    print("Password protect key.")
    while user_key.is_protected:
        print("Input password, or leave blank for no password.")
        p1 = input("> ")
        if not p1:
            print("No password selected.")
            break
        print("Repeat password:")
        p2 = input("> ")
        if p1 != p2:
            print("Passwords do not match.")
            continue
        user_key.protect(p1, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        del p1
        del p2

    # save key
    with open(USER_KEY_PATH, "w") as f:
        f.write(str(user_key))
    # return key
    return user_key


def loginOrRegister() -> PGPKey:
    if isRegistered():
        try:
            return login()
        except PGPError:
            print("Something is wrong with the key, please register instead")
    return register()


def loadContacts() -> PGPKeyring: ...  # load contact keys from dir


def saveContacts(contacts: PGPKeyring) -> None: ...  # save contact keys to dir


def registerContact() -> PGPKey: ...  # add a new public key to your contacts


def sendMessage(
    user_key: PGPKey, contacts: PGPKeyring
) -> (
    None
): ...  # encrypt a message with a contact's public key, and sign with our private key
def recieveMessage(
    user_key: PGPKey, contacts: PGPKeyring
) -> (
    None
): ...  # verify a message with a contact's public key, and decrypt with our private key


# Main Loop
def main() -> None:
    # log in / register
    user_key = None
    while user_key is None:
        try:
            user_key = loginOrRegister()
        except LoginFailed:
            print(
                "Password Incorrect. (R)etry Auth/(Q)uit Program/(D)elete Key and Register"
            )
            match input("> ").lower():
                case "r":
                    pass
                case "q":
                    quit()
                case "d":
                    os.remove(USER_KEY_PATH)
    contacts = loadContacts()
    # Ask for an action to perform
    ## register a contact
    ## "send" a message (no networking in this version)
    ## "recieve" a message (see above)
    exit = False
    while not exit:
        print(
            "What would you like to do?\n"
            + "1. Register a contact\n"
            + "2. Send a message\n"
            + "3. Recieve a message\n"
            + "0. Exit"
        )  # Extension: handle encryption of one message to multiple recipients
        action = input("> ")
        match action:
            case "0":
                exit = True
            case "1":
                contacts.load(registerContact())
            case "2":
                sendMessage(user_key, contacts)
            case "3":
                recieveMessage(user_key, contacts)
