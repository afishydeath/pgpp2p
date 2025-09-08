from pgpy import PGPKey, PGPUID, PGPKeyring, PGPMessage
from pgpy.errors import PGPError
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm,
)
from pgpy.pgp import Fingerprint
from os import path
import os
import sys


USER_KEY_PATH = "./data/user.asc"
USER_PUBLIC_KEY_PATH = "./public.asc"
CONTACT_PATH = "./data/contacts/"

# Supress warnings caused by pgpy

if not sys.warnoptions:
    import warnings

    warnings.simplefilter("ignore")


# Errors
class LoginFailed(Exception):
    pass


class ExitContact(Exception):
    pass


# Helper Functions
def isRegistered() -> bool:
    return path.exists(USER_KEY_PATH) and path.isfile(USER_KEY_PATH)


def getChoice(options: dict[str, str]) -> str:
    for key, value in options.items():
        print(f"{key}. {value}")
    while (selection := input("Input selection:\n> ")) not in options.keys():
        print("Invalid choice")
    return selection


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
    while not user_key.is_protected:
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


def loadContacts() -> PGPKeyring:
    # load contact keys from dir
    contacts = PGPKeyring()
    for f in os.listdir(CONTACT_PATH):
        contacts.load(CONTACT_PATH + f)
    return contacts


def saveContacts(contacts: PGPKeyring) -> None:
    # save contact keys to dir
    for fingerprint in contacts.fingerprints():
        with contacts.key(fingerprint) as key:
            with open(CONTACT_PATH + key.userids[0].name + ".asc", "w") as f:
                f.write(str(key))


def registerContact(contacts: PGPKeyring) -> PGPKeyring:
    # add a new public key to your contacts
    res = PGPKey.from_file(input("Input path for key.\n> "))
    match res:
        case PGPKey():
            contact = res
        case [PGPKey(), _]:
            contact = res[0]
    contacts.load(contact)
    print("Contact " + contact.userids[0].name + " registered.")
    saveContacts(contacts)
    return contacts


def printContacts(contacts: PGPKeyring) -> None:
    # obtain a list of just contact information
    contact_uids: list[PGPUID] = []
    for fingerprint in contacts.fingerprints():
        with contacts.key(fingerprint) as k:
            contact_uids.append(k.userids[0])
    # sort the list by user name
    contact_uids = sorted(contact_uids, key=lambda uid: uid.name)
    # print the contact info
    print("Contacts:")
    for p, uid in enumerate(contact_uids):
        print(f"{p}. {uid.name}, ({uid.comment}), {uid.email}")


def selectContactFingerprint(contacts: PGPKeyring) -> Fingerprint:
    fingerprint = None
    while fingerprint is None:
        print("Select a contact")
        options = {
            "n": "Type contact name",
            "?": "get a list of contacts",
            "q": "cancel",
        }
        choice = getChoice(options)
        match choice:
            case "?":
                printContacts(contacts)
            case "q":
                raise ExitContact
            case _:
                try:
                    search_string = input("Input contact name:\n> ")
                    with contacts.key(search_string) as k:
                        print(k.userids[0].name + " Selected.")
                        fingerprint = k.fingerprint
                except KeyError:
                    print("Name not fount in contacts.")
    return fingerprint


def sendMessage(user_key: PGPKey, contacts: PGPKeyring) -> None:
    # encrypt a message with a contact's public key, and sign with our private key
    ## Select the Contact to message.
    try:
        fingerprint = selectContactFingerprint(contacts)
    except ExitContact:
        return None
    # get a message from the user
    print("How would you like to send your message?")
    options = {
        "t": "input message directly",
        "f": "input path to a file",
        "q": "cancel",
    }
    c = getChoice(options)
    match c.lower():
        case "q":
            return None
        case "f":
            message = PGPMessage.new(input("Path:\n> "), file=True)
        case "t":
            message = PGPMessage.new(input("Message:\n> "))

    if user_key.is_protected:
        with user_key.unlock(input("Input your password:\n> ")):
            message |= user_key.sign(message)
    else:
        message |= user_key.sign(message)

    with contacts.key(fingerprint) as k:
        message = k.encrypt(message)

    print("Would you like the encrypted message printed or written to a file?")
    options = {"p": "Print the message", "f": "Write the message to a file"}
    c = getChoice(options)
    match c:
        case "p":
            print(str(message))
        case "f":
            with open(input("Input file path:\n> "), "w") as f:
                f.write(str(message))
                print("Message written")


def recieveMessage(user_key: PGPKey, contacts: PGPKeyring) -> None:
    # verify a message with a contact's public key, and decrypt with our private key
    print("How would you like to provide the encrypted message?")
    options = {"f": "Provide a path to a file", "p": "Paste the text here", "q": "Exit"}
    c = getChoice(options)
    match c:
        case "f":
            message = PGPMessage.from_file(input("Input file path:\n> "))
        case "p":
            message = PGPMessage.from_blob(input("Input raw text here:\n> "))
        case "q":
            return None
    # select the sender
    try:
        contact = selectContactFingerprint(contacts)
    except ExitContact:
        return None

    # decrypt message
    if user_key.is_protected:
        with user_key.unlock(input("Input your password:\n> ")):
            message = user_key.decrypt(message)
    else:
        message = user_key.decrypt(message)

    # verify signature of message
    with contacts.key(contact) as k:
        try:
            k.verify(message)
            print("Signature Verified.")
        except PGPError:
            print("Signature verification Failed.")

    print("Would you like the decrypted message printed or written to a file?")
    options = {"p": "Print the message", "f": "Write the message to a file"}
    c = getChoice(options)
    match c:
        case "p":
            print(message.message)
        case "f":
            with open(input("Input file path:\n> "), "w") as f:
                f.write(message.message)
                print("Message written")


def shareContact(user_key: PGPKey) -> None:
    print("Would you like your public key output as a file or printed?")
    options = {"f": "Output as a file", "p": "Print the key"}
    c = getChoice(options)
    match c:
        case "f":
            with open(USER_PUBLIC_KEY_PATH, "w") as f:
                f.write(str(user_key.pubkey))
                print("Public key written to " + USER_PUBLIC_KEY_PATH)
        case "p":
            print(str(user_key.pubkey))


# Main Loop
def main() -> None:
    # log in / register
    user_key = None
    while user_key is None:
        try:
            user_key = loginOrRegister()
        except LoginFailed:
            print("Password Incorrect.")
            options = {
                "r": "retry authentication",
                "q": "quit program",
                "d": "delete key and re-register",
            }
            c = getChoice(options)
            match c:
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
        print("What would you like to do?")
        options = {
            "1": "Register a contact",
            "2": "Send a message",
            "3": "Recieve a message",
            "4": "Share your contact",
            "0": "Quit",
        }  # Extension: handle encryption of one message to multiple recipients
        action = getChoice(options)
        match action:
            case "0":
                exit = True
            case "1":
                contacts = registerContact(contacts)
            case "2":
                sendMessage(user_key, contacts)
            case "3":
                recieveMessage(user_key, contacts)
            case "4":
                shareContact(user_key)


if __name__ == "__main__":
    main()
