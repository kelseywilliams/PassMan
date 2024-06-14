import hashlib, binascii, os, json, sys, getpass, colored, base64, shutil
from cryptography.fernet import Fernet
from random import randint
import traceback
class PassMan(object):
    CWD = os.environ['PASSMAN']
    PWD_PATH = CWD + "/pwd.json"
    CONFIG_PATH = CWD + "/master_key.json"
    DATA_PATH = CWD + "/data/"

    red = colored.fg("red")
    grn = colored.fg("green")
    res = colored.attr('reset')

    def __init__(self, domain, account):
        self.domain = domain
        self.account = account
        self.master_key = None
    
    '''Utility methods'''
    @staticmethod
    def error(msg):
        print(PassMan.red+msg+PassMan.res, file=sys.stderr)

    @staticmethod
    def success(msg):
        print(PassMan.grn+msg+PassMan.res)

    @staticmethod
    def hash_password_fernet(pwd):
        hash = hashlib.sha512(pwd.encode("utf-8")).hexdigest()
        url_hex = base64.urlsafe_b64encode(str.encode(hash))
        key = url_hex[-44:]
        key = key.decode("utf-8")
        return key

    @staticmethod
    def hash_password(pwd):
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', pwd.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    @staticmethod
    def verify_password(stored_pass, prov_pass):
        salt = stored_pass[:64]
        stored_pass = stored_pass[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', prov_pass.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_pass

    @staticmethod
    def decrypt_file(file, key):
        token = Fernet(key)
        with open(file, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = token.decrypt(encrypted_data)
        with open(file, "wb") as f:
            f.write(decrypted_data)

    @staticmethod
    def encrypt_file(file, key):
        token = Fernet(key)
        with open(file, "rb") as f:
            data = f.read()
        encrypted_data = token.encrypt(data)
        with open(file, "wb") as f:
            f.write(encrypted_data)

    @staticmethod    
    def decrypt_data(data, key):
        token = Fernet(key)
        decrypted_data = token.decrypt(data.encode('utf-8'))
        return decrypted_data.decode('utf-8')

    @staticmethod
    def encrypt_data(data, key):
        token = Fernet(key)
        encrypted_data = token.encrypt(data.encode('utf-8'))
        return encrypted_data.decode('utf-8')

    @staticmethod
    def get_file_json(filepath, key):
        PassMan.decrypt_file(filepath, key)
        with open(filepath, "r") as j:
            content = json.load(j)
        PassMan.encrypt_file(filepath, key)
        return content
    
    @staticmethod
    def save_file_json(filepath, key, content):
        with open(filepath, "w") as j:
            json.dump(content, j)
        PassMan.encrypt_file(filepath, key)
    
    @staticmethod
    def get_pwd_json():
        with open(PassMan.PWD_PATH, "r") as p:
            content = json.load(p)
        return content
    
    @staticmethod
    def save_pwd_json(content):
        with open(PassMan.PWD_PATH, "w") as p:
            json.dump(content, p)

    # Use this method to prompt a new password and confirmation password
    # as well as repeat the message if the two do not match.
    @staticmethod
    def set_pwd(pwd_msg, conf_msg):
        pwd = getpass.getpass(prompt=pwd_msg)
        conf = getpass.getpass(prompt=conf_msg)
        if pwd != conf:
            PassMan.error("Passwords do not match.")
            try:
                PassMan.set_pwd(pwd_msg, conf_msg)
            except RecursionError:
                PassMan.error("Maximum number of retries exceeded.")
                sys.exit()
        return pwd


    ''' Main methods '''
    def init_passman(self):
        folder = os.listdir(PassMan.CWD)
        if "data" not in folder:
            os.mkdir(PassMan.DATA_PATH)
        if "pwd.json" not in folder:
            shutil.rmtree(PassMan.DATA_PATH)
            os.mkdir(PassMan.DATA_PATH)
            print("Welcome to PassMan password manager!")
            try:
                pwd = PassMan.set_pwd("Please enter a strong password:", "Confirm password:")
                master_key = PassMan.hash_password_fernet(pwd)
                pwd_hash = PassMan.hash_password(pwd)
                pwd_content = {"pwd" : pwd_hash}
                PassMan.save_pwd_json(pwd_content)
                self.master_key = master_key
                PassMan.success("Successfully set password.")
                return True
            except Exception:
                PassMan.error("Setup failed.")
                sys.exit()
        return False

    def login(self):
        try:
            if self.init_passman():
                return True
            pwd = getpass.getpass(prompt="Password:")
            content = PassMan.get_pwd_json()
            if PassMan.verify_password(content["pwd"], pwd):
                self.master_key = PassMan.hash_password_fernet(pwd)
                return True
            else:
                PassMan.error("Given password does not match stored password.")
                return False
        except Exception:
            PassMan.error("Login failure.")

    def rekey(self):
        try:
            pwd = PassMan.set_pwd("Enter new password:", "Confirm new password:")
            newMaster = PassMan.hash_password_fernet(pwd)
            newPwd = PassMan.hash_password(pwd)
            pwd_content = PassMan.get_pwd_json()
            pwd_content["pwd"] = newPwd
            PassMan.save_pwd_json(pwd_content)
            folder = os.listdir(PassMan.DATA_PATH)
            for file in folder:
                PassMan.decrypt_file(PassMan.DATA_PATH + file, self.master_key)
                PassMan.encrypt_file(PassMan.DATA_PATH + file, newMaster)
                raw_filename = file.replace(".json", "")
                raw_filename = PassMan.decrypt_data(raw_filename, self.master_key)
                new_file = PassMan.encrypt_data(raw_filename, newMaster)
                os.rename(PassMan.DATA_PATH + file, PassMan.DATA_PATH + new_file + ".json")
            PassMan.success("Successfully reset password.")
        except Exception:
            PassMan.error("Password reset failed.")

    def fetch(self):
        try:
            domain = self.domain
            account = self.account
            folder = os.listdir(PassMan.DATA_PATH)
            master_key = self.master_key
            count = 0
            def fetch_format(account, usr, pwd, note):
                print(f"========== account {account}:\nUsername:{usr}\nPassword:{pwd}")
                if note != "":
                    print(f"Note:{note}")
            for file in folder:
                filepath = PassMan.DATA_PATH + file
                content = PassMan.get_file_json(filepath, master_key)
                raw_filename = file.replace(".json", "")
                if(PassMan.decrypt_data(raw_filename, master_key) == domain):
                    count += 1
                    accounts = [*content['accounts']]
                    print(f"{domain}")
                    if self.account != None:
                        if account in accounts:
                            usr = content['accounts'][account]['usr']
                            pwd = content['accounts'][account]['pwd']
                            note = content['accounts'][account]['note']
                            fetch_format(account, usr, pwd, note)
                        else:
                            PassMan.error(f"Account {account} could not be found under {domain}.")
                    else:
                        for i in range(len(accounts)):
                            usr = content['accounts'][accounts[i]]['usr']
                            pwd = content['accounts'][accounts[i]]['pwd']
                            note = content['accounts'][accounts[i]]['note']
                            fetch_format(i, usr, pwd, note)
            if(count < 1):
                PassMan.error(f"No accounts found under {domain}.")
        except Exception:
            traceback.print_exc()
            PassMan.error("Failed to fetch account(s).")

    def _list(self):
        try:
            domains = []
            used_letters = []
            folder = os.listdir(PassMan.DATA_PATH)
            master_key = self.master_key
            for file in folder:
                raw_filename = file.replace(".json", "")
                domain = PassMan.decrypt_data(raw_filename, master_key)
                if domain[:1] not in used_letters:
                    used_letters.append(domain[:1])
                domains.append(domain)
            domains = sorted(domains)
            used_letters = sorted(used_letters)
            if len(used_letters) == 0:
                PassMan.error("There are no accounts to list.")
            else:
                print("Stored Domains")
                for letter in used_letters:
                    print(f"========== {letter.upper()}:")
                    for domain in domains:
                        if domain[:1] == letter:
                            print(domain)
        except Exception:
            PassMan.error("Failed to list accounts")

    def add(self):
        try:
            domain = self.domain
            usr = input("Username to add:")
            pwd = getpass.getpass(prompt="Password to add:")
            if pwd == "gen":
                chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@!$&_+="
                new_pwd = ""
                def get_len():
                    num = input("How many characters?:")
                    if num.isdigit():
                        num = int(num)
                    else:
                        PassMan.error("Input must be of type integer.")
                        num = get_len()
                    return num
                num = get_len()
                for i in range(num):
                    new_pwd = new_pwd + chars[randint(0, len(chars) -1)]
                pwd = new_pwd
                
            note = input("Notes to add:")
            folder = os.listdir(PassMan.DATA_PATH)
            master_key = self.master_key
            count = 0
            for file in folder:
                filepath = PassMan.DATA_PATH + file
                raw_filename = file.replace(".json", "")
                if(PassMan.decrypt_data(raw_filename, master_key) == domain):
                    count += 1  
                    content = PassMan.get_file_json(filepath, master_key)
                    account = len(content['accounts'])
                    content['accounts'][account] = {
                                        "usr" : usr,
                                        "pwd" : pwd,
                                        "note" : note
                                    }
                    PassMan.save_file_json(filepath, master_key, content)
                    PassMan.success("Successfully saved account.")
            if(count < 1):
                content = {
                            "accounts": {
                                0 : {
                                    "usr" : usr,
                                    "pwd" : pwd,
                                    "note" : note
                                }
                            }
                        }
                domain = PassMan.encrypt_data(domain.lower(), master_key)
                filepath = PassMan.DATA_PATH + domain + ".json"
                PassMan.save_file_json(filepath, master_key, content)
                PassMan.success("Successfully saved account.") 
        except Exception:
            PassMan.error("Failed to save account.")

    def delete(self):
        try:
            domain = self.domain
            account = self.account
            master_key = self.master_key
            folder = os.listdir(PassMan.DATA_PATH)
            count = 0
            for file in folder:
                filepath = PassMan.DATA_PATH + file
                raw_filename = file.replace(".json", "")
                if(PassMan.decrypt_data(raw_filename, master_key) == domain):
                    count += 1
                    if account == None:
                        confirm = input(PassMan.red+f"You are about to delete all accounts under {domain}.  Are you sure? (y/n)"+PassMan.res)
                        if confirm.lower() == "y":
                            os.remove(filepath)
                            PassMan.success(f"All accounts under {domain} removed.")
                        else:
                            PassMan.error(f"Failed to remove all accounts under {domain}.")
                    else:
                        content = PassMan.get_file_json(filepath, master_key)
                        accounts = [*content['accounts']]
                        new_content = {
                                        "accounts" : {

                                        } 
                                    }
                        if account in accounts:
                            confirm = input(PassMan.red+f"You are about to delete account {account} from under {domain}.  Are you sure? (y/n)"+PassMan.res)
                            if confirm.lower() == "y":
                                del content['accounts'][account]
                                accounts = [*content['accounts']]
                                for i in range(len(accounts)):
                                    new_content['accounts'][f'{i}'] = content['accounts'][accounts[i]]
                                PassMan.save_file_json(filepath, master_key, new_content)
                                PassMan.success(f"Account {account} removed from under {domain}.")
                                if(len(accounts) == 0):
                                    os.remove(filepath)
                                    return
                            else:
                                PassMan.error(f"Failed to remove account {account} from under {domain}.")
                                return
                        else:
                            PassMan.error(f"Account {account} could not be found under {domain}.")
            if(count < 1):
                PassMan.error(f"No accounts found under {domain}.")
        except Exception:
            PassMan.error("Failed to delete account(s).")
    def dump(self):
        try:
            domains = []
            used_letters = []
            folder = os.listdir(PassMan.DATA_PATH)
            master_key = self.master_key
            for file in folder:
                raw_filename = file.replace(".json", "")
                domain = PassMan.decrypt_data(raw_filename, master_key)
                if domain[:1] not in used_letters:
                    used_letters.append(domain[:1])
                domains.append(domain)
            domains = sorted(domains)
            used_letters = sorted(used_letters)
            if len(used_letters) == 0:
                PassMan.error("There are no accounts to list.")
            else:
                for domain in domains:
                    folder = os.listdir(PassMan.DATA_PATH)
                    master_key = self.master_key
                    count = 0
                    def fetch_format(account, usr, pwd, note):
                        print(f"========== account {account}:\nUsername:{usr}\nPassword:{pwd}")
                        if note != "":
                            print(f"Note:{note}")
                    for file in folder:
                        filepath = PassMan.DATA_PATH + file
                        content = PassMan.get_file_json(filepath, master_key)
                        raw_filename = file.replace(".json", "")
                        if(PassMan.decrypt_data(raw_filename, master_key) == domain):
                            count += 1
                            accounts = [*content['accounts']]
                            print(f"\n{domain}")
                            for i in range(len(accounts)):
                                usr = content['accounts'][accounts[i]]['usr']
                                pwd = content['accounts'][accounts[i]]['pwd']
                                note = content['accounts'][accounts[i]]['note']
                                fetch_format(i, usr, pwd, note)
                    if(count < 1):
                        PassMan.error(f"No accounts found under {domain}.")
        except Exception:
            PassMan.error("Failed to dump accounts.")


class Parser():
    HELP = """Usage: passman <command> [<domain>][<account>]

passman commands:
    fetch 	fetch existing account or accounts under a domain name.  
                takes arguments domain and optional argument account.

    list	list all domain names in passman.  takes no arguments

    add         adds an account under a domain name. takes arguments domain.

    delete      deletes an account or all accounts under a domain name. 
                takes arguments domain and optional argument account.

    rekey	resets master key"""

    def __init__(self, args):
        self.args = args
        self.cmds = ["fetch", "list", "add", "delete", "rekey", "help", "dump"]
        self.cmd = None
        self.d = None
        self.a = None

    @staticmethod
    def get_command(args):
        if len(args) > 1:
            return args[1].lower()
        else:
            PassMan.error("PassMan: No commands given.")
            print(Parser.HELP)
            sys.exit()

    @staticmethod
    def get_arguments(cmd, num_args, args):
        def size_err(cmd, len_args, min, max):
            too_few = "Too few arguments."
            too_many = "Too many arguments."
            if len_args > max:
                err = too_many
            elif len_args < min:
                err = too_few
            PassMan.error(f"PassMan: {err}  {cmd} takes no arguments.  Type \"passman help\" for more info." )
            sys.exit()

        if num_args == 0:
            if len(args) == 2:
                return
            else:
                size_err(cmd, len(args), 2,2)
        if num_args == 1:
            if len(args) == 3:
                d = args[2]
                return d
            else:
                size_err(cmd, len(args), 3,3)
        if num_args == 2:
            if len(args) > 2 and len(args) < 5:
                d = args[2]
                a = None
                if len(args) == 4:
                    a = args[3]
                return (d, a)
            else:
                size_err(cmd, len(args), 3, 4)

    def run(self):
        passman = PassMan(self.d, self.a)
        if passman.login():
            return passman
        else:
            sys.exit()

    def run_command(self):
        self.cmd = Parser.get_command(self.args)
        if self.cmd in self.cmds:
            if self.cmd == "rekey":
                Parser.get_arguments("rekey", 0, self.args)
                self.run().rekey()
            if self.cmd == "list":
                Parser.get_arguments("list", 0, self.args)
                self.run()._list()
            if self.cmd == "dump":
                Parser.get_arguments("dump", 0, self.args)
                self.run().dump()
            if self.cmd == "add":
                self.d = Parser.get_arguments("add", 1, self.args)
                self.run().add()
            if self.cmd == "fetch":
                self.d, self.a = Parser.get_arguments("fetch", 2, self.args)
                self.run().fetch()
            if self.cmd == "delete":
                self.d, self.a = Parser.get_arguments("delete", 2, self.args)
                self.run().delete()
            if self.cmd == "help":
                print(Parser.HELP)
        else:
            PassMan.error("PassMan: Invalid command.")

try:
    parser = Parser(sys.argv)
    parser.run_command()
except KeyboardInterrupt:
    pass