from passman import PassMan
import sys

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
