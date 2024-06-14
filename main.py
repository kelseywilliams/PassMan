from cliparser import Parser
import sys

try:
    parser = Parser(sys.argv)
    parser.run_command()
except KeyboardInterrupt:
    pass