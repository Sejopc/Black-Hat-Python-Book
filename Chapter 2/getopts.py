import sys
import getopt

if not len(sys.argv[1:]):
    print("Pass arguments to the program...")
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:", ["help", "listen", "execute=", "target=", "port=", "command", "upload="])
except getopt.GetoptError as err:
    print(str(err))
    print("Invalid arguments")

for o,a in opts:
    print(o,a)
    print("----------------------------")
    #print(a)
    #print("----------------------------")
    #print(zip(o,a))
    #print("----------------------------")

    print()
    print()
    print()
print(args)
