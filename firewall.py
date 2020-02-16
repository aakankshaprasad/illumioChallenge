from collections import defaultdict
import sys


class TrieNode:

    def __init__(self):
        self.children = defaultdict()
        self.terminating = False


class Trie:

    def __init__(self):
        self.root = self.get_node()

    def get_node(self):
        return TrieNode()

    def get_index(self, ch):
        return int(ch)

    def insert(self, word):

        root = self.root
        tempLength = len(word)

        for i in range(tempLength):
            index = self.get_index(word[i])
            # print(index)
            if index not in root.children:
                root.children[index] = self.get_node()
                # print(root.children[index])
            root = root.children.get(index)

        root.terminating = True

    def search(self, word):
        root = self.root
        len1 = len(word)
        # print(word)
        for i in range(len1):
            index = self.get_index(word[i])
            # print(index)
            if not root:
                return False
            root = root.children.get(index)

        return True if root and root.terminating else False


class Firewall:
    directionMap = [{}]
    minimumIP = ""
    maximumIP = ""
    minimumPort = 0
    maximumPort = 0

    def __init__(self):
        Firewall.directionMap = [{} for new_list in range(4)]

    def hash(self, direction, protocol):
        key = direction.lower() + protocol.lower()
        if key == 'inboundtcp':
            return 0
        elif key == 'inboundudp':
            return 1
        elif key == 'outboundtcp':
            return 2
        else:
            return 3

    def convertIPToNum(self, ip):
        ipArray = ip.split('.')
        result = 0
        for i in range(len(ipArray)):
            power = 3 - i
            iptemp = int(ipArray[i])
            result += iptemp * pow(256, power)
        return result

    def dectoIP(self, ip):
        result = []
        for i in range(4):
            result.insert(0, str(ip & 0xff))
            if i < 3:
                result.insert(0, '.')
            ip = ip >> 8
        return "".join(result)

    def parse(self, port, ip):
        if '-' in port:
            portValues = port.split('-')
            self.minimumPort = int(portValues[0])
            self.maximumPort = int(portValues[1])
        else:
            self.minimumPort = self.maximumPort = int(port)

        if '-' in ip:
            ipValues = ip.split('-')
            self.minimumIP = ipValues[0]
            self.maximumIP = ipValues[1]
        else:
            self.minimumIP = self.maximumIP = ip

    def readFile(self, file):
        # reading rules from a text file
        lineList = [line.rstrip('\n') for line in open(file)]
        print("Building IP-Trie")
        for line in lineList:
            # print(line)
            param = line.split(',')
            # print(param)
            hashIndex = self.hash(param[0], param[1])
            dictonaryInMainList = Firewall.directionMap[hashIndex]
            # print(hashIndex)
            # print(dictonaryInMainList)
            self.parse(param[2], param[3])

            for i in range(self.minimumPort - 1, self.maximumPort):
                # root = dictonaryInMainList[i]
                if i not in dictonaryInMainList:
                    root = Trie()
                    dictonaryInMainList[i] = root
                else:
                    root = dictonaryInMainList[i]
                # print("Port = ", i)

                for j in range(self.convertIPToNum(self.minimumIP), self.convertIPToNum(self.maximumIP) + 1):
                    ipconvert = self.dectoIP(j)
                    # print(ipconvert)
                    root.insert(ipconvert.split('.'))

    def accept_packet(self, direction, protocol, port, ip):
        hashIndex = self.hash(direction, protocol)
        portMap = self.directionMap[hashIndex]
        if port - 1 in portMap:
            root = portMap[port - 1]
            if root:
                return root.search(ip.split('.'))
        return False


if __name__ == "__main__":
    inputFile = ""
    if len(sys.argv) == 3:
        file = sys.argv[1]
        inputFile = sys.argv[2]
    else:
        file = "rules"
    fw = Firewall()
    fileOK = 1
    inputOK = 1

    try:
        fw.readFile(file)
        print("Finised building IP-Trie")
    except IOError:
        print("No File Found")
        fileOK = 0

    lineList = []
    try:
        lineList = [line.rstrip('\n') for line in open(inputFile)]
    except IOError:
        print("No Input File Found")
        inputOK = 0

    if fileOK and inputOK:
        print("Checking Input")
        for line in lineList:
            inputList = line.split(",")
            print(fw.accept_packet(inputList[0].strip(), inputList[1].strip(), int(inputList[2]), inputList[3].strip()))
    print("Program Terminated")
