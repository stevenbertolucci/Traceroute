# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    def __init__(self, hops=30):
        self.__RTTmax = None
        self.__RTTmin = None
        self.__RTTavg = None
        self.__RTTcount = 0
        self.__RTTtotal = 0
        self.__RTTstart = 0
        self.__RTTend = 0
        self.__packetTotal = 0
        self.__packetSuccess = 0
        self.hops = hops
        self.ttl = 1
        self.port = 33434
        self.destinationIp = None

    # ################################################################################################################ #
    # IcmpPacket class GETTERS                                                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def getRTTmax(self):
        return self.__RTTmax

    def getRTTmin(self):
        return self.__RTTmin

    def getRTTavg(self):
        return self.__RTTavg

    def getRTTtotalAndCount(self):
        return self.__RTTtotal, self.__RTTcount

    def getStartEnd(self):
        return self.__RTTstart, self.__RTTend

    def getPacketsQuants(self):
        return self.__packetSuccess, self.__packetTotal

    # ################################################################################################################ #
    # IcmpPacket class SETTERS                                                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setRTTmax(self, RTT):
        self.__RTTmax = RTT

    def setRTTmin(self, RTT):
        self.__RTTmin = RTT

    def setRTTavg(self, RTT):
        self.__RTTavg = RTT

    def setRTTtotalAndCount(self, RTT, count):
        self.__RTTtotal = RTT
        self.__RTTcount += count

    def setStartEnd(self, start, end):
        self.__RTTstart = start
        self.__RTTend = end

    def setPacketsQuants(self, good, total):
        self.__packetSuccess += good
        self.__packetTotal += total

    """ ------------------------------------------------------------------------------------------------
            Citations:

            I used the variables timeReceived and timeSent from this skeleton code to retrieve the time. I did 
            not write the code for timeReceived and timeSent as it was given to me in this skeleton code. Also, 
            I modeled the RTT calculation based on a picture of RTT in an article. The TA in this class shared 
            an article with me during office hours. The link to an article is: 

            Source:  https://www.redhat.com/sysadmin/ping-traceroute-netstat

            The article shows a picture of how RTT works when sending an echo request. I used the data from 
            the echo request to calculate the RTT. 
    --------------------------------------------------------------------------------------------------"""
    def __calcRTT(self, timeReceived, timeSent):
        # Calculate RTTs
        current = (timeReceived - timeSent) * 1000
        total, count = self.getRTTtotalAndCount()
        self.setStartEnd(timeReceived, timeSent)

        if (self.getRTTmax() is None) and (self.getRTTmin() is None):
            self.setRTTmax(current)
            self.setRTTmin(current)
            self.setRTTavg(0)

        if (total == 0) and (count == 0):
            self.setRTTtotalAndCount(current, 1)
        else:
            # Set min, max, average
            if current > self.getRTTmax():
                self.setRTTmax(current)
            elif current < self.getRTTmin():
                self.setRTTmin(current)
            total += current
            count += 1
            self.setRTTtotalAndCount(total, 1)
            average = total / count
            self.setRTTavg(average)

            return

    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        def __init__(self):
            self.__RTTmax = None
            self.__RTTmin = None
            self.__RTTavg = None
            self.__RTTcount = 0
            self.__RTTtotal = 0
            self.__RTTstart = 0
            self.__RTTend = 0
            self.__packetTotal = 0
            self.__packetSuccess = 0

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getRTTmax(self):
            return self.__RTTmax

        def getRTTmin(self):
            return self.__RTTmin

        def getRTTavg(self):
            return self.__RTTavg

        def getRTTtotalAndCount(self):
            return self.__RTTtotal, self.__RTTcount

        def getStartEnd(self):
            return self.__RTTstart, self.__RTTend

        def getPacketsQuants(self):
            return self.__packetSuccess, self.__packetTotal

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setRTTmax(self, RTT):
            self.__RTTmax = RTT

        def setRTTmin(self, RTT):
            self.__RTTmin = RTT

        def setRTTavg(self, RTT):
            self.__RTTavg = RTT

        def setRTTtotalAndCount(self, RTT, count):
            self.__RTTtotal = RTT
            self.__RTTcount += count

        def setStartEnd(self, start, end):
            self.__RTTstart = start
            self.__RTTend = end

        def setPacketsQuants(self, good, total):
            self.__packetSuccess += good
            self.__packetTotal += total

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            icmpReplyPacket.setIsValidResponse(True)

            # Get Sequence #, Packet Identifier, and raw data
            sequenceNumber = icmpReplyPacket.getIcmpSequenceNumber()
            packetIdentifier = icmpReplyPacket.getIcmpIdentifier()
            rawData = icmpReplyPacket.getIcmpData()

            # Print Debug Message
            print("---- DEBUG MESSAGE ----")
            # Print expected vs actual output
            print("Actual Output: " + str(self.getPacketSequenceNumber()) + " " + str(self.getPacketIdentifier()) + " "
                  + str(self.getDataRaw()))
            print("Expected Output: " + str(sequenceNumber) + " " + str(packetIdentifier) + " " + str(rawData) + "\n")

            # Set debug value
            icmpReplyPacket.setIdentifierDebug(packetIdentifier, self.getPacketIdentifier())
            icmpReplyPacket.setSequenceDebug(sequenceNumber, self.getPacketSequenceNumber())
            icmpReplyPacket.setDataRawDebug(rawData, self.getDataRaw())

            if ((sequenceNumber == self.getPacketSequenceNumber()) and (packetIdentifier == self.getPacketIdentifier())
                    and (rawData == self.getDataRaw())):
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
                icmpReplyPacket.setIcmpDataRaw_isValid(True)
                return icmpReplyPacket.setIsValidResponse(True)

            else:
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                icmpReplyPacket.setIcmpSequenceNumber_isValid(False)
                icmpReplyPacket.setIcmpDataRaw_isValid(False)
                return icmpReplyPacket.setIsValidResponse(False)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("---------------------------------------------------------------------------------------------------")
            if self.getTtl() == 255 or self.getTtl() == 1:
                print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress + "\n")

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 2
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if not whatReady[0]:  # Timeout
                    self.setIcmpType(3)
                    self.setIcmpCode(3)
                    print("  TTL=%d" % self.getTtl(), "   *            Type=3     Code=3    Request timed out --> Destination Unreachable: Port Unreachable")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Calculate RTTs
                    self.calcRTT(timeReceived, pingStartTime)
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    # For Ping Program
                    if self.getTtl() == 255 and addr[0] == self.__destinationIpAddress:
                        print("[ICMP Type=%d" % icmpType, "] -> Echo Reply: \n")
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)

                        if icmpCode != 0:
                            self.displayICMPcode(self.getIcmpCode())
                            self.setPacketsQuants(1, 1)
                        return  # Echo reply is the end and therefore should return

                    elif icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              + "\n[ICMP Type=%d" % icmpType, "] -> Error: Time Exceeded")
                        self.displayICMPcode(self.getIcmpCode())
                        self.setPacketsQuants(0, 1)

                    elif icmpType == 3 or icmpCode == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  ) + "\n[ICMP Type=%d" % icmpType, "] -> Error: Destination Unreachable")
                        self.displayICMPcode(self.getIcmpCode())
                        self.setPacketsQuants(0, 1)

                    # For traceroute program
                    elif addr[0] == self.__destinationIpAddress and self.getTtl() != 255:
                        print("\n -----> You have arrived at the destination server <----- \n", )
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              ) + "\n[ICMP Type=%d" % icmpType, "] -> Echo Reply")
                        mySocket.close()
                        return 1

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *      Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

        """ ------------------------------------------------------------------------------------------------
        Citations:
        
        I used the variables timeReceived and timeSent from this skeleton code to retrieve the time. I did 
        not write the code for timeReceived and timeSent as it was given to me in this skeleton code. Also, 
        I modeled the RTT calculation based on a picture of RTT in an article. The TA in this class shared 
        an article with me during office hours. The link to an article is: 
        
        Source:  https://www.redhat.com/sysadmin/ping-traceroute-netstat
        
        The article shows a picture of how RTT works when sending an echo request. I used the data from 
        the echo request to calculate the RTT. 
        --------------------------------------------------------------------------------------------------"""
        def calcRTT(self, timeReceived, timeSent):
            # Calculate RTTs
            current = (timeReceived - timeSent) * 1000

            # Initialize the variables
            total, count = self.getRTTtotalAndCount()
            self.setStartEnd(timeReceived, timeSent)

            if (self.getRTTmax() is None) and (self.getRTTmin() is None):
                self.setRTTmax(current)
                self.setRTTmin(current)
                self.setRTTavg(0)

            if (total == 0) and (count == 0):
                self.setRTTtotalAndCount(current, 1)
            else:
                # Set min, max, average
                if current > self.getRTTmax():
                    self.setRTTmax(current)
                elif current < self.getRTTmin():
                    self.setRTTmin(current)
                total += current
                count += 1
                self.setRTTtotalAndCount(total, 1)
                average = total / count
                self.setRTTavg(average)
                return

        """ ----------------------------------------------------------------------------------------------
        Citations: 
        
        Copied all the code from iana.org to keep track of the ICMP code when running this program. 
        
        Source: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        ------------------------------------------------------------------------------------------------"""
        def displayICMPcode(self, icmpCode):
            if icmpCode == 0:
                print("Time To Live Exceeded in Transit")
            elif icmpCode == 1:
                print("Host Unreachable")
            elif icmpCode == 2:
                print("Protocol Unreachable")
            elif icmpCode == 3:
                print("Port Unreachable")
            elif icmpCode == 4:
                print("Fragmentation Needed and Don't Fragment was Set")
            elif icmpCode == 5:
                print("Source Route Failed")
            elif icmpCode == 6:
                print("Destination Network Unknown")
            elif icmpCode == 7:
                print("Destination Host Unknown")
            elif icmpCode == 8:
                print("Source Host Isolated")
            elif icmpCode == 9:
                print("Communication with Destination Network is AdministrativelyProhibited")
            elif icmpCode == 10:
                print("Communication with Destination Host is AdministrativelyProhibited")
            elif icmpCode == 11:
                print("Destination Network Unreachable for Type of Service")
            elif icmpCode == 12:
                print("Destination Host Unreachable for Type of Service")
            elif icmpCode == 13:
                print("Communication Administratively Prohibited")
            elif icmpCode == 14:
                print("Host Precedence Violation")
            elif icmpCode == 15:
                print("Precedence cutoff in effect")

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self._actualRawData = None
            self._expectedRawData = None
            self._actualSeq = None
            self._expectedSeq = None
            self._actualID = None
            self._expectedID = None
            self.__IcmpDataRaw_isValid = None
            self.__IcmpSecuenceNumber_isValid = None
            self.__IcmpIdentifier_isValid = None
            self.__recvPacket = recvPacket
            self._IcmpIdentifier_isValid = False
            self._IcmpSequenceNumber_isValid = False
            self._IcmpDataRaw_isValid = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse
        
        def getIcmpIdentifier_isValid(self):
            return self._IcmpIdentifier_isValid
        
        def getIcmpSequenceNumber_isValid(self):
            return self._IcmpSequenceNumber_isValid
        
        def getIcmpDataRaw_isValid(self):
            return self._IcmpDataRaw_isValid
        
        def getIdentifierDebug(self):
            return self._expectedID, self._actualID
        
        def getSequenceDebug(self):
            return self._expectedSeq, self._actualSeq
        
        def getDataRawDebug(self):
            return self._expectedRawData, self._actualRawData

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, boolVal):
            self.__IcmpIdentifier_isValid = boolVal
        
        def setIcmpSequenceNumber_isValid(self, boolval):
            self.__IcmpSecuenceNumber_isValid = boolval

        def setIcmpDataRaw_isValid(self, boolval):
            self.__IcmpDataRaw_isValid = boolval
        
        def setIdentifierDebug(self, expected, actual):
            # Sets the Ids of expected and actual values
            self._expectedID = expected
            self._actualID = actual
        
        def setSequenceDebug(self, expected, actual):
            # Sets the Sequences of expected and actual values
            self._expectedSeq = expected
            self._actualSeq = actual
        
        def setDataRawDebug(self, expected, actual):
            # Sets the Raw Data of expected and actual values
            self._expectedRawData = expected
            self._actualRawData = actual

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            print("*** PACKET DETAILS ***")
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]

            # Is the icmp identifier valid?
            if self.getIcmpIdentifier_isValid():
                print("Identifier is valid")
            else:
                expected, actual = self.getIdentifierDebug()
                print("Expected Identifier: ", expected, " Actual: ", actual)

            # Is the icmp sequence valid?
            if self.getIcmpSequenceNumber_isValid():
                print("Sequence Number is valid")
            else:
                expected, actual = self.getSequenceDebug()
                print("Expected Sequence Number: ", expected, " Actual: ", actual)

            # Is the icmp raw data valid?
            if self.getIcmpDataRaw_isValid():
                print("Raw Data is valid")
            else:
                expected, actual = self.getDataRawDebug()
                print("Expected Raw Data: ", expected, " Actual: ", actual)

            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  ) + "\n")

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            start, end = icmpPacket.getStartEnd()
            self.__calcRTT(start, end)

            """ ----------------------------------------------------------------------------------------------
            Citation: 
            
            I used the ICMP Type Code and ICMP Code from iana.org to understand what happened to the packets
            I sent through Ping and Traceroute. 
            
            Source: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
            -----------------------------------------------------------------------------------------------"""
            if icmpPacket.getIcmpType() == 8:
                self.setPacketsQuants(1, 1)
                good, total = icmpPacket.getPacketsQuants()
                self.setPacketsQuants(good, total)
                print("Reply from %s" % host, ": bytes=", len(icmpPacket.getDataRaw()), " time=", ((start - end) * 1000), " TTL: ", self.getttl())
                

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

            if i == 3:
                print("\n*** Ping Statistics for: ", host, "***\nMaximum RTT: ", self.getRTTmax(), "\nMinimum RTT: ", self.getRTTmin(), "\nAverage RTT: ",
                    self.getRTTavg(), "\n")
                good, total = self.getPacketsQuants()
                if total != 0:
                    packetLoss = ((self.__packetTotal - self.__packetSuccess) / self.__packetTotal) * 100
                    print("Packets: Sent = ", self.__packetTotal, ", Received = ", self.__packetSuccess)
                    print("Packet Loss: ", packetLoss, "%")
                else:
                    print("Packet Loss: No packets were sent, so packet loss is undefined\n")

    """ ---------------------------------------------------------------------------------------------------
    Citations: 
    
    To implement a traceroute function, I have researched online and 
    found a helpful article by a programmer, Marin Atanasov Nikolov. In the article, it shows
    how to implement a simple traceroute function, so I used some of the code as a starter code. I then
    coded the rest of the implementation, on my own, to get the traceroute to work. The link to the article is: 
    
    Source:  https://dnaeon.github.io/traceroute-in-python/
    
    I also copied and pasted some of the skeleton code from the "def __sendIcmpEchoRequest(self, host)"
    function, above, into this traceroute function so that I can build packets and send it to the server. 
    I do not know who the author of this skeleton code, so I can't name the person. Sorry
    ------------------------------------------------------------------------------------------------------- """
    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here
        try:
            self.destinationIp = gethostbyname(host)
        except error as e:
            raise IOError("Unable to resolve, {}".format(e))

        text = 'traceroute to {} ({}), {} hops max'.format(host, self.destinationIp, self.hops)
        print("\n\n***** Traceroute Started *****\n")
        print(text)
        stopOrNot = 0
        i = 0

        while stopOrNot != 1:
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16-bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            while stopOrNot != 1:
                receiver = self.createReceiver()
                sender = self.createSender()
                sender.sendto(b'', (host, self.port))
                address = [0 for i in range(self.hops)]

                try:
                    icmpPacket = IcmpHelperLibrary.IcmpPacket()
                    icmpPacket.setIcmpTarget(self.destinationIp)
                    icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)
                    icmpPacket.setTtl(self.ttl)
                    stopOrNot = icmpPacket.sendEchoRequest()
                    self.ttl += 1
                    i += 1
                    data, address = receiver.recvfrom(2048)
                    print("\nThis router's IP Address: ", address)

                    if address == self.destinationIp:
                        break

                except timeout:
                    print("Pinging next available router...")
                except error as e:
                    raise IOError('Socket error: {}'.format(e))
                finally:
                    receiver.close()
                    sender.close()

        print("\n\n***** Trace Complete *****\n\n")

    def createReceiver(self):
        sock = socket(family=AF_INET, type=SOCK_RAW, proto=IPPROTO_ICMP)
        try:
            sock.bind(('', self.getport()))
            sock.settimeout(10)
        except error as e:
            raise IOError('Unable to bind receiver socket: {}'.format(e))
        return sock

    def createSender(self):
        sock = socket(family=AF_INET, type=SOCK_DGRAM, proto=IPPROTO_UDP)
        sock.setsockopt(IPPROTO_IP, IP_TTL, self.ttl)
        return sock

    def getttl(self):
        return self.ttl

    def getport(self):
        return self.port

    def incTTL(self):
        self.ttl += 1

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    #icmpHelperPing.sendPing("209.233.126.254")
    #icmpHelperPing.sendPing("www.google.com")
    icmpHelperPing.sendPing("gaia.cs.umass.edu")
    #icmpHelperPing.sendPing("164.151.129.20")
    #icmpHelperPing.sendPing("122.56.99.243")
    icmpHelperPing.traceRoute("104.21.28.187")           # Italian website: www.eabianca.it
    #icmpHelperPing.traceRoute("164.151.129.20")
    #icmpHelperPing.traceRoute("142.250.189.164")
    #icmpHelperPing.traceRoute("199.59.243.224")         # Pearson's server at www.pearson.uk
    #icmpHelperPing.traceRoute("34.101.125.250")         # Google's server in Jakarta Indonesia
    

if __name__ == "__main__":
    main()
