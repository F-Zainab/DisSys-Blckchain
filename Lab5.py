import hashlib
import socket
import selectors
import time
from datetime import datetime

MSG_HDR_SIZE=24
GENESIS_BLOCK_HASH=bytes.fromhex('6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000')
MAGIC_BYTES=bytes.fromhex('f9beb4d9')
VERSION=70015

VERSION_MSG='version'
VERACK_MSG='verack'
GETHEADERS_MSG='getheaders'
HEADERS_MSG='headers'
GETDATA_MSG='getdata'
BLOCK_MSG='block'

class Utility(object):
    @staticmethod
    def GetHash(data):
        hash1 = hashlib.sha256(data).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return hash2

    @staticmethod
    def GetChecksum(data):
        hash = Utility.GetHash(data)
        checksum = hash[:4]
        return checksum

    @staticmethod
    def GetEpochTime():
        epoch = datetime(1970, 1, 1)
        utc = datetime.utcnow()
        return (utc - epoch).total_seconds()

    @staticmethod
    def GetEpochTimeAsStr(epochTime):
        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(epochTime))

    @staticmethod
    def IntToBytes(n, sizeInBytes):
        return int(n).to_bytes(sizeInBytes, byteorder='little', signed=True)

    @staticmethod
    def UintToBytes(n, sizeInBytes):
        return int(n).to_bytes(sizeInBytes, byteorder='little', signed=False)

    @staticmethod
    def IntFromBytes(b):
        return int.from_bytes(b, byteorder='little', signed=True)

    @staticmethod
    def UintFromBytes(b):
        return int.from_bytes(b, byteorder='little', signed=False)

    @staticmethod
    def BoolToBytes(flag):
        return Utility.UintToBytes(1 if flag else 0, 1)

    @staticmethod
    def BoolFromBytes(b):
        return Utility.UintFromBytes(b) == 1

    @staticmethod
    def IPv4ToIPv6(ipv4Str):
        pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        return pchIPv4 + bytearray((int(x) for x in ipv4Str.split('.')))

    @staticmethod
    def IPv4FromIPv6(ipv6):
        return '.'.join([str(b) for b in ipv6[12:]])

class ByteStreamReader(object):
    def __init__(self, bytesBuffer=b''):
        self.rIdx = 0
        self.byteBuffer = bytesBuffer

    def EnsureBytesAvailable(self, count):
        size = len(self.byteBuffer)
        if self.rIdx + count > size:
            raise ValueError(f'More bytes than available requested. CurrentIdx={self.rIdx}, Requested={count}, BufferSize={size}')

    def ReadNextBytes(self, count):
        self.EnsureBytesAvailable(count)
        bytes = self.byteBuffer[self.rIdx:self.rIdx + count]
        self.rIdx = self.rIdx + count
        return bytes

    def SkipNextBytes(self, count):
        self.EnsureBytesAvailable(count)
        self.rIdx = self.rIdx + count

    def ReadBytesCount(self):
        return self.rIdx

    def RemainingBytes(self):
        return self.byteBuffer[self.rIdx:]

    def HasRemaininBytes(self):
        return self.rIdx < len(self.byteBuffer)

    def Append(self, bytesBuffer):
        self.byteBuffer += bytesBuffer

    def DiscardReadMessage(self):
        self.byteBuffer = self.RemainingBytes()
        self.rIdx = 0
        size = len(self.byteBuffer)
        if size > 0 and self.byteBuffer[:4] != MAGIC_BYTES:
            raise ValueError(f'Read stream must begin at magic bytes.')

    def HasNextMessage(self):
        if len(self.byteBuffer) < MSG_HDR_SIZE:
            return False
        payloadSizeBytes = self.byteBuffer[16:20]
        payloadSize = Utility.UintFromBytes(payloadSizeBytes)
        if len(self.byteBuffer) < (MSG_HDR_SIZE + payloadSize):
            return False
        return True

    def GetMessageBytes(self):
        payloadSizeBytes = self.byteBuffer[16:20]
        payloadSize = Utility.UintFromBytes(payloadSizeBytes)
        msgSize = MSG_HDR_SIZE + payloadSize
        return self.byteBuffer[:msgSize]

class CompactSize(object):
    @staticmethod
    def Serialize(n):
        if n <= 252:
            return Utility.UintToBytes(n, 1)
        if n <= 0xffff:
            return bytes.fromhex('fd') + Utility.UintToBytes(n, 2)
        if n <= 0xffffffff:
            return bytes.fromhex('fe') + Utility.UintToBytes(n, 4)
        return bytes.fromhex('ff') + Utility.UintToBytes(n, 8)

    @staticmethod
    def Derialize(streamReader : ByteStreamReader):
        key = streamReader.ReadNextBytes(1)
        if key == bytes.fromhex('ff'):
            return Utility.UintFromBytes(streamReader.ReadNextBytes(8))
        if key == bytes.fromhex('fe'):
            return Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        if key == bytes.fromhex('fd'):
            return Utility.UintFromBytes(streamReader.ReadNextBytes(2))
        return Utility.UintFromBytes(key)

# See https://bitcoin.org/en/developer-reference#message-headers
class MessageHeader(object):
    def __init__(self, commandName=None, payloadSize=None, checksum=None):
        self.MagicBytes = MAGIC_BYTES
        self.CommandName = commandName
        self.PayloadSize = payloadSize
        self.Checksum = checksum
    
    def CommandNameToBytes(self):
        targetBuffer = bytearray(12)
        cmdBytes = self.CommandName.encode(encoding='utf-8')
        targetBuffer[:len(cmdBytes)] = cmdBytes
        return targetBuffer
    
    def Serialize(self):
        msgBytes = self.MagicBytes
        msgBytes += self.CommandNameToBytes()
        msgBytes += Utility.UintToBytes(self.PayloadSize, 4)
        msgBytes += self.Checksum
        return msgBytes
    
    @staticmethod
    def CommandNameFromBytes(bytesBuffer):
        cmdBytes = bytearray([b for b in bytesBuffer if b != 0])
        return str(cmdBytes, encoding='utf-8')

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        mh = MessageHeader()
        mh.MagicBytes = streamReader.ReadNextBytes(4)
        mh.CommandName = MessageHeader.CommandNameFromBytes(streamReader.ReadNextBytes(12))
        mh.PayloadSize = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        mh.Checksum = streamReader.ReadNextBytes(4)
        return mh

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}HEADER")
        print(f"{padding}------")
        padding += '  '
        print(f"{padding}{'MagicBytes':25}{self.MagicBytes.hex()}")
        print(f"{padding}{'CommandName':25}{self.CommandName}")
        print(f"{padding}{'PayloadSize':25}{self.PayloadSize}")
        print(f"{padding}{'Checksum':25}{self.Checksum.hex()}")

# See https://bitcoin.org/en/developer-reference#version
class VersionMessage(object):
    def __init__(self, senderAddress=(None, None), receiverAddress=(None, None)):
        self.Version = VERSION
        self.Services = 0
        self.TimeStamp = Utility.GetEpochTime()
        self.ReceiverServices = 0x01
        self.ReceiverIP = receiverAddress[0]
        self.ReceiverPort = receiverAddress[1]
        self.SenderServices = 0
        self.SenderIP = senderAddress[0]
        self.SenderPort = senderAddress[1]
        self.Nonce = 0
        self.UserAgentByteCount = 0
        self.UserAgent = None
        self.StartHeight = 0
        self.Relay = False

    def Serialize(self):
        msgBytes = Utility.IntToBytes(self.Version, 4)
        msgBytes += Utility.UintToBytes(self.Services, 8)
        msgBytes += Utility.IntToBytes(self.TimeStamp, 8)
        msgBytes += Utility.UintToBytes(self.ReceiverServices, 8)
        msgBytes += Utility.IPv4ToIPv6(self.ReceiverIP)
        msgBytes += Utility.UintToBytes(self.ReceiverPort, 2)
        msgBytes += Utility.UintToBytes(self.SenderServices, 8)
        msgBytes += Utility.IPv4ToIPv6(self.SenderIP)
        msgBytes += Utility.UintToBytes(self.SenderPort, 2)
        msgBytes += Utility.UintToBytes(self.Nonce, 8)
        msgBytes += CompactSize.Serialize(self.UserAgentByteCount)
        if self.UserAgentByteCount > 0:
            msgBytes += self.UserAgent
        msgBytes += Utility.IntToBytes(self.StartHeight, 4)
        msgBytes += Utility.BoolToBytes(self.Relay)
        return msgBytes

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        verMsg = VersionMessage()
        verMsg.Version = Utility.IntFromBytes(streamReader.ReadNextBytes(4))
        verMsg.Services = Utility.UintFromBytes(streamReader.ReadNextBytes(8))
        verMsg.TimeStamp = Utility.IntFromBytes(streamReader.ReadNextBytes(8))
        verMsg.ReceiverServices = Utility.UintFromBytes(streamReader.ReadNextBytes(8))
        verMsg.ReceiverIP = Utility.IPv4FromIPv6(streamReader.ReadNextBytes(16))
        verMsg.ReceiverPort = Utility.UintFromBytes(streamReader.ReadNextBytes(2))
        verMsg.SenderServices = Utility.UintFromBytes(streamReader.ReadNextBytes(8))
        verMsg.SenderIP = Utility.IPv4FromIPv6(streamReader.ReadNextBytes(16))
        verMsg.SenderPort = Utility.UintFromBytes(streamReader.ReadNextBytes(2))
        verMsg.Nonce = Utility.UintFromBytes(streamReader.ReadNextBytes(8))
        verMsg.UserAgentByteCount = CompactSize.Derialize(streamReader)
        verMsg.UserAgent = streamReader.ReadNextBytes(verMsg.UserAgentByteCount)
        verMsg.StartHeight = Utility.IntFromBytes(streamReader.ReadNextBytes(4))
        verMsg.Relay = Utility.BoolFromBytes(streamReader.ReadNextBytes(1))
        return verMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}VERSION")
        print(f"{padding}-------")
        padding += '  '
        print(f"{padding}{'Version':25}{self.Version}")
        print(f"{padding}{'Services':25}{hex(self.Services)}")
        print(f"{padding}{'TimeStamp':25}{Utility.GetEpochTimeAsStr(self.TimeStamp)}")
        print(f"{padding}{'ReceiverServices':25}{hex(self.ReceiverServices)}")
        print(f"{padding}{'ReceiverIP':25}{self.ReceiverIP}")
        print(f"{padding}{'ReceiverPort':25}{self.ReceiverPort}")
        print(f"{padding}{'SenderServices':25}{hex(self.SenderServices)}")
        print(f"{padding}{'SenderIP':25}{self.SenderIP}")
        print(f"{padding}{'SenderPort':25}{self.SenderPort}")
        print(f"{padding}{'Nonce':25}{self.Nonce}")
        print(f"{padding}{'UserAgentByteCount':25}{self.UserAgentByteCount}")
        print(f"{padding}{'UserAgent':25}{self.UserAgent.hex()}")
        print(f"{padding}{'StartHeight':25}{self.StartHeight}")
        print(f"{padding}{'Relay':25}{self.Relay}")

# see https://bitcoin.org/en/developer-reference#getheaders
class GetHeadersMessage(object):
    def __init__(self):
        self.Version = VERSION
        #self.Version = 70002
        self.HashCount = 0
        self.BlockHeaderHashes = []
        self.StopHash = bytearray(32)

    def Serialize(self):
        message = Utility.UintToBytes(self.Version, 4)
        message += CompactSize.Serialize(self.HashCount)
        for headerHash in self.BlockHeaderHashes:
            message += headerHash
        message += self.StopHash
        return message

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        ghMsg = GetHeadersMessage()
        ghMsg.Version = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        ghMsg.HashCount = CompactSize.Derialize(streamReader)
        for __ in range(0, ghMsg.HashCount):
            ghMsg.BlockHeaderHashes.append(streamReader.ReadNextBytes(32))
        ghMsg.StopHash = streamReader.ReadNextBytes(32)
        return ghMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}GETHEADER")
        print(f"{padding}-------------------")
        padding += '  '
        print(f"{padding}{'Version':25}{self.Version}")
        print(f"{padding}{'HashCount':25}{self.HashCount}")
        if self.HashCount > 0:
            print(f"{padding}{'FirstBlockHeaderHash':25}{self.BlockHeaderHashes[0].hex()}")
            print(f"{padding}{'LastBlockHeaderHash':25}{self.BlockHeaderHashes[self.HashCount - 1].hex()}")
        print(f"{padding}{'StopHash':25}{self.StopHash.hex()}")

# https://bitcoin.org/en/developer-reference#block-headers
class BlockHeader(object):
    def __init__(self):
        self.Version = None
        self.PrevBlockHeaderHash = None
        self.MerkelRootHash = None
        self.Time = None
        self.NBits = None
        self.Nonce = None 
    
    def Serialize(self):
        message = Utility.IntToBytes(self.Version, 4)
        message += self.PrevBlockHeaderHash
        message += self.MerkelRootHash
        message += Utility.UintToBytes(self.Time, 4)
        message += Utility.UintToBytes(self.NBits, 4)
        message += Utility.UintToBytes(self.Nonce, 4)
        return message

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        bh = BlockHeader()
        bh.Version = Utility.IntFromBytes(streamReader.ReadNextBytes(4))
        bh.PrevBlockHeaderHash = streamReader.ReadNextBytes(32)
        bh.MerkelRootHash = streamReader.ReadNextBytes(32)
        bh.Time = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        bh.NBits = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        bh.Nonce = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        return bh

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}BLOCKHEADER")
        print(f"{padding}-------------------")
        padding += '  '
        print(f"{padding}{'Version':25}{self.Version}")
        print(f"{padding}{'PrevBlockHeaderHash':25}{self.PrevBlockHeaderHash.hex()}")
        print(f"{padding}{'MerkelRootHash':25}{self.MerkelRootHash.hex()}")
        print(f"{padding}{'Time':25}{Utility.GetEpochTimeAsStr(self.Time)}")
        print(f"{padding}{'NBits':25}{self.NBits}")
        print(f"{padding}{'Nonce':25}{self.Nonce}")

# See https://bitcoin.org/en/developer-reference#txout
class TransactionOutput(object):
    def __init__(self):
        self.Value = None
        self.PkScriptByteCount = 0
        self.PkScript = None

    ##TODO: Something missing in deserilization of Block which is causing 
    ##      'Value' to be negative and then 'PkScriptByteCount' to have
    ##      arbitrarily large value.
    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        tMsg = TransactionOutput()
        tMsg.Value = Utility.IntFromBytes(streamReader.ReadNextBytes(8))
        tMsg.PkScriptByteCount = CompactSize.Derialize(streamReader)
        tMsg.PkScript = streamReader.ReadNextBytes(tMsg.PkScriptByteCount)
        return tMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}TRANSACTION OUTPUT")
        print(f"{padding}-------------------")
        padding += '  '
        print(f"{padding}{'Value':25}{self.Value}")
        print(f"{padding}{'PkScriptByteCount':25}{self.PkScriptByteCount}")
        if self.PkScriptByteCount > 0:
            bytesToDisp = min(50, self.PkScriptByteCount)
            print(f"{padding}{'PkScript':25}{self.PkScript[:bytesToDisp].hex()}")

# See https://bitcoin.org/en/developer-reference#outpoint
class Outpoint(object):
    def __init__(self):
        self.TxnId = None
        self.Index = None

    def Serialize(self):
        pass

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        oMsg = Outpoint()
        oMsg.TxnId = streamReader.ReadNextBytes(32)
        oMsg.Index = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        return oMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}OUTPOINT")
        print(f"{padding}--------")
        padding += '  '
        print(f"{padding}{'TxnId':25}{self.TxnId.hex()}")
        print(f"{padding}{'Index':25}{self.Index}")

# See https://bitcoin.org/en/developer-reference#txin
class TransactionInput(object):
    def __init__(self):
        self.PrevOutput = None
        self.ScriptByteCount = 0
        self.SignatureScript = None
        self.Sequence = None

    def Serialize(self):
        pass

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        tMsg = TransactionInput()
        tMsg.PrevOutput =  Outpoint.Deserialize(streamReader)
        tMsg.ScriptByteCount = CompactSize.Derialize(streamReader)
        tMsg.SignatureScript = streamReader.ReadNextBytes(tMsg.ScriptByteCount)
        tMsg.Sequence = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        return tMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}TRANSACTION INPUT")
        print(f"{padding}-------------------")
        padding += '  '
        self.PrevOutput.Print(paddingSize + 2)
        print(f"{padding}{'ScriptByteCount':25}{self.ScriptByteCount}")
        if self.ScriptByteCount > 0:
            bytesToDisp = min(50, self.ScriptByteCount)
            print(f"{padding}{'SignatureScript':25}{self.SignatureScript[:bytesToDisp].hex()}")
        print(f"{padding}{'Sequence':25}{self.Sequence}")

# See https://bitcoin.org/en/developer-reference#coinbase
class CoinbaseInput(object):
    def __init__(self):
        self.Hash = None
        self.Index = None
        self.ScriptByteCount = 0
        self.Height = None
        self.CoinbaseScript = None
        self.Sequence = None

    def Serialize(self):
        pass

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader, txnVersion):
        cbMsg = CoinbaseInput()
        cbMsg.Hash =  streamReader.ReadNextBytes(32)
        cbMsg.Index = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        cbMsg.ScriptByteCount = CompactSize.Derialize(streamReader)
        if txnVersion != 1:
            cbMsg.Height = streamReader.ReadNextBytes(4)
        cbMsg.CoinbaseScript = streamReader.ReadNextBytes(cbMsg.ScriptByteCount)
        cbMsg.Sequence = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        return cbMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}TRANSACTION INPUT")
        print(f"{padding}-------------------")
        padding += '  '
        print(f"{padding}{'Hash':25}{self.Hash.hex()}")
        print(f"{padding}{'Index':25}{self.Index}")
        print(f"{padding}{'ScriptByteCount':25}{self.ScriptByteCount}")
        if self.Height is not None:
            print(f"{padding}{'Height':25}{self.Height.hex()}")
        if self.ScriptByteCount > 0:
            bytesToDisp = min(50, self.ScriptByteCount)
            print(f"{padding}{'CoinbaseScript':25}{self.CoinbaseScript[:bytesToDisp].hex()}")
        print(f"{padding}{'Sequence':25}{self.Sequence}")

# See https://bitcoin.org/en/developer-reference#raw-transaction-format
class Transaction(object):
    def __init__(self):
        self.Version = None
        self.TxnInputCount = 0
        self.TxnInputs = []
        self.IsCoinbaseTxn = False
        self.CoinbaseInput = None
        self.TxnOutputCount = 0
        self.TxnOutputs = []
        self.LockTime = None

    def Serialize(self):
        pass
    
    @staticmethod
    def Deserialize(streamReader: ByteStreamReader, isCoinbaseTxn=False):
        tMsg = Transaction()
        tMsg.Version = Utility.IntFromBytes(streamReader.ReadNextBytes(4))
        tMsg.TxnInputCount = CompactSize.Derialize(streamReader)
        tMsg.IsCoinbaseTxn = isCoinbaseTxn
        if tMsg.IsCoinbaseTxn == True:
            tMsg.CoinbaseInput = CoinbaseInput.Deserialize(streamReader, tMsg.Version)
        else:
            for __ in range(0, tMsg.TxnInputCount):
                txnInput = TransactionInput.Deserialize(streamReader)
                tMsg.TxnInputs.append(txnInput)
        tMsg.TxnOutputCount = CompactSize.Derialize(streamReader)
        for __ in range(0, tMsg.TxnOutputCount):
            txnOutput = TransactionOutput.Deserialize(streamReader)
            tMsg.TxnOutputs.append(txnOutput)
        tMsg.LockTime = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        return tMsg

    def Print(self, paddingSize, suffix):
        padding = ' ' * paddingSize
        print(f"{padding}TRANSACTION {suffix}")
        print(f"{padding}--------------------")
        padding += '  '
        print(f"{padding}{'Version':25}{self.Version}")
        print(f"{padding}{'TxnInputCount':25}{self.TxnInputCount}")
        print(f"{padding}{'TxnOutputCount':25}{self.TxnOutputCount}")
        print(f"{padding}{'LockTime':25}{self.LockTime}")

# See https://bitcoin.org/en/developer-reference#block
class Block(object):
    def __init__(self):
        self.Header = None
        self.TxnCount = 0
        self.Txns = []

    def Serialize(self):
        pass

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        bMsg = Block()
        bMsg.Header = BlockHeader.Deserialize(streamReader)
        bMsg.TxnCount = CompactSize.Derialize(streamReader)
        for i in range(0, bMsg.TxnCount):
            isCoinbaseTxn = (i == 0)
            bMsg.Txns.append(Transaction.Deserialize(streamReader, isCoinbaseTxn))
        return bMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}BLOCK")
        print(f"{padding}-----")
        padding += '  '
        self.Header.Print(paddingSize + 2)
        print(f"{padding}{'TxnCount':25}{self.TxnCount}")
        for i in range(0, self.TxnCount):
            self.Txns[i].Print(paddingSize + 2, ' #' + str(i))

# See https://bitcoin.org/en/developer-reference#data-messages
class Inventory(object):
    def __init__(self, type=None, objHash=None):
        self.Type = type
        self.ObjHash = objHash

    def Serialize(self):
        message = Utility.UintToBytes(self.Type, 4)
        message += self.ObjHash
        return message
    
    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        inv = Inventory()
        inv.Type = Utility.UintFromBytes(streamReader.ReadNextBytes(4))
        inv.ObjHash = streamReader.ReadNextBytes(32)
        return inv
    
    def GetTypeStr(self):
        if self.Type == 2:
            return 'MSG_BLOCK'
        return 'UNEXPECTED'

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}INVENTORY")
        print(f"{padding}-----------------")
        padding += '  '
        print(f"{padding}{'Type':25}{self.GetTypeStr()}")
        print(f"{padding}{'Hash':25}{self.ObjHash.hex()}")

# See https://bitcoin.org/en/developer-reference#getdata
class GetDataMessage(object):
    def __init__(self):
        self.Count = 0
        self.Inventories = []

    def Serialize(self):
        message = CompactSize.Serialize(self.Count)
        for inv in self.Inventories:
            message += inv.Serialize()
        return message
    
    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        gdMsg = GetDataMessage()
        gdMsg.Count = CompactSize.Derialize(streamReader)
        for __ in range(0, gdMsg.Count):
            gdMsg.Inventories.append(Inventory.Deserialize(streamReader))
        return gdMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}GETDATA")
        print(f"{padding}---------------")
        padding += '  '
        print(f"{padding}{'Count':25}{self.Count}")
        self.Inventories[self.Count - 1].Print(paddingSize + 2)


# See https://bitcoin.org/en/developer-reference#headers
class HeadersMessage(object):
    def __init__(self):
        self.Count = 0
        self.Headers = []
    
    def Serialize(self):
        msgBytes = CompactSize.Serialize(self.Count)
        for hdr in self.Headers:
            msgBytes += hdr.Serialize()
            msgBytes += bytearray(1)
        return msgBytes

    def GetLastHeaderHash(self):
        return self.GetHeaderHash(self.Count - 1)

    def GetHeaderHash(self, blockHeaderIdx):
        blockHeader = self.Headers[blockHeaderIdx]
        #blockHeaderBytes = blockHeader.Serialize()
        #return Utility.GetHash(blockHeaderBytes)
        return blockHeader.PrevBlockHeaderHash

    @staticmethod
    def Deserialize(streamReader: ByteStreamReader):
        hMsg = HeadersMessage()
        hMsg.Count = CompactSize.Derialize(streamReader)
        for __ in range(0, hMsg.Count):
            hMsg.Headers.append(BlockHeader.Deserialize(streamReader))
            streamReader.ReadNextBytes(1) # transaction count 0x00
        return hMsg

    def Print(self, paddingSize):
        padding = ' ' * paddingSize
        print(f"{padding}BLOCK HEADERS")
        print(f"{padding + '-' * 56}")
        padding += '  '
        print(f"{padding}{'Count':25}{self.Count}")
        lastHeader = self.Headers[self.Count - 1]
        lastHeader.Print(paddingSize + 2)

class MessageBuilder(object):
    def __init__(self):
        self.EmtyPayloadChecksum = bytes.fromhex('5df6e0e2')

    def BuildMessage(self, msgType, payloadBytes):
        checksum = Utility.GetChecksum(payloadBytes)
        headerMessage = MessageHeader(msgType, len(payloadBytes), checksum)
        headerBytes = headerMessage.Serialize()
        message = headerBytes + payloadBytes
        return message

    def BuildVersionMessage(self, receiverAddr, senderAddr):
        versionMssg = VersionMessage(receiverAddr, senderAddr)
        payloadBytes = versionMssg.Serialize()
        return self.BuildMessage(VERSION_MSG, payloadBytes)
    
    # See https://bitcoin.org/en/developer-reference#verack
    # See https://bitcoin.org/en/developer-reference#message-headers
    def BuildVerAckMessage(self):
        headerMessage = MessageHeader(VERACK_MSG, 0, self.EmtyPayloadChecksum)
        headerBytes = headerMessage.Serialize()
        return headerBytes

    def BuildGetHeadersMessage(self, blockHeaderHash):
        getHeadersMsg = GetHeadersMessage()
        getHeadersMsg.HashCount = 1
        getHeadersMsg.BlockHeaderHashes = [blockHeaderHash]
        payloadBytes = getHeadersMsg.Serialize()
        return self.BuildMessage(GETHEADERS_MSG, payloadBytes)

    def BuildGetDataMessageForBlock(self, blockHeaderHash):
        getDataMsg = GetDataMessage()
        getDataMsg.Count = 1
        getDataMsg.Inventories = [Inventory(2, blockHeaderHash)]
        payloadBytes = getDataMsg.Serialize()
        return self.BuildMessage(GETDATA_MSG, payloadBytes)

    def PrintMessage(self, byteBuffer, prefix=None):
        streamReader = ByteStreamReader(byteBuffer)
        header = MessageHeader.Deserialize(streamReader)
        print(f'\n{prefix} [{header.CommandName}] MESSAGE')
        print('-' * 80)
        if len(byteBuffer) <= 40:
            print(byteBuffer.hex())
        else:
            print(byteBuffer[:40].hex() + '...')
        print('-' * 80)
        header.Print(2)

        msg = None
        if header.CommandName == VERSION_MSG:
            msg = VersionMessage.Deserialize(streamReader)
        if header.CommandName == GETHEADERS_MSG:
            msg = GetHeadersMessage.Deserialize(streamReader)
        if header.CommandName == HEADERS_MSG:
            msg = HeadersMessage.Deserialize(streamReader)
        if header.CommandName == GETDATA_MSG:
            msg = GetDataMessage.Deserialize(streamReader)
        if header.CommandName == BLOCK_MSG:
            msg = BlockMessage.Deserialize(streamReader)
        if msg is not None:
            msg.Print(2)

class Node(object):
    def __init__(self, peerAddress):
        self.peerAddress = peerAddress
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.msgBuilder = MessageBuilder()
        self.streamReader = ByteStreamReader()
        self.latestBlockHeaderHash = GENESIS_BLOCK_HASH
        self.blockHeaderCount = 1
        self.targetBlockNumber = 4062477 % 600000 # SU ID % 600000
        
        self.clientSocket.setblocking(True)
        self.clientSocket.connect(self.peerAddress)
        self.myAddress = self.clientSocket.getsockname()

    def ProcessPayload(self, commandName):
        processed = True
        if commandName == VERSION_MSG:
            versionMsg = VersionMessage.Deserialize(self.streamReader)
            versionMsg.Print(2)
            verAckMsg = self.msgBuilder.BuildVerAckMessage()
            self.SendMessage(verAckMsg)
        elif commandName == VERACK_MSG:
            getHeadersMsg = self.msgBuilder.BuildGetHeadersMessage(self.latestBlockHeaderHash)
            self.SendMessage(getHeadersMsg)
        elif commandName == HEADERS_MSG:
            headersMsg = HeadersMessage.Deserialize(self.streamReader)
            headersMsg.Print(2)

            self.blockHeaderCount += headersMsg.Count
            self.latestBlockHeaderHash = headersMsg.GetLastHeaderHash()

            print('-----------------------------------------------------------')
            print(f'\nRECEIVED BLOCK HEADER COUNT={self.blockHeaderCount}')
            print(f'TARGET BLOCK NUMBER={self.targetBlockNumber}')
            print(f'LATEST BLOCK HEADER HASH={self.latestBlockHeaderHash.hex()}')
            print('-----------------------------------------------------------')

            if self.blockHeaderCount < self.targetBlockNumber:
                getHeadersMsg = self.msgBuilder.BuildGetHeadersMessage(self.latestBlockHeaderHash)
                self.SendMessage(getHeadersMsg)
            else:
                blockIdx = self.targetBlockNumber - (self.blockHeaderCount - headersMsg.Count) - 1
                targetBlockHeaderHash = headersMsg.GetHeaderHash(blockIdx)
                getDataMsg = self.msgBuilder.BuildGetDataMessageForBlock(targetBlockHeaderHash)
                self.SendMessage(getDataMsg)
        elif commandName == BLOCK_MSG:
            blockMsg = Block.Deserialize(self.streamReader)
            blockMsg.Print(2)
        else:
            processed = False
        return processed

    def Display(self, msgBytes, header):
        print(f'\nRECEIVED [{header.CommandName}] MESSAGE')
        print('-' * 80)
        if len(msgBytes) <= 40:
            print(msgBytes.hex())
        else:
            print(msgBytes[:40].hex() + '...')
        print('-' * 80)
        header.Print(2)
        if header.CommandName == BLOCK_MSG:
            f = open("Header" + str(Utility.GetEpochTime()) + ".txt", "w", encoding='utf8')
            f.write(msgBytes.hex())
            f.close()

    def HandleMessage(self):
        self.clientSocket.setblocking(True)
        msgBytes = self.clientSocket.recv(4096)
        self.clientSocket.setblocking(False)

        if len(msgBytes) == 0:
            print(f'Empty message recevied.')
            return
        self.streamReader.Append(msgBytes)

        while self.streamReader.HasNextMessage() == True:
            msgBytes = self.streamReader.GetMessageBytes()
            header = MessageHeader.Deserialize(self.streamReader)
            self.Display(msgBytes, header)
            if self.ProcessPayload(header.CommandName) == False:
                self.streamReader.SkipNextBytes(header.PayloadSize)
            self.streamReader.DiscardReadMessage()

    def SendMessage(self, msg):
        self.msgBuilder.PrintMessage(msg, 'SENDING')
        self.clientSocket.sendall(msg)

    def Run(self):
        verMsg = self.msgBuilder.BuildVersionMessage(self.myAddress, self.peerAddress)
        self.SendMessage(verMsg)

        selector = selectors.DefaultSelector()
        self.clientSocket.setblocking(False)
        selector.register(self.clientSocket, selectors.EVENT_READ)
        while True:
            events = selector.select(timeout = 10)
            for __, __ in events:
                self.HandleMessage()

targetAddress = ('34.192.2.58', 8333)
node = Node(targetAddress)
node.Run()
