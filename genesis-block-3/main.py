import hashlib
import struct
import time

from construct import *

from utils import *


def getGenesisBlock(time=int(time.time()),
                    pszTimestamp='The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
                    pubkey='045c13d245cfbe91faee1abc8edaa874cf9404eba4d280afed882d57f09c5deefdc6b49047b6e0595e7858a00b5da95a9448ea9b9784dd876dfe898c1bdca048cd',
                    nonce=0,
                    bits=0x1d00ffff,
                    value=5000000000):
    print("start mining...")
    hashMerkleRoot = getHashMerkleRoot(pubkey, pszTimestamp, value)
    blockHeader = createBlockHeader(hashMerkleRoot, time, bits, nonce)
    genesisHash, nonce = tryToGetHash(blockHeader, bits, nonce)

    print("\r\n------input------")
    print("time: " + str(time))
    print("pszTimestamp: " + pszTimestamp)
    print("pubkey: " + pubkey)
    print("bits: " + hex(bits))
    print("value: " + str(value))

    print("\r\n------output------")
    print("nonce: " + str(nonce))
    print("genesis hash: " + genesisHash.hex())
    print("merkle hash: " + hashMerkleRoot[::-1].hex())

def getHashMerkleRoot(pubkey, pszTimestamp, value):
    scriptLen = '41'
    OP_CHECKSIG = 'ac'
    outputScript = hexstr2Str(scriptLen + pubkey + OP_CHECKSIG)

    pszPrefix = ""
    if len(pszTimestamp) > 76:
        pszPrefix = '4c'
    scriptPrefix = '04ffff001d0104' + pszPrefix + str2Hexstr(chr(len(pszTimestamp)))
    inputScript = hexstr2Str(scriptPrefix + str2Hexstr(pszTimestamp))

    transaction = Struct("version" / Array(4, Byte),
                         "num_inputs" / Byte,
                         "prev_output" / Array(32, Byte),
                         "prev_out_idx" / Int,
                         "input_script_len" / Byte,
                         "input_script" / Array(len(inputScript), Byte),
                         "sequence" / Int,
                         "num_outputs" / Byte,
                         "out_value" / Array(8, Byte),
                         "output_script_len" / Byte,
                         "output_script" / Array(0x43, Byte),
                         "locktime" / Int)
    #  4 + 1 + 32 + 4 + 1 + 4 + 1 + 8 + 1 + 0x43 + 4 = 127
    tx = transaction.parse(b'\x00' * (127 + len(inputScript)))
    tx.version = struct.pack('<I', 1)
    tx.num_inputs = 1
    tx.prev_output = struct.pack('<qqqq', 0, 0, 0, 0)
    tx.prev_out_idx = 0xFFFFFFFF
    tx.input_script_len = len(inputScript)
    tx.input_script = inputScript.encode('iso-8859-1')
    tx.sequence = 0xFFFFFFFF
    tx.num_outputs = 1
    tx.out_value = struct.pack('<q', value)
    tx.output_script_len = 0x43
    tx.output_script = outputScript.encode('iso-8859-1')
    tx.locktime = 0
    return hashlib.sha256(hashlib.sha256(transaction.build(tx)).digest()).digest()

def createBlockHeader(hashMerkleRoot, time, bits, nonce):
    blockHeader = Struct("version" / Array(4, Byte),
                          "hash_prev_block" / Array(32, Byte),
                          "hash_merkle_root" / Array(32, Byte),
                          "time" / Array(4, Byte),
                          "bits" / Array(4, Byte),
                          "nonce" / Array(4, Byte))

    genesisblock = blockHeader.parse(b'\x00' * 80)
    genesisblock.version = struct.pack('<I', 1)
    genesisblock.hash_prev_block = struct.pack('<qqqq', 0, 0, 0, 0)
    genesisblock.hash_merkle_root = hashMerkleRoot
    genesisblock.time = struct.pack('<I', time)
    genesisblock.bits = struct.pack('<I', bits)
    genesisblock.nonce = struct.pack('<I', nonce)
    return blockHeader.build(genesisblock)

def tryToGetHash(blockData, bits, nonce):
    target = (bits & 0xffffff) * 2 ** (8 * ((bits >> 24) - 3))
    while True:
        sha256Hash = hashlib.sha256(hashlib.sha256(blockData).digest()).digest()[::-1]
        if int(sha256Hash.hex(), 16) < target:
            return (sha256Hash, nonce)
        else:
            nonce = nonce + 1
            blockData = blockData[0:len(blockData) - 4] + struct.pack('<I', nonce)

if __name__ == '__main__':
    getGenesisBlock(time=1610105038,
                    pszTimestamp='Neubitcoin was created on 2021-01-06.  --sunshuai',
                    pubkey='045c13d245cfbe91faee1abc8edaa874cf9404eba4d280afed882d57f09c5deefdc6b49047b6e0595e7858a00b5da95a9448ea9b9784dd876dfe898c1bdca048cd',
                    nonce=2,
                    bits=0x207fffff,
                    value=5000000000)
