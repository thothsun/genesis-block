# -*- coding:utf-8 –*-
import hashlib
import struct
import time

from construct import *


def getGenesisBlock(time=int(time.time()),
                    pszTimestamp='The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
                    pubkey='045c13d245cfbe91faee1abc8edaa874cf9404eba4d280afed882d57f09c5deefdc6b49047b6e0595e7858a00b5da95a9448ea9b9784dd876dfe898c1bdca048cd',
                    bits=0x1d00ffff,
                    value=5000000000):
    print "start mining..."
    hashMerkleRoot = getHashMerkleRoot(pubkey, pszTimestamp, value)
    blockHeader = createBlockHeader(hashMerkleRoot, time, bits)
    genesisHash, nonce = tryToGetHash(blockHeader, bits)

    print "\r\n------input------"
    print "time: " + str(time)
    print "pszTimestamp: " + pszTimestamp
    print "pubkey: " + pubkey
    print "bits: " + hex(bits)
    print "value: " + str(value)

    print "\r\n------output------"
    print "nonce: " + str(nonce)
    print "genesis hash: " + genesisHash.encode('hex')
    print "merkle hash: " + hashMerkleRoot[::-1].encode('hex')

def getHashMerkleRoot(pubkey,pszTimestamp,value):
    scriptLen = '41'
    OP_CHECKSIG = 'ac'
    outputScript = (scriptLen + pubkey + OP_CHECKSIG).decode('hex')

    pszPrefix = ""
    if len(pszTimestamp) > 76:
        pszPrefix = '4c'
    scriptPrefix = '04ffff001d0104' + pszPrefix + chr(len(pszTimestamp)).encode('hex')
    inputScript = (scriptPrefix + pszTimestamp.encode('hex')).decode('hex')

    transaction = Struct("transaction",
                         Bytes("version", 4),
                         Byte("num_inputs"),
                         StaticField("prev_output", 32),
                         UBInt32('prev_out_idx'),
                         Byte('input_script_len'),
                         Bytes('input_script', len(inputScript)),
                         UBInt32('sequence'),
                         Byte('num_outputs'),
                         Bytes('out_value', 8),
                         Byte('output_script_len'),
                         Bytes('output_script', 0x43),
                         UBInt32('locktime'))

    tx = transaction.parse('\x00' * (127 + len(inputScript)))
    tx.version = struct.pack('<I', 1)
    tx.num_inputs = 1
    tx.prev_output = struct.pack('<qqqq', 0, 0, 0, 0)
    tx.prev_out_idx = 0xFFFFFFFF
    tx.input_script_len = len(inputScript)
    tx.input_script = inputScript
    tx.sequence = 0xFFFFFFFF
    tx.num_outputs = 1
    tx.out_value = struct.pack('<q', value)
    tx.output_script_len = 0x43
    tx.output_script = outputScript
    tx.locktime = 0
    return hashlib.sha256(hashlib.sha256(transaction.build(tx)).digest()).digest()

def createBlockHeader(hashMerkleRoot, time, bits):
    blockHeader = Struct("block_header",
                         Bytes("version", 4),
                         Bytes("hash_prev_block", 32),
                         Bytes("hash_merkle_root", 32),
                         Bytes("time", 4),
                         Bytes("bits", 4),
                         Bytes("nonce", 4))

    genesisblock = blockHeader.parse('\x00' * 80)
    genesisblock.version = struct.pack('<I', 1)
    genesisblock.hash_prev_block = struct.pack('<qqqq', 0, 0, 0, 0)
    genesisblock.hash_merkle_root = hashMerkleRoot
    genesisblock.time = struct.pack('<I', time)
    genesisblock.bits = struct.pack('<I', bits)
    genesisblock.nonce = struct.pack('<I', 0)
    return blockHeader.build(genesisblock)

def tryToGetHash(blockData, bits):
    nonce = 0
    target = (bits & 0xffffff) * 2 ** (8 * ((bits >> 24) - 3))

    while True:
        sha256Hash = hashlib.sha256(hashlib.sha256(blockData).digest()).digest()[::-1]
        if int(sha256Hash.encode('hex'), 16) < target:
            return (sha256Hash, nonce)
        else:
            nonce = nonce + 1
            blockData = blockData[0:len(blockData) - 4] + struct.pack('<I', nonce)

if __name__ == '__main__':
    getGenesisBlock(time=1610105038,
                    pszTimestamp='Neubitcoin was created on 2021-01-06.  --sunshuai',
                    pubkey='045c13d245cfbe91faee1abc8edaa874cf9404eba4d280afed882d57f09c5deefdc6b49047b6e0595e7858a00b5da95a9448ea9b9784dd876dfe898c1bdca048cd',
                    bits=0x207fffff,
                    value=5000000000)
