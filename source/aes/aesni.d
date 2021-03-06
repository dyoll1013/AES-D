/**
 * Module containing support for AES-NI instructions. These instructions provide
 * hardware accelerated AES encryption and decryption on supported CPUs. This
 * module currently only works on 64-bit x86 machines. However, you should use the
 * `aesniIsSupported()` function to make sure that the instructions are supported
 * before using any of the other functions.
 */
module aes.aesni;

import aes.common;

/* For reasons beyond my comprehension, on OS X the linking convention is that
   C functions have an underscore prepended to their name. So the functions in
   the assembly file are defined with the underscore, so for compiling elsewhere
   we must create aliases to them. */
version (OSX)
{
    extern (C) bool aesniIsSupported() nothrow;

    extern (C) private {
        void aesniScheduleKeys128(uint* roundKeys) nothrow;
        void aesniScheduleKeys192(uint* roundKeys) nothrow;
        void aesniScheduleKeys256(uint* roundKeys) nothrow;
        
        void aesniPrepareDecryptionKeys(uint* roundKeys, ulong nr) nothrow;
        
        void aesniEncryptRound128(ubyte* block) nothrow;
        void aesniEncryptRound192(ubyte* block) nothrow;
        void aesniEncryptRound256(ubyte* block) nothrow;
        
        void aesniDecryptRound128(ubyte* block) nothrow;
        void aesniDecryptRound192(ubyte* block) nothrow;
        void aesniDecryptRound256(ubyte* block) nothrow;
        
        void aesniLoadRoundKeys128(uint* roundKeys) nothrow;
        void aesniLoadRoundKeys192(uint* roundKeys) nothrow;
        void aesniLoadRoundKeys256(uint* roundKeys) nothrow;
    }
} 
else
{
    extern (C) bool _aesniIsSupported() nothrow;
    alias aesniIsSupported = _aesniIsSupported;

    extern (C) private {
        void _aesniScheduleKeys128(uint* roundKeys) nothrow;
        alias aesniScheduleKeys128 = _aesniScheduleKeys128;
        void _aesniScheduleKeys192(uint* roundKeys) nothrow;
        alias aesniScheduleKeys192 = _aesniScheduleKeys192;
        void _aesniScheduleKeys256(uint* roundKeys) nothrow;
        alias aesniScheduleKeys256 = _aesniScheduleKeys256;
        
        void _aesniPrepareDecryptionKeys(uint* roundKeys, ulong nr) nothrow;
        alias aesniPrepareDecryptionKeys = _aesniPrepareDecryptionKeys;
        
        void _aesniEncryptRound128(ubyte* block) nothrow;
        alias aesniEncryptRound128 = _aesniEncryptRound128;
        void _aesniEncryptRound192(ubyte* block) nothrow;
        alias aesniEncryptRound192 = _aesniEncryptRound192;
        void _aesniEncryptRound256(ubyte* block) nothrow;
        alias aesniEncryptRound256 = _aesniEncryptRound256;
        
        void _aesniDecryptRound128(ubyte* block) nothrow;
        alias aesniDecryptRound128 = _aesniDecryptRound128;
        void _aesniDecryptRound192(ubyte* block) nothrow;
        alias aesniDecryptRound192 = _aesniDecryptRound192;
        void _aesniDecryptRound256(ubyte* block) nothrow;
        alias aesniDecryptRound256 = _aesniDecryptRound256;
        
        void _aesniLoadRoundKeys128(uint* roundKeys) nothrow;
        alias aesniLoadRoundKeys128 = _aesniLoadRoundKeys128;
        void _aesniLoadRoundKeys192(uint* roundKeys) nothrow;
        alias aesniLoadRoundKeys192 = _aesniLoadRoundKeys192;
        void _aesniLoadRoundKeys256(uint* roundKeys) nothrow;
        alias aesniLoadRoundKeys256 = _aesniLoadRoundKeys256;
    }
}

class AesniEncryptor128 : AesEncryptor {
    
    private uint[] expandedKey;
    
    this(const ubyte[] key) nothrow
    in {
        assert(key.length == 16);
    }
    body {
        expandedKey = new uint[11*4];
        expandedKey[0 .. 4] = cast(uint[]) key;
        aesniScheduleKeys128(expandedKey.ptr);
    }
    
    override void processBlock(ubyte[] block) nothrow
    {
        aesniLoadRoundKeys128(expandedKey.ptr);
        aesniEncryptRound128(block.ptr);
    }
    
    override void processChunk(ubyte[] chunk) nothrow
    {
        aesniLoadRoundKeys128(expandedKey.ptr);
        
        auto nBlocks = chunk.length / 16;
        auto blockPtr = chunk.ptr;
        
        while (nBlocks > 0) {
            aesniEncryptRound128(blockPtr);
            blockPtr += 16;
            nBlocks -= 1;
        }
    }
}

class AesniEncryptor192 : AesEncryptor {
    
    private uint[] expandedKey;
    
    this(const ubyte[] key) nothrow
    in {
        assert(key.length == 24);
    }
    body {
        expandedKey = new uint[13*4];
        expandedKey[0 .. 6] = cast(uint[]) key;
        aesniScheduleKeys192(expandedKey.ptr);
    }
    
    override void processBlock(ubyte[] block) nothrow
    {
        aesniLoadRoundKeys192(expandedKey.ptr);
        aesniEncryptRound192(block.ptr);
    }
    
    override void processChunk(ubyte[] chunk) nothrow
    {
        aesniLoadRoundKeys192(expandedKey.ptr);
        
        auto nBlocks = chunk.length / 16;
        auto blockPtr = chunk.ptr;
        
        while (nBlocks > 0) {
            aesniEncryptRound192(blockPtr);
            blockPtr += 16;
            nBlocks -= 1;
        }
    }
}

class AesniEncryptor256 : AesEncryptor {
    
    private uint[] expandedKey;
    
    this(const ubyte[] key) nothrow
    in {
        assert(key.length == 32);
    }
    body {
        expandedKey = new uint[15*4];
        expandedKey[0 .. 8] = cast(uint[]) key;
        aesniScheduleKeys256(expandedKey.ptr);
    }
    
    override void processBlock(ubyte[] block) nothrow
    {
        aesniLoadRoundKeys256(expandedKey.ptr);
        aesniEncryptRound256(block.ptr);
    }
    
    override void processChunk(ubyte[] chunk) nothrow
    {
        aesniLoadRoundKeys256(expandedKey.ptr);
        
        auto nBlocks = chunk.length / 16;
        auto blockPtr = chunk.ptr;
        
        while (nBlocks > 0) {
            aesniEncryptRound256(blockPtr);
            blockPtr += 16;
            nBlocks -= 1;
        }
    }
}

class AesniDecryptor128 : AesDecryptor {
    
    private uint[] expandedKey;
    
    this(const ubyte[] key) nothrow
    in {
        assert(key.length == 16);
    }
    body {
        expandedKey = new uint[11*4];
        expandedKey[0 .. 4] = cast(uint[]) key;
        aesniScheduleKeys128(expandedKey.ptr);
        aesniPrepareDecryptionKeys(expandedKey.ptr, 10);
    }
    
    override void processBlock(ubyte[] block) nothrow
    {
        aesniLoadRoundKeys128(expandedKey.ptr);
        aesniDecryptRound128(block.ptr);
    }
    
    override void processChunk(ubyte[] chunk) nothrow
    {
        aesniLoadRoundKeys128(expandedKey.ptr);
        
        auto nBlocks = chunk.length / 16;
        auto blockPtr = chunk.ptr;
        
        while (nBlocks > 0) {
            aesniDecryptRound128(blockPtr);
            blockPtr += 16;
            nBlocks -= 1;
        }
    }
}

class AesniDecryptor192 : AesDecryptor {
    
    private uint[] expandedKey;
    
    this(const ubyte[] key) nothrow
    in {
        assert(key.length == 24);
    }
    body {
        expandedKey = new uint[13*4];
        expandedKey[0 .. 6] = cast(uint[]) key;
        aesniScheduleKeys192(expandedKey.ptr);
        aesniPrepareDecryptionKeys(expandedKey.ptr, 12);
    }
    
    override void processBlock(ubyte[] block) nothrow
    {
        aesniLoadRoundKeys192(expandedKey.ptr);
        aesniDecryptRound192(block.ptr);
    }
    
    override void processChunk(ubyte[] chunk) nothrow
    {
        aesniLoadRoundKeys192(expandedKey.ptr);
        
        auto nBlocks = chunk.length / 16;
        auto blockPtr = chunk.ptr;
        
        while (nBlocks > 0) {
            aesniDecryptRound192(blockPtr);
            blockPtr += 16;
            nBlocks -= 1;
        }
    }
}

class AesniDecryptor256 : AesDecryptor {
    
    private uint[] expandedKey;
    
    this(const ubyte[] key) nothrow
    in {
        assert(key.length == 32);
    }
    body {
        expandedKey = new uint[15*4];
        expandedKey[0 .. 8] = cast(uint[]) key;
        aesniScheduleKeys256(expandedKey.ptr);
        aesniPrepareDecryptionKeys(expandedKey.ptr, 14);
    }
    
    override void processBlock(ubyte[] block) nothrow
    {
        aesniLoadRoundKeys256(expandedKey.ptr);
        aesniDecryptRound256(block.ptr);
    }
    
    override void processChunk(ubyte[] chunk) nothrow
    {
        aesniLoadRoundKeys256(expandedKey.ptr);
        
        auto nBlocks = chunk.length / 16;
        auto blockPtr = chunk.ptr;
        
        while (nBlocks > 0) {
            aesniDecryptRound256(blockPtr);
            blockPtr += 16;
            nBlocks -= 1;
        }
    }
}

// basically just runs the same tests as in aes.encryptor, aes.decryptor, 
// and aes.scheduler but with the AES-NI versions of the functions
unittest {
    import aes.common : State;
    
    assert(aesniIsSupported());
    
    ubyte[] testKey128 = [
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c,
    ];
    
    State[] roundKeys128 = [
        [
            [0x2b,0x7e,0x15,0x16],
            [0x28,0xae,0xd2,0xa6],
            [0xab,0xf7,0x15,0x88],
            [0x09,0xcf,0x4f,0x3c]
        ],
        [
            [0xa0,0xfa,0xfe,0x17],
            [0x88,0x54,0x2c,0xb1],
            [0x23,0xa3,0x39,0x39],
            [0x2a,0x6c,0x76,0x05]
        ],
        [
            [0xf2,0xc2,0x95,0xf2],
            [0x7a,0x96,0xb9,0x43],
            [0x59,0x35,0x80,0x7a],
            [0x73,0x59,0xf6,0x7f]
        ],
        [
            [0x3d,0x80,0x47,0x7d],
            [0x47,0x16,0xfe,0x3e],
            [0x1e,0x23,0x7e,0x44],
            [0x6d,0x7a,0x88,0x3b]
        ],
        [
            [0xef,0x44,0xa5,0x41],
            [0xa8,0x52,0x5b,0x7f],
            [0xb6,0x71,0x25,0x3b],
            [0xdb,0x0b,0xad,0x00]
        ],
        [
            [0xd4,0xd1,0xc6,0xf8],
            [0x7c,0x83,0x9d,0x87],
            [0xca,0xf2,0xb8,0xbc],
            [0x11,0xf9,0x15,0xbc]
        ],
        [
            [0x6d,0x88,0xa3,0x7a],
            [0x11,0x0b,0x3e,0xfd],
            [0xdb,0xf9,0x86,0x41],
            [0xca,0x00,0x93,0xfd]
        ],
        [
            [0x4e,0x54,0xf7,0x0e],
            [0x5f,0x5f,0xc9,0xf3],
            [0x84,0xa6,0x4f,0xb2],
            [0x4e,0xa6,0xdc,0x4f]
        ],
        [
            [0xea,0xd2,0x73,0x21],
            [0xb5,0x8d,0xba,0xd2],
            [0x31,0x2b,0xf5,0x60],
            [0x7f,0x8d,0x29,0x2f]
        ],
        [
            [0xac,0x77,0x66,0xf3],
            [0x19,0xfa,0xdc,0x21],
            [0x28,0xd1,0x29,0x41],
            [0x57,0x5c,0x00,0x6e]
        ],
        [
            [0xd0,0x14,0xf9,0xa8],
            [0xc9,0xee,0x25,0x89],
            [0xe1,0x3f,0x0c,0xc8],
            [0xb6,0x63,0x0c,0xa6]
        ]
    ];
    
    auto e1 = new AesniEncryptor128(testKey128);
    assert(cast(State[]) e1.expandedKey == roundKeys128);
    
    ubyte[] testKey192 = [
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,
        0x64,0x52,0xc8,0x10,0xf3,0x2b,
        0x80,0x90,0x79,0xe5,0x62,0xf8,
        0xea,0xd2,0x52,0x2c,0x6b,0x7b,
    ];
    
    State[] roundKeys192 = [
        [
            [0x8e,0x73,0xb0,0xf7],
            [0xda,0x0e,0x64,0x52],
            [0xc8,0x10,0xf3,0x2b],
            [0x80,0x90,0x79,0xe5]
        ],
        [
            [0x62,0xf8,0xea,0xd2],
            [0x52,0x2c,0x6b,0x7b],
            [0xfe,0x0c,0x91,0xf7],
            [0x24,0x02,0xf5,0xa5]
        ],
        [
            [0xec,0x12,0x06,0x8e],
            [0x6c,0x82,0x7f,0x6b],
            [0x0e,0x7a,0x95,0xb9],
            [0x5c,0x56,0xfe,0xc2]
        ],
        [
            [0x4d,0xb7,0xb4,0xbd],
            [0x69,0xb5,0x41,0x18],
            [0x85,0xa7,0x47,0x96],
            [0xe9,0x25,0x38,0xfd]
        ],
        [
            [0xe7,0x5f,0xad,0x44],
            [0xbb,0x09,0x53,0x86],
            [0x48,0x5a,0xf0,0x57],
            [0x21,0xef,0xb1,0x4f]
        ],
        [
            [0xa4,0x48,0xf6,0xd9],
            [0x4d,0x6d,0xce,0x24],
            [0xaa,0x32,0x63,0x60],
            [0x11,0x3b,0x30,0xe6]
        ],
        [
            [0xa2,0x5e,0x7e,0xd5],
            [0x83,0xb1,0xcf,0x9a],
            [0x27,0xf9,0x39,0x43],
            [0x6a,0x94,0xf7,0x67]
        ],
        [
            [0xc0,0xa6,0x94,0x07],
            [0xd1,0x9d,0xa4,0xe1],
            [0xec,0x17,0x86,0xeb],
            [0x6f,0xa6,0x49,0x71]
        ],
        [
            [0x48,0x5f,0x70,0x32],
            [0x22,0xcb,0x87,0x55],
            [0xe2,0x6d,0x13,0x52],
            [0x33,0xf0,0xb7,0xb3]
        ],
        [
            [0x40,0xbe,0xeb,0x28],
            [0x2f,0x18,0xa2,0x59],
            [0x67,0x47,0xd2,0x6b],
            [0x45,0x8c,0x55,0x3e]
        ],
        [
            [0xa7,0xe1,0x46,0x6c],
            [0x94,0x11,0xf1,0xdf],
            [0x82,0x1f,0x75,0x0a],
            [0xad,0x07,0xd7,0x53]
        ],
        [
            [0xca,0x40,0x05,0x38],
            [0x8f,0xcc,0x50,0x06],
            [0x28,0x2d,0x16,0x6a],
            [0xbc,0x3c,0xe7,0xb5]
        ],
        [
            [0xe9,0x8b,0xa0,0x6f],
            [0x44,0x8c,0x77,0x3c],
            [0x8e,0xcc,0x72,0x04],
            [0x01,0x00,0x22,0x02]
        ],
    ];
    
    auto e2 = new AesniEncryptor192(testKey192);
    assert(cast(State[]) e2.expandedKey == roundKeys192);
    
    ubyte[] testKey256 = [
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4,
    ];
    
    State[] roundKeys256 = [
        [
            [0x60,0x3d,0xeb,0x10],
            [0x15,0xca,0x71,0xbe],
            [0x2b,0x73,0xae,0xf0],
            [0x85,0x7d,0x77,0x81],
        ],
        [
            [0x1f,0x35,0x2c,0x07],
            [0x3b,0x61,0x08,0xd7],
            [0x2d,0x98,0x10,0xa3],
            [0x09,0x14,0xdf,0xf4],
        ],
        [
            [0x9b,0xa3,0x54,0x11],
            [0x8e,0x69,0x25,0xaf],
            [0xa5,0x1a,0x8b,0x5f],
            [0x20,0x67,0xfc,0xde],
        ],
        [
            [0xa8,0xb0,0x9c,0x1a],
            [0x93,0xd1,0x94,0xcd],
            [0xbe,0x49,0x84,0x6e],
            [0xb7,0x5d,0x5b,0x9a],
        ],
        [
            [0xd5,0x9a,0xec,0xb8],
            [0x5b,0xf3,0xc9,0x17],
            [0xfe,0xe9,0x42,0x48],
            [0xde,0x8e,0xbe,0x96],
        ],
        [
            [0xb5,0xa9,0x32,0x8a],
            [0x26,0x78,0xa6,0x47],
            [0x98,0x31,0x22,0x29],
            [0x2f,0x6c,0x79,0xb3],
        ],
        [
            [0x81,0x2c,0x81,0xad],
            [0xda,0xdf,0x48,0xba],
            [0x24,0x36,0x0a,0xf2],
            [0xfa,0xb8,0xb4,0x64],
        ],
        [
            [0x98,0xc5,0xbf,0xc9],
            [0xbe,0xbd,0x19,0x8e],
            [0x26,0x8c,0x3b,0xa7],
            [0x09,0xe0,0x42,0x14],
        ],
        [
            [0x68,0x00,0x7b,0xac],
            [0xb2,0xdf,0x33,0x16],
            [0x96,0xe9,0x39,0xe4],
            [0x6c,0x51,0x8d,0x80],
        ],
        [
            [0xc8,0x14,0xe2,0x04],
            [0x76,0xa9,0xfb,0x8a],
            [0x50,0x25,0xc0,0x2d],
            [0x59,0xc5,0x82,0x39],
        ],
        [
            [0xde,0x13,0x69,0x67],
            [0x6c,0xcc,0x5a,0x71],
            [0xfa,0x25,0x63,0x95],
            [0x96,0x74,0xee,0x15],
        ],
        [
            [0x58,0x86,0xca,0x5d],
            [0x2e,0x2f,0x31,0xd7],
            [0x7e,0x0a,0xf1,0xfa],
            [0x27,0xcf,0x73,0xc3],
        ],
        [
            [0x74,0x9c,0x47,0xab],
            [0x18,0x50,0x1d,0xda],
            [0xe2,0x75,0x7e,0x4f],
            [0x74,0x01,0x90,0x5a],
        ],
        [
            [0xca,0xfa,0xaa,0xe3],
            [0xe4,0xd5,0x9b,0x34],
            [0x9a,0xdf,0x6a,0xce],
            [0xbd,0x10,0x19,0x0d],
        ],
        [
            [0xfe,0x48,0x90,0xd1],
            [0xe6,0x18,0x8d,0x0b],
            [0x04,0x6d,0xf3,0x44],
            [0x70,0x6c,0x63,0x1e],
        ],
    ];
    
    auto e3 = new AesniEncryptor256(testKey256);
    assert(cast(State[]) e3.expandedKey == roundKeys256);
    
    immutable ubyte[] plaintext = [
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff
    ];
    
    AesAlgorithm e;
    AesAlgorithm d;
    ubyte[] buf = plaintext.dup;
    
    ubyte[] key128 = [
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    ];
    
    ubyte[] ciphertext128 = [
        0x69,0xc4,0xe0,0xd8,
        0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,
        0x70,0xb4,0xc5,0x5a
    ];
    
    e = new AesniEncryptor128(key128);
    d = new AesniDecryptor128(key128);
    
    e.processBlock(buf);
    assert(buf == ciphertext128);
    
    d.processBlock(buf);
    assert(buf == plaintext);
    
    e.processChunk(buf);
    assert(buf == ciphertext128);
    
    d.processChunk(buf);
    assert(buf == plaintext);
    
    ubyte[] key192 = [
        0x00,0x01,0x02,0x03,0x04,0x05,
        0x06,0x07,0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f,0x10,0x11,
        0x12,0x13,0x14,0x15,0x16,0x17
    ];
    
    ubyte[] ciphertext192 = [
        0xdd,0xa9,0x7c,0xa4,
        0x86,0x4c,0xdf,0xe0,
        0x6e,0xaf,0x70,0xa0,
        0xec,0x0d,0x71,0x91
    ];
    
    e = new AesniEncryptor192(key192);
    d = new AesniDecryptor192(key192);
    
    e.processBlock(buf);
    assert(buf == ciphertext192);
    
    d.processBlock(buf);
    assert(buf == plaintext);
    
    e.processChunk(buf);
    assert(buf == ciphertext192);
    
    d.processChunk(buf);
    assert(buf == plaintext);
    
    ubyte[] key256 = [
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    ];
    
    ubyte[] ciphertext256 = [
        0x8e,0xa2,0xb7,0xca,
        0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,
        0x4b,0x49,0x60,0x89
    ];
    
    e = new AesniEncryptor256(key256);
    d = new AesniDecryptor256(key256);
    
    e.processBlock(buf);
    assert(buf == ciphertext256);
    
    d.processBlock(buf);
    assert(buf == plaintext);
    
    e.processChunk(buf);
    assert(buf == ciphertext256);
    
    d.processChunk(buf);
    assert(buf == plaintext);
}