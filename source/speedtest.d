import std.stdio, std.conv, std.random, std.datetime, std.getopt;
import aes, aes.encryptor, aes.decryptor, aes.aesni;

immutable ubyte[] key128 = [
    0x00,0x01,0x02,0x03,
    0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,
    0x0c,0x0d,0x0e,0x0f
];

immutable ubyte[] key192 = [
    0x00,0x01,0x02,0x03,0x04,0x05,
    0x06,0x07,0x08,0x09,0x0a,0x0b,
    0x0c,0x0d,0x0e,0x0f,0x10,0x11,
    0x12,0x13,0x14,0x15,0x16,0x17
];

immutable ubyte[] key256 = [
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
];

ubyte[] data;

int main(string[] args) {
    
    size_t dataSize = 1_000_000; // default to 1 MB
    bool testNaive = true;
    bool testAesni = true;
    bool checkResult = false;
    
    void parseSizeArg(string option, string value) {
        dataSize = parse!size_t(value);
        
        if (value.length == 0)
            return;
        
        if (value.length == 1) {
            
            char suffix = value[0];
            size_t sizeMult;
            
            switch (suffix) {
                case 'B', 'b':
                    sizeMult = 1;
                    break;
                    
                case 'K', 'k':
                    sizeMult = 1000;
                    break;
                    
                case 'M', 'm':
                    sizeMult = 1000 ^^ 2;
                    break;
                    
                case 'G', 'g':
                    sizeMult = 1000 ^^ 3;
                    break;
                    
                default:
                    throw new ConvException("invalid size suffix");
            }
            
            dataSize *= sizeMult;
            
        } else
            throw new ConvException("invalid size");
    }
    
    try {
        
        getopt(args,
            "test-naive", &testNaive,
            "test-aes-ni", &testAesni,
            "check-result", &checkResult,
            "size", &parseSizeArg);
        
    } catch (Exception e) {
        writeUsage(args[0]);
        return -1;
    }
    
    if (dataSize % 16 != 0)
        dataSize = (dataSize / 16 + 1) * 16;
    
    writeln("Randomly generating ", dataSize, " bytes...");
    
    data = new ubyte[dataSize];
    Random rng;
    rng.seed(cast(int) Clock.currStdTime());
    
    auto intData = cast(uint[]) data;
    for (size_t i = 0; i < intData.length; i++) {
        intData[i] = rng.front;
        rng.popFront();
    }
    
    ubyte[] dataCopy;
    if (checkResult)
        dataCopy = data.dup;
    
    if (testNaive) {
        
        writeln("Testing naive algorithms:");
        
        write("    128-bit key encryption... ");
        stdout.flush();
        runTest(new DefaultEncryptor(key128));
        
        write("    128-bit key decryption... ");
        stdout.flush();
        runTest(new DefaultDecryptor(key128));
        
        write("    192-bit key encryption... ");
        stdout.flush();
        runTest(new DefaultEncryptor(key192));
        
        write("    192-bit key decryption... ");
        stdout.flush();
        runTest(new DefaultDecryptor(key192));
        
        write("    256-bit key encryption... ");
        stdout.flush();
        runTest(new DefaultEncryptor(key256));
        
        write("    256-bit key decryption... ");
        stdout.flush();
        runTest(new DefaultDecryptor(key256));
    }
    
    if (testAesni) {
        
        if (!aesniIsSupported()) {
            writeln("AES-NI is not supported on your system.");
            return 0;
        }
        
        writeln("Testing AES-NI based algorithms:");
        
        write("    128-bit key encryption... ");
        stdout.flush();
        runTest(new AesniEncryptor128(key128));
        
        write("    128-bit key decryption... ");
        stdout.flush();
        runTest(new AesniDecryptor128(key128));
        
        write("    192-bit key encryption... ");
        stdout.flush();
        runTest(new AesniEncryptor192(key192));
        
        write("    192-bit key decryption... ");
        stdout.flush();
        runTest(new AesniDecryptor192(key192));
        
        write("    256-bit key encryption... ");
        stdout.flush();
        runTest(new AesniEncryptor256(key256));
        
        write("    256-bit key decryption... ");
        stdout.flush();
        runTest(new AesniDecryptor256(key256));
    }
    
    if (checkResult) {
        write("Checking result against original... ");
        if (data == dataCopy)
            writeln("Success!");
        else
            writeln("Failure. Algorithm is flawed.");
    }
    
    return 0;
}

void writeUsage(string name)
{
    writeln("usage: ", name, " [--size <size>] [--test-naive <true|false>] [--test-aesni <true|false>]");
}

void runTest(AesAlgorithm aes)
{
    StopWatch timer;
    timer.start();
    aes.processChunk(data);
    timer.stop();
    
    auto t = timer.peek();
    auto secs = t.seconds;
    auto millis = t.msecs;
    auto bpns = cast(double) data.length / t.nsecs;
    writefln("%d.%03d s, %.2f MB/s", secs, millis - secs*1000, bpns * 1000);
}