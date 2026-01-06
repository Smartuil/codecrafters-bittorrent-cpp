/**
 * @file main.cpp
 * @brief BitTorrent 客户端 - Bencode 解码器实现
 * 
 * 本文件实现了 BitTorrent 协议中使用的 Bencode 编码格式的解码功能。
 * Bencode 是 BitTorrent 协议用于编码 .torrent 文件和 tracker 通信的数据格式。
 * 
 * ============================================================================
 * Bencode 编码格式详解
 * ============================================================================
 * 
 * Bencode 支持四种数据类型：
 * 
 * 1. 字符串 (Strings)
 *    格式: <长度>:<内容>
 *    - 长度是十进制数字，表示字符串的字节数
 *    - 冒号 ':' 作为分隔符
 *    - 内容是实际的字符串数据
 *    
 *    示例:
 *    | 原始字符串 | Bencode 编码 | 解释                    |
 *    |-----------|-------------|------------------------|
 *    | "hi"      | 2:hi        | 长度=2, 内容="hi"       |
 *    | "hello"   | 5:hello     | 长度=5, 内容="hello"    |
 *    | "foo"     | 3:foo       | 长度=3, 内容="foo"      |
 *    | ""        | 0:          | 长度=0, 空字符串         |
 * 
 * 2. 整数 (Integers)
 *    格式: i<数字>e
 *    - 'i' 是起始标记
 *    - 数字可以是正数、负数或零
 *    - 'e' 是结束标记
 *    
 *    示例:
 *    | 原始数字 | Bencode 编码 |
 *    |---------|-------------|
 *    | 52      | i52e        |
 *    | -52     | i-52e       |
 *    | 0       | i0e         |
 * 
 * 3. 列表 (Lists)
 *    格式: l<元素1><元素2>...e
 *    - 'l' 是起始标记
 *    - 元素之间没有分隔符，直接连接
 *    - 'e' 是结束标记
 *    - 元素可以是任意 Bencode 类型（包括嵌套列表）
 *    
 *    示例:
 *    | 原始数据           | Bencode 编码      |
 *    |-------------------|------------------|
 *    | ["hello", 52]     | l5:helloi52ee    |
 *    | []                | le               |
 *    | [["hello"]]       | ll5:helloee      |
 * 
 * 4. 字典 (Dictionaries)
 *    格式: d<key1><value1><key2><value2>...e
 *    - 'd' 是起始标记
 *    - 键必须是字符串，且按字典序（lexicographical order）排列
 *    - 值可以是任意 Bencode 类型
 *    - 'e' 是结束标记
 *    
 *    示例: "d3:foo3:bar5:helloi52ee" 解析过程:
 *    
 *    d    3:foo    3:bar    5:hello    i52e    e
 *    │      │        │         │        │      │
 *    │      │        │         │        │      └── 字典结束标记
 *    │      │        │         │        └── 值2: 整数 52
 *    │      │        │         └── 键2: 字符串 "hello" (长度5)
 *    │      │        └── 值1: 字符串 "bar" (长度3)
 *    │      └── 键1: 字符串 "foo" (长度3)
 *    └── 字典起始标记
 *    
 *    结果: {"foo":"bar", "hello":52}
 * 
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>    // 文件读取
#include <sstream>    // 字符串流
#include <iomanip>    // 十六进制格式化输出
#include <cstdint>    // 固定宽度整数类型
#include <cstring>    // memcpy
#include <random>     // 随机数生成
#include <stdexcept>  // std::runtime_error
#include <algorithm>  // std::min
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>



// 网络相关头文件（Linux/POSIX）

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close


#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

// ============================================================================
// SHA-1 哈希算法实现
// ============================================================================
// SHA-1 (Secure Hash Algorithm 1) 产生 160 位 (20 字节) 的哈希值
// 用于计算 torrent 文件的 Info Hash

/**
 * @brief SHA-1 哈希计算类
 * 
 * 实现 SHA-1 算法，用于计算 info 字典的哈希值
 */
class SHA1 
{
public:
    SHA1() { reset(); }
    
    /**
     * @brief 更新哈希计算，添加更多数据
     * @param data 要添加的数据
     * @param len 数据长度
     */
    void update(const uint8_t* data, size_t len)
    {
        size_t i = 0;
        size_t index = (count[0] >> 3) & 0x3F;
        
        count[0] += static_cast<uint32_t>(len << 3);
        if (count[0] < (len << 3)) count[1]++;
        count[1] += static_cast<uint32_t>(len >> 29);
        
        size_t partLen = 64 - index;
        
        if (len >= partLen) 
        {
            std::memcpy(&buffer[index], data, partLen);
            transform(buffer);
            
            for (i = partLen; i + 63 < len; i += 64)
                transform(&data[i]);
            
            index = 0;
        }
        
        std::memcpy(&buffer[index], &data[i], len - i);
    }
    
    void update(const std::string& s)
    {
        update(reinterpret_cast<const uint8_t*>(s.c_str()), s.size());
    }
    
    /**
     * @brief 完成哈希计算并返回结果
     * @return 20 字节的 SHA-1 哈希值
     */
    std::string final()
    {
        uint8_t finalcount[8];
        for (uint32_t i = 0; i < 8; i++)
            finalcount[i] = static_cast<uint8_t>((count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
        
        uint8_t c = 0x80;
        update(&c, 1);
        
        while ((count[0] & 504) != 448)
        {
            c = 0x00;
            update(&c, 1);
        }
        
        update(finalcount, 8);
        
        std::string hash(20, '\0');
        for (uint32_t i = 0; i < 20; i++)
            hash[i] = static_cast<char>((state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
        
        reset();
        return hash;
    }
    
    /**
     * @brief 便捷函数：计算字符串的 SHA-1 哈希
     * @param s 输入字符串
     * @return 20 字节的 SHA-1 哈希值
     */
    static std::string hash(const std::string& s)
    {
        SHA1 sha1;
        sha1.update(s);
        return sha1.final();
    }

private:
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
    
    void reset()
    {
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
        count[0] = count[1] = 0;
    }
    
    static uint32_t rol(uint32_t value, uint32_t bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }
    
    static uint32_t blk(const uint32_t* block, uint32_t i)
    {
        return rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i], 1);
    }
    
    static void R0(const uint32_t* block, uint32_t v, uint32_t& w, uint32_t x, uint32_t y, uint32_t& z, uint32_t i)
    {
        z += ((w & (x ^ y)) ^ y) + block[i] + 0x5A827999 + rol(v, 5);
        w = rol(w, 30);
    }
    
    static void R1(uint32_t* block, uint32_t v, uint32_t& w, uint32_t x, uint32_t y, uint32_t& z, uint32_t i)
    {
        block[i] = blk(block, i);
        z += ((w & (x ^ y)) ^ y) + block[i] + 0x5A827999 + rol(v, 5);
        w = rol(w, 30);
    }
    
    static void R2(uint32_t* block, uint32_t v, uint32_t& w, uint32_t x, uint32_t y, uint32_t& z, uint32_t i)
    {
        block[i] = blk(block, i);
        z += (w ^ x ^ y) + block[i] + 0x6ED9EBA1 + rol(v, 5);
        w = rol(w, 30);
    }
    
    static void R3(uint32_t* block, uint32_t v, uint32_t& w, uint32_t x, uint32_t y, uint32_t& z, uint32_t i)
    {
        block[i] = blk(block, i);
        z += (((w | x) & y) | (w & x)) + block[i] + 0x8F1BBCDC + rol(v, 5);
        w = rol(w, 30);
    }
    
    static void R4(uint32_t* block, uint32_t v, uint32_t& w, uint32_t x, uint32_t y, uint32_t& z, uint32_t i)
    {
        block[i] = blk(block, i);
        z += (w ^ x ^ y) + block[i] + 0xCA62C1D6 + rol(v, 5);
        w = rol(w, 30);
    }
    
    void transform(const uint8_t* data)
    {
        uint32_t block[16];
        for (uint32_t i = 0; i < 16; i++)
            block[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
        
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
        
        R0(block, a, b, c, d, e, 0);  R0(block, e, a, b, c, d, 1);  R0(block, d, e, a, b, c, 2);  R0(block, c, d, e, a, b, 3);
        R0(block, b, c, d, e, a, 4);  R0(block, a, b, c, d, e, 5);  R0(block, e, a, b, c, d, 6);  R0(block, d, e, a, b, c, 7);
        R0(block, c, d, e, a, b, 8);  R0(block, b, c, d, e, a, 9);  R0(block, a, b, c, d, e, 10); R0(block, e, a, b, c, d, 11);
        R0(block, d, e, a, b, c, 12); R0(block, c, d, e, a, b, 13); R0(block, b, c, d, e, a, 14); R0(block, a, b, c, d, e, 15);
        R1(block, e, a, b, c, d, 0);  R1(block, d, e, a, b, c, 1);  R1(block, c, d, e, a, b, 2);  R1(block, b, c, d, e, a, 3);
        R2(block, a, b, c, d, e, 4);  R2(block, e, a, b, c, d, 5);  R2(block, d, e, a, b, c, 6);  R2(block, c, d, e, a, b, 7);
        R2(block, b, c, d, e, a, 8);  R2(block, a, b, c, d, e, 9);  R2(block, e, a, b, c, d, 10); R2(block, d, e, a, b, c, 11);
        R2(block, c, d, e, a, b, 12); R2(block, b, c, d, e, a, 13); R2(block, a, b, c, d, e, 14); R2(block, e, a, b, c, d, 15);
        R2(block, d, e, a, b, c, 0);  R2(block, c, d, e, a, b, 1);  R2(block, b, c, d, e, a, 2);  R2(block, a, b, c, d, e, 3);
        R2(block, e, a, b, c, d, 4);  R2(block, d, e, a, b, c, 5);  R2(block, c, d, e, a, b, 6);  R2(block, b, c, d, e, a, 7);
        R3(block, a, b, c, d, e, 8);  R3(block, e, a, b, c, d, 9);  R3(block, d, e, a, b, c, 10); R3(block, c, d, e, a, b, 11);
        R3(block, b, c, d, e, a, 12); R3(block, a, b, c, d, e, 13); R3(block, e, a, b, c, d, 14); R3(block, d, e, a, b, c, 15);
        R3(block, c, d, e, a, b, 0);  R3(block, b, c, d, e, a, 1);  R3(block, a, b, c, d, e, 2);  R3(block, e, a, b, c, d, 3);
        R3(block, d, e, a, b, c, 4);  R3(block, c, d, e, a, b, 5);  R3(block, b, c, d, e, a, 6);  R3(block, a, b, c, d, e, 7);
        R3(block, e, a, b, c, d, 8);  R3(block, d, e, a, b, c, 9);  R3(block, c, d, e, a, b, 10); R3(block, b, c, d, e, a, 11);
        R4(block, a, b, c, d, e, 12); R4(block, e, a, b, c, d, 13); R4(block, d, e, a, b, c, 14); R4(block, c, d, e, a, b, 15);
        R4(block, b, c, d, e, a, 0);  R4(block, a, b, c, d, e, 1);  R4(block, e, a, b, c, d, 2);  R4(block, d, e, a, b, c, 3);
        R4(block, c, d, e, a, b, 4);  R4(block, b, c, d, e, a, 5);  R4(block, a, b, c, d, e, 6);  R4(block, e, a, b, c, d, 7);
        R4(block, d, e, a, b, c, 8);  R4(block, c, d, e, a, b, 9);  R4(block, b, c, d, e, a, 10); R4(block, a, b, c, d, e, 11);
        R4(block, e, a, b, c, d, 12); R4(block, d, e, a, b, c, 13); R4(block, c, d, e, a, b, 14); R4(block, b, c, d, e, a, 15);
        
        state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
    }
};

/**
 * @brief 将二进制字符串转换为十六进制字符串
 * @param binary 二进制数据
 * @return 十六进制字符串（小写）
 */
std::string to_hex(const std::string& binary)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : binary)
    {
        ss << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

/**
 * @brief 将十六进制字符串转换为二进制数据
 * @param hex 十六进制字符串（如 "d69f91e6..."）
 * @return std::string 二进制数据
 */
std::string from_hex(const std::string& hex)
{
    std::string binary;
    binary.reserve(hex.size() / 2);
    
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        std::string byte_str = hex.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byte_str, nullptr, 16));
        binary.push_back(byte);
    }
    
    return binary;
}

/**
 * @brief 解码 Bencode 编码的值（带位置跟踪）
 * 
 * Bencode 支持四种数据类型：
 * 1. 字符串 (Strings): 格式为 "<长度>:<内容>"，例如 "5:hello" 表示字符串 "hello"
 * 2. 整数 (Integers): 格式为 "i<数字>e"，例如 "i52e" 表示整数 52，"i-52e" 表示 -52
 * 3. 列表 (Lists): 格式为 "l<元素>e"，例如 "l5:helloi52ee" 表示 ["hello", 52]
 * 4. 字典 (Dictionaries): 格式为 "d<键值对>e"，例如 "d3:foo3:bare" 表示 {"foo":"bar"}
 * 
 * @param encoded_value Bencode 编码的字符串
 * @param pos 当前解析位置（引用，会被更新为解析结束后的位置）
 * @return json 解码后的 JSON 对象
 * @throws std::runtime_error 当遇到无效或不支持的编码格式时抛出异常
 */
json decode_bencoded_value(const std::string& encoded_value, size_t& pos) 
{
    // 检查第一个字符是否为数字，判断是否为字符串类型
    // Bencode 字符串以长度数字开头（0-9）
    if (std::isdigit(encoded_value[pos])) 
    {
        // ================================================================
        // 解码 Bencode 字符串
        // ================================================================
        // 格式: "<长度>:<字符串内容>"
        // 
        // 解析示例: "5:hello"
        //   - "5" 是长度（表示后面有 5 个字符）
        //   - ":" 是分隔符
        //   - "hello" 是实际内容
        // 
        // 解析步骤:
        //   1. 找到冒号位置 -> colon_index = 1
        //   2. 提取长度字符串 "5" -> length = 5
        //   3. 从冒号后提取 5 个字符 -> "hello"
        //   4. 更新 pos 到字符串末尾之后
        
        // 查找冒号分隔符的位置（从当前位置开始搜索）
        size_t colon_index = encoded_value.find(':', pos);
        
        if (colon_index != std::string::npos) 
        {
            // 提取长度部分（当前位置到冒号之间的数字字符串）
            // 例如: pos=0, colon_index=1, 则提取 substr(0, 1) = "5"
            std::string number_string = encoded_value.substr(pos, colon_index - pos);
            
            // 将长度字符串转换为 64 位整数
            // 使用 atoll 处理可能的大数值
            int64_t length = std::atoll(number_string.c_str());
            
            // 提取实际字符串内容（从冒号后开始，长度为 length）
            // 例如: colon_index=1, length=5, 则提取 substr(2, 5) = "hello"
            std::string str = encoded_value.substr(colon_index + 1, length);
            
            // 更新位置：冒号位置 + 1（冒号本身）+ 字符串长度
            // 例如: pos = 1 + 1 + 5 = 7，指向 "5:hello" 之后的位置
            pos = colon_index + 1 + length;
            
            // 将字符串包装为 JSON 对象并返回
            return json(str);
        } 
        else 
        {
            // 字符串格式错误：缺少冒号分隔符
            throw std::runtime_error("Invalid encoded value: " + encoded_value);
        }
    } 
    else if (encoded_value[pos] == 'i')
    {
        // ================================================================
        // 解码 Bencode 整数
        // ================================================================
        // 格式: "i<数字>e"
        // 
        // 解析示例: "i52e"
        //   - "i" 是起始标记
        //   - "52" 是数字内容
        //   - "e" 是结束标记
        // 
        // 解析步骤:
        //   1. 跳过 'i'，从 pos+1 开始
        //   2. 找到 'e' 的位置 -> end_index
        //   3. 提取 'i' 和 'e' 之间的数字字符串
        //   4. 转换为整数
        //   5. 更新 pos 到 'e' 之后
        
        // 查找结束标记 'e' 的位置（从当前位置开始搜索）
        size_t end_index = encoded_value.find('e', pos);
        
        if (end_index != std::string::npos)
        {
            // 提取数字部分（'i' 和 'e' 之间的内容）
            // 例如: "i52e", pos=0, end_index=3
            //       substr(0+1, 3-0-1) = substr(1, 2) = "52"
            std::string number_string = encoded_value.substr(pos + 1, end_index - pos - 1);
            
            // 将数字字符串转换为 64 位整数
            // 支持正数、负数和零
            int64_t number = std::atoll(number_string.c_str());
            
            // 更新位置：跳过结束标记 'e'
            // 例如: pos = 3 + 1 = 4，指向 "i52e" 之后的位置
            pos = end_index + 1;
            
            // 将整数包装为 JSON 对象并返回
            return json(number);
        }
        else
        {
            // 整数格式错误：缺少结束标记 'e'
            throw std::runtime_error("Invalid encoded integer: " + encoded_value);
        }
    }
    else if (encoded_value[pos] == 'l')
    {
        // ================================================================
        // 解码 Bencode 列表
        // ================================================================
        // 格式: "l<元素1><元素2>...e"
        // 
        // 解析示例: "l5:helloi52ee" -> ["hello", 52]
        //   - "l" 是起始标记
        //   - "5:hello" 是第一个元素（字符串）
        //   - "i52e" 是第二个元素（整数）
        //   - "e" 是结束标记
        // 
        // 解析步骤:
        //   1. 跳过 'l'
        //   2. 循环: 检查当前字符是否为 'e'
        //      - 如果不是 'e'，递归解析下一个元素
        //      - pos 会被递归调用自动更新
        //   3. 遇到 'e' 时退出循环，跳过 'e'
        // 
        // 位置变化示例 "l5:helloi52ee":
        //   pos=0 -> 看到 'l', pos++ -> pos=1
        //   pos=1 -> 解析 "5:hello" -> pos=8
        //   pos=8 -> 解析 "i52e" -> pos=12
        //   pos=12 -> 看到 'e', 退出循环, pos++ -> pos=13
        
        // 跳过列表起始标记 'l'
        pos++;
        
        // 创建 JSON 数组来存储列表元素
        json list = json::array();
        
        // 循环解析列表中的每个元素，直到遇到结束标记 'e'
        while (encoded_value[pos] != 'e')
        {
            // 递归调用解码函数解析下一个元素
            // 关键: pos 是引用传递，递归调用后会自动更新到该元素之后的位置
            // 这样下一次循环就能从正确的位置继续解析
            list.push_back(decode_bencoded_value(encoded_value, pos));
        }
        
        // 跳过列表结束标记 'e'
        pos++;
        
        return list;
    }
    else if (encoded_value[pos] == 'd')
    {
        // ================================================================
        // 解码 Bencode 字典
        // ================================================================
        // 格式: "d<key1><value1><key2><value2>...e"
        // 
        // 解析示例: "d3:foo3:bar5:helloi52ee" -> {"foo":"bar","hello":52}
        // 
        // 编码结构分解:
        //   d        -> 字典起始标记
        //   3:foo    -> 键1: 字符串 "foo" (长度=3)
        //   3:bar    -> 值1: 字符串 "bar" (长度=3)
        //   5:hello  -> 键2: 字符串 "hello" (长度=5)
        //   i52e     -> 值2: 整数 52
        //   e        -> 字典结束标记
        // 
        // 解析步骤详解:
        //   | 步骤 | pos | 当前字符 | 操作                      | 结果              |
        //   |-----|-----|---------|--------------------------|------------------|
        //   | 1   | 0   | 'd'     | 识别为字典，pos++          | 进入字典解析       |
        //   | 2   | 1   | '3'     | 递归解析字符串 "3:foo"     | key="foo", pos=6 |
        //   | 3   | 6   | '3'     | 递归解析字符串 "3:bar"     | val="bar", pos=11|
        //   | 4   | 11  | '5'     | 递归解析字符串 "5:hello"   | key="hello",pos=18|
        //   | 5   | 18  | 'i'     | 递归解析整数 "i52e"        | val=52, pos=22   |
        //   | 6   | 22  | 'e'     | 遇到结束标记，退出循环      | 返回字典          |
        // 
        // 关键点:
        //   - 键必须是字符串类型
        //   - 键按字典序排列（Bencode 规范要求）
        //   - 值可以是任意 Bencode 类型（字符串、整数、列表、字典）
        //   - pos 是引用传递，每次递归调用后自动更新位置
        
        // 跳过字典起始标记 'd'
        pos++;
        
        // 创建 JSON 对象来存储键值对
        json dict = json::object();
        
        // 循环解析字典中的每个键值对，直到遇到结束标记 'e'
        while (encoded_value[pos] != 'e')
        {
            // 第一步: 解析键（键必须是字符串类型）
            // 递归调用解码函数，pos 会被自动更新到键之后的位置
            json key = decode_bencoded_value(encoded_value, pos);
            
            // 第二步: 解析值（值可以是任意 Bencode 类型）
            // 再次递归调用，pos 继续更新到值之后的位置
            json value = decode_bencoded_value(encoded_value, pos);
            
            // 第三步: 将键值对添加到字典中
            // key.get<std::string>() 将 JSON 字符串转换为 C++ string 作为键
            dict[key.get<std::string>()] = value;
        }
        
        // 跳过字典结束标记 'e'
        pos++;
        
        return dict;
    }
    else 
    {
        // 遇到未知的编码类型
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

/**
 * @brief 解码 Bencode 编码的值（便捷包装函数）
 * 
 * 这是一个便捷的包装函数，内部创建位置变量并调用带位置跟踪的解码函数。
 * 
 * @param encoded_value Bencode 编码的字符串
 * @return json 解码后的 JSON 对象
 */
json decode_bencoded_value(const std::string& encoded_value) 
{
    size_t pos = 0;
    return decode_bencoded_value(encoded_value, pos);
}

/**
 * @brief 读取文件内容为字符串
 * 
 * 以二进制模式读取文件，确保能正确处理非 UTF-8 字符（如 SHA-1 哈希）
 * 
 * @param file_path 文件路径
 * @return std::string 文件内容
 */
std::string read_file(const std::string& file_path)
{
    // 以二进制模式打开文件，避免换行符转换等问题
    std::ifstream file(file_path, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file: " + file_path);
    }
    
    // 使用 stringstream 读取整个文件内容
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

/**
 * @brief 从 torrent 文件内容中提取 info 字典的原始 Bencode 数据
 * 
 * Info Hash 需要对 info 字典的原始 Bencode 编码数据计算 SHA-1，
 * 而不是对解析后再重新编码的数据计算。因此需要直接从原始文件中提取。
 * 
 * @param file_content torrent 文件的完整内容
 * @return std::string info 字典的原始 Bencode 编码数据
 */
std::string extract_info_dict(const std::string& file_content)
{
    // 查找 "4:info" 键的位置
    // 在 Bencode 中，"info" 键编码为 "4:info"
    std::string info_key = "4:info";
    size_t info_pos = file_content.find(info_key);
    
    if (info_pos == std::string::npos)
    {
        throw std::runtime_error("Could not find info dictionary in torrent file");
    }
    
    // info 字典的起始位置（跳过 "4:info" 键）
    size_t dict_start = info_pos + info_key.length();
    
    // 使用解码函数来确定 info 字典的结束位置
    // 通过 pos 引用参数，解码完成后 pos 会指向字典结束后的位置
    size_t pos = dict_start;
    decode_bencoded_value(file_content, pos);
    
    // 提取 info 字典的原始 Bencode 数据
    return file_content.substr(dict_start, pos - dict_start);
}

// ============================================================================
// URL 编码和 HTTP 请求功能
// ============================================================================

/**
 * @brief URL 编码二进制数据
 * 
 * 将二进制数据（如 info_hash）转换为 URL 编码格式
 * 例如: 字节 0xD6 编码为 "%D6"
 * 
 * @param data 要编码的二进制数据
 * @return std::string URL 编码后的字符串
 */
std::string url_encode(const std::string& data)
{
    std::ostringstream encoded;
    encoded << std::hex << std::uppercase << std::setfill('0');
    
    for (unsigned char c : data)
    {
        // 字母数字和 -_.~ 不需要编码
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded << c;
        }
        else
        {
            encoded << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    
    return encoded.str();
}

/**
 * @brief URL 解码
 * 
 * 将 URL 编码的字符串解码为原始字符串
 * 例如: "%2F" 解码为 "/"
 * 
 * @param data URL 编码的字符串
 * @return std::string 解码后的字符串
 */
std::string url_decode(const std::string& data)
{
    std::string decoded;
    decoded.reserve(data.size());
    
    for (size_t i = 0; i < data.size(); i++)
    {
        if (data[i] == '%' && i + 2 < data.size())
        {
            // 解码 %XX 格式
            std::string hex = data.substr(i + 1, 2);
            char c = static_cast<char>(std::stoi(hex, nullptr, 16));
            decoded += c;
            i += 2;
        }
        else if (data[i] == '+')
        {
            // '+' 在 URL 中表示空格
            decoded += ' ';
        }
        else
        {
            decoded += data[i];
        }
    }
    
    return decoded;
}

/**
 * @brief 解析磁力链接
 * 
 * 从磁力链接中提取 info hash 和 tracker URL
 * 
 * @param magnet_link 磁力链接字符串
 * @param info_hash 输出: info hash（40 字符十六进制）
 * @param tracker_url 输出: tracker URL
 */
void parse_magnet_link(const std::string& magnet_link, std::string& info_hash, std::string& tracker_url)
{
    // 磁力链接格式: magnet:?xt=urn:btih:<info_hash>&dn=<name>&tr=<tracker_url>
    
    // 查找查询参数开始位置
    size_t query_start = magnet_link.find('?');
    if (query_start == std::string::npos)
    {
        throw std::runtime_error("Invalid magnet link: no query parameters");
    }
    
    std::string query = magnet_link.substr(query_start + 1);
    
    // 解析查询参数
    size_t pos = 0;
    while (pos < query.size())
    {
        // 查找参数结束位置
        size_t amp_pos = query.find('&', pos);
        std::string param;
        if (amp_pos == std::string::npos)
        {
            param = query.substr(pos);
            pos = query.size();
        }
        else
        {
            param = query.substr(pos, amp_pos - pos);
            pos = amp_pos + 1;
        }
        
        // 分割键值对
        size_t eq_pos = param.find('=');
        if (eq_pos == std::string::npos) continue;
        
        std::string key = param.substr(0, eq_pos);
        std::string value = param.substr(eq_pos + 1);
        
        if (key == "xt")
        {
            // xt=urn:btih:<info_hash>
            std::string prefix = "urn:btih:";
            size_t hash_start = value.find(prefix);
            if (hash_start != std::string::npos)
            {
                info_hash = value.substr(hash_start + prefix.size());
            }
        }
        else if (key == "tr")
        {
            // tr=<tracker_url> (URL 编码)
            tracker_url = url_decode(value);
        }
    }
}

/**
 * @brief 生成随机的 20 字节 peer_id
 * 
 * 格式: -CC0001-<12个随机字符>
 * - CC: 客户端标识 (CodeCrafters)
 * - 0001: 版本号
 * - 后面12个字符随机生成
 * 
 * @return std::string 20 字节的 peer_id
 */
std::string generate_peer_id()
{
    std::string peer_id = "-CC0001-";  // 8 字节前缀
    
    // 使用随机设备和 Mersenne Twister 生成器
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 61);  // 0-9, a-z, A-Z
    
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    // 生成剩余 12 个随机字符
    for (int i = 0; i < 12; i++)
    {
        peer_id += charset[dis(gen)];
    }
    
    return peer_id;
}

/**
 * @brief 生成指定长度的随机字节序列
 */
std::string generate_random_bytes(size_t length)
{
    std::string out(length, '\0');
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    for (size_t i = 0; i < length; i++)
    {
        out[i] = static_cast<char>(dis(gen));
    }

    return out;
}

/**
 * @brief 生成握手用的 20 字节随机 peer_id（任意字节值）
 */
std::string generate_peer_id_bytes()
{
    return generate_random_bytes(20);
}

/**
 * @brief 解析 "<host>:<port>" 字符串
 */
void parse_host_port(const std::string& host_port, std::string& host, int& port)
{
    size_t colon = host_port.rfind(':');
    if (colon == std::string::npos)
    {
        throw std::runtime_error("Invalid peer address (expected <host>:<port>): " + host_port);
    }

    host = host_port.substr(0, colon);
    std::string port_str = host_port.substr(colon + 1);

    if (host.empty() || port_str.empty())
    {
        throw std::runtime_error("Invalid peer address (expected <host>:<port>): " + host_port);
    }

    port = std::stoi(port_str);
}

/**
 * @brief 解析 URL，提取 host、port 和 path
 * 
 * @param url 完整的 URL
 * @param host 输出: 主机名
 * @param port 输出: 端口号
 * @param path 输出: 路径
 */
void parse_url(const std::string& url, std::string& host, int& port, std::string& path)
{
    // 跳过 "http://"
    size_t start = url.find("://");
    if (start == std::string::npos)
    {
        start = 0;
    }
    else
    {
        start += 3;
    }
    
    // 查找路径开始位置
    size_t path_start = url.find('/', start);
    if (path_start == std::string::npos)
    {
        path = "/";
        path_start = url.length();
    }
    else
    {
        path = url.substr(path_start);
    }
    
    // 提取 host:port
    std::string host_port = url.substr(start, path_start - start);
    
    // 查找端口分隔符
    size_t colon = host_port.find(':');
    if (colon == std::string::npos)
    {
        host = host_port;
        port = 80;  // 默认 HTTP 端口
    }
    else
    {
        host = host_port.substr(0, colon);
        port = std::stoi(host_port.substr(colon + 1));
    }
}

/**
 * @brief 发送 HTTP GET 请求并返回响应体
 * 
 * @param url 请求的 URL（包含查询参数）
 * @return std::string HTTP 响应体
 */
std::string http_get(const std::string& url)
{
    std::string host, path;
    int port;
    parse_url(url, host, port, path);

    // 解析主机名
    struct addrinfo hints{}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0)
    {
        throw std::runtime_error("Failed to resolve host: " + host);
    }
    
    // 创建 socket
    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET)
    {
        freeaddrinfo(result);
        throw std::runtime_error("Failed to create socket");
    }
    
    // 连接到服务器
    if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR)
    {
        closesocket(sock);
        freeaddrinfo(result);
        throw std::runtime_error("Failed to connect to server");
    }
    
    freeaddrinfo(result);
    
    // 构建 HTTP 请求
    std::ostringstream request;
    request << "GET " << path << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "Connection: close\r\n";
    request << "\r\n";
    
    std::string request_str = request.str();
    
    // 发送请求
    if (send(sock, request_str.c_str(), static_cast<int>(request_str.size()), 0) == SOCKET_ERROR)
    {
        closesocket(sock);
        throw std::runtime_error("Failed to send request");
    }
    
    // 接收响应
    std::string response;
    char buffer[4096];
    int bytes_received;
    
    while ((bytes_received = recv(sock, buffer, sizeof(buffer), 0)) > 0)
    {
        response.append(buffer, bytes_received);
    }

    closesocket(sock);

    // 解析 HTTP 响应，提取响应体
    // HTTP 响应头和响应体之间用 \r\n\r\n 分隔
    size_t body_start = response.find("\r\n\r\n");
    if (body_start == std::string::npos)
    {
        throw std::runtime_error("Invalid HTTP response");
    }
    
    return response.substr(body_start + 4);
}

// ============================================================================
// TCP 工具函数（peer 握手用）
// ============================================================================

/**
 * @brief 连接到指定 host:port，返回已连接的 socket
 */
SOCKET tcp_connect(const std::string& host, int port)
{
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0)
    {
        throw std::runtime_error("Failed to resolve host: " + host);
    }

    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET)
    {
        freeaddrinfo(result);
        throw std::runtime_error("Failed to create socket");
    }

    if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR)
    {
        closesocket(sock);
        freeaddrinfo(result);
        throw std::runtime_error("Failed to connect to peer");
    }

    freeaddrinfo(result);
    return sock;
}

/**
 * @brief 确保发送完所有数据
 */
void send_all(SOCKET sock, const std::string& data)
{
    size_t total_sent = 0;
    while (total_sent < data.size())
    {
        int sent = send(sock, data.data() + total_sent, static_cast<int>(data.size() - total_sent), 0);
        if (sent == SOCKET_ERROR || sent == 0)
        {
            throw std::runtime_error("Failed to send data");
        }
        total_sent += static_cast<size_t>(sent);
    }
}

/**
 * @brief 接收指定长度的字节数（不够则循环接收）
 */
std::string recv_exact(SOCKET sock, size_t length)
{
    std::string out;
    out.resize(length);

    size_t total = 0;
    while (total < length)
    {
        int received = recv(sock, &out[total], static_cast<int>(length - total), 0);
        if (received == SOCKET_ERROR)
        {
            throw std::runtime_error("Failed to receive data");
        }
        if (received == 0)
        {
            throw std::runtime_error("Peer closed connection");
        }
        total += static_cast<size_t>(received);
    }

    return out;
}

// ============================================================================
// Peer Message 编解码（下载 piece 用）
// ============================================================================

uint32_t read_u32_be(const std::string& buf, size_t offset)
{
    return (static_cast<uint32_t>(static_cast<unsigned char>(buf[offset])) << 24) |
           (static_cast<uint32_t>(static_cast<unsigned char>(buf[offset + 1])) << 16) |
           (static_cast<uint32_t>(static_cast<unsigned char>(buf[offset + 2])) << 8) |
           (static_cast<uint32_t>(static_cast<unsigned char>(buf[offset + 3])));
}

void append_u32_be(std::string& out, uint32_t value)
{
    out.push_back(static_cast<char>((value >> 24) & 0xFF));
    out.push_back(static_cast<char>((value >> 16) & 0xFF));
    out.push_back(static_cast<char>((value >> 8) & 0xFF));
    out.push_back(static_cast<char>(value & 0xFF));
}

struct PeerMessage
{
    uint32_t length = 0; // 不含自身 4 字节前缀
    bool keepalive = false;
    uint8_t id = 0;
    std::string payload;
};

PeerMessage recv_peer_message(SOCKET sock)
{
    PeerMessage msg;
    std::string len_bytes = recv_exact(sock, 4);
    msg.length = read_u32_be(len_bytes, 0);

    if (msg.length == 0)
    {
        msg.keepalive = true;
        return msg;
    }

    std::string rest = recv_exact(sock, msg.length);
    msg.id = static_cast<uint8_t>(rest[0]);
    if (msg.length > 1)
    {
        msg.payload = rest.substr(1);
    }

    return msg;
}

void send_peer_message(SOCKET sock, uint8_t id, const std::string& payload)
{
    std::string out;
    out.reserve(4 + 1 + payload.size());

    uint32_t length = static_cast<uint32_t>(1 + payload.size());
    append_u32_be(out, length);
    out.push_back(static_cast<char>(id));
    out += payload;

    send_all(sock, out);
}

/**
 * @brief 构建 BitTorrent 握手消息
 * 
 * @param info_hash 20 字节的 info hash
 * @param peer_id 20 字节的 peer id
 * @param support_extensions 是否支持扩展协议（设置第 20 位）
 * @return std::string 68 字节的握手消息
 */
std::string build_handshake(const std::string& info_hash, const std::string& peer_id, bool support_extensions = false)
{
    if (info_hash.size() != 20) throw std::runtime_error("Invalid info_hash length");
    if (peer_id.size() != 20) throw std::runtime_error("Invalid peer_id length");

    std::string handshake;
    handshake.reserve(68);
    handshake.push_back(static_cast<char>(19));
    handshake += "BitTorrent protocol";
    
    // 8 字节保留位
    // 如果支持扩展，设置第 20 位（从右边数，从 0 开始）
    // 第 20 位在第 6 个字节（索引 5）的第 4 位
    // 00 00 00 00 00 10 00 00 (hex)
    if (support_extensions)
    {
        handshake.append(5, '\0');           // 前 5 字节为 0
        handshake.push_back('\x10');         // 第 6 字节 = 0x10 (00010000)
        handshake.append(2, '\0');           // 后 2 字节为 0
    }
    else
    {
        handshake.append(8, '\0');           // 全部为 0
    }
    
    handshake += info_hash;
    handshake += peer_id;
    return handshake;
}

/**
 * @brief 执行 BitTorrent 握手
 * 
 * @param sock 已连接的 socket
 * @param info_hash 20 字节的 info hash
 * @param my_peer_id 20 字节的本地 peer id
 * @param support_extensions 是否支持扩展协议
 * @param peer_supports_extensions 输出: 对方是否支持扩展协议
 * @return std::string 对方的 peer id（20 字节）
 */
std::string perform_handshake(SOCKET sock, const std::string& info_hash, const std::string& my_peer_id, 
                              bool support_extensions = false, bool* peer_supports_extensions = nullptr)
{
    std::string hs = build_handshake(info_hash, my_peer_id, support_extensions);
    send_all(sock, hs);

    std::string response = recv_exact(sock, 68);
    if (static_cast<unsigned char>(response[0]) != 19 || response.substr(1, 19) != "BitTorrent protocol")
    {
        throw std::runtime_error("Invalid handshake response");
    }

    // 检查对方是否支持扩展（保留位第 20 位）
    // 
    // 握手响应结构 (68 字节):
    //   索引:    0      1-19              20-27        28-47        48-67
    //          ┌───┬─────────────────┬────────────┬────────────┬────────────┐
    //          │19 │BitTorrent proto │ 保留位(8B) │ info_hash  │  peer_id   │
    //          └───┴─────────────────┴────────────┴────────────┴────────────┘
    //           1B       19 字节          8 字节      20 字节      20 字节
    //
    // 保留位 (索引 20-27):
    //   索引:   20   21   22   23   24   25   26   27
    //         ┌────┬────┬────┬────┬────┬────┬────┬────┐
    //         │ 00 │ 00 │ 00 │ 00 │ 00 │ 10 │ 00 │ 00 │  ← 支持扩展时
    //         └────┴────┴────┴────┴────┴────┴────┴────┘
    //                                   ↑
    //                              response[25] = 0x10
    //
    // 第 20 位（从右数，从 0 开始）位于:
    //   - 字节索引 25（从右数第 3 个字节: 27 - 20/8 = 25）
    //   - 该字节内第 4 位（20 % 8 = 4，即 0x10 = 00010000）
    if (peer_supports_extensions != nullptr)
    {
        unsigned char reserved_byte = static_cast<unsigned char>(response[25]);
        *peer_supports_extensions = (reserved_byte & 0x10) != 0;
    }

    // reserved(8) + info_hash(20) + peer_id(20)
    std::string received_peer_id = response.substr(48, 20);
    return received_peer_id;
}

// ============================================================================
// Bencode 编码函数
// ============================================================================

/**
 * @brief 将 JSON 对象编码为 Bencode 格式
 */

//  {"m": {"ut_metadata": 1}}
//         ↓ bencode_encode
// d                           ← 字典开始
//   1:m                       ← 键 "m" (长度1)
//   d                         ← 值是字典，字典开始
//     11:ut_metadata          ← 键 "ut_metadata" (长度11)
//     i1e                     ← 值 1 (整数)
//   e                         ← 内层字典结束
// e                           ← 外层字典结束

// 最终: "d1:md11:ut_metadatai1eee"
std::string bencode_encode(const json& j)
{
    if (j.is_string())
    {
        std::string s = j.get<std::string>();
        return std::to_string(s.size()) + ":" + s;
    }
    else if (j.is_number_integer())
    {
        return "i" + std::to_string(j.get<int64_t>()) + "e";
    }
    else if (j.is_array())
    {
        std::string result = "l";
        for (const auto& item : j)
        {
            result += bencode_encode(item);
        }
        result += "e";
        return result;
    }
    else if (j.is_object())
    {
        std::string result = "d";
        // 字典键必须按字典序排列
        std::vector<std::string> keys;
        for (auto it = j.begin(); it != j.end(); ++it)
        {
            keys.push_back(it.key());
        }
        std::sort(keys.begin(), keys.end());
        
        for (const auto& key : keys)
        {
            result += std::to_string(key.size()) + ":" + key;
            result += bencode_encode(j[key]);
        }
        result += "e";
        return result;
    }
    
    throw std::runtime_error("Unsupported JSON type for bencode encoding");
}

// ============================================================================
// 扩展协议相关函数
// ============================================================================

/**
 * @brief 发送扩展握手消息
 * 
 * 扩展消息格式:
 * - 4 字节: 消息长度
 * - 1 字节: 消息 ID (20 = 扩展消息)
 * - 1 字节: 扩展消息 ID (0 = 扩展握手)
 * - N 字节: Bencode 编码的字典 {"m": {"ut_metadata": <ID>}}
 */
void send_extension_handshake(SOCKET sock)
{
    // 构建扩展握手字典
    // {"m": {"ut_metadata": 1}}
    json ext_handshake;
    ext_handshake["m"]["ut_metadata"] = 1;  // 我们使用 ID 1 表示 ut_metadata
    
    std::string bencoded = bencode_encode(ext_handshake);
    
    // 构建完整消息
    std::string message;
    
    // 消息长度 = 1 (消息ID) + 1 (扩展消息ID) + bencoded.size()
    uint32_t length = static_cast<uint32_t>(2 + bencoded.size());
    append_u32_be(message, length);
    
    message.push_back(static_cast<char>(20));  // 消息 ID = 20 (扩展消息)
    message.push_back(static_cast<char>(0));   // 扩展消息 ID = 0 (扩展握手)
    message += bencoded;
    
    send_all(sock, message);
}

/**
 * @brief 接收扩展握手消息
 * 
 * 扩展握手消息格式:
 * - 4 字节: 消息长度
 * - 1 字节: 消息 ID (20 = 扩展消息)
 * - 1 字节: 扩展消息 ID (0 = 扩展握手)
 * - N 字节: Bencode 编码的字典 {"m": {"ut_metadata": <ID>}, ...}
 * 
 * @param sock 已连接的 socket
 * @return json 解析后的扩展握手字典
 */
json recv_extension_handshake(SOCKET sock)
{
    // 循环接收消息，直到收到扩展握手消息 (ID=20, ExtID=0)
    while (true)
    {
        PeerMessage msg = recv_peer_message(sock);
        
        if (msg.keepalive) continue;
        
        // 检查是否是扩展消息 (ID=20)
        if (msg.id == 20 && !msg.payload.empty())
        {
            // 第一个字节是扩展消息 ID
            uint8_t ext_msg_id = static_cast<uint8_t>(msg.payload[0]);
            
            // 扩展握手的扩展消息 ID 是 0
            if (ext_msg_id == 0)
            {
                // 剩余部分是 Bencode 编码的字典
                std::string bencoded = msg.payload.substr(1);
                return decode_bencoded_value(bencoded);
            }
        }
        
        // 其他消息类型，继续等待
    }
}

/**
 * @brief 发送元数据请求消息
 * 
 * 元数据请求消息格式:
 * - 4 字节: 消息长度
 * - 1 字节: 消息 ID (20 = 扩展消息)
 * - 1 字节: 扩展消息 ID (对方的 ut_metadata ID)
 * - N 字节: Bencode 编码的字典 {"msg_type": 0, "piece": 0}
 *           msg_type=0 表示请求消息
 *           piece=0 表示请求第 0 个元数据分片
 * 
 * @param sock 已连接的 socket
 * @param peer_metadata_id 对方的 ut_metadata 扩展 ID
 * @param piece_index 要请求的元数据分片索引（通常为 0）
 */
void send_metadata_request(SOCKET sock, int peer_metadata_id, int piece_index = 0)
{
    // 构建请求字典 {"msg_type": 0, "piece": 0}
    json request;
    request["msg_type"] = 0;  // 0 = request
    request["piece"] = piece_index;
    
    std::string bencoded = bencode_encode(request);
    
    // 构建完整消息
    std::string message;
    
    // 消息长度 = 1 (消息ID) + 1 (扩展消息ID) + bencoded.size()
    uint32_t length = static_cast<uint32_t>(2 + bencoded.size());
    append_u32_be(message, length);
    
    message.push_back(static_cast<char>(20));  // 消息 ID = 20 (扩展消息)
    message.push_back(static_cast<char>(peer_metadata_id));  // 对方的 ut_metadata ID
    message += bencoded;
    
    send_all(sock, message);
}

/**
 * @brief 接收元数据数据消息
 * 
 * 元数据数据消息格式:
 * - 4 字节: 消息长度
 * - 1 字节: 消息 ID (20 = 扩展消息)
 * - 1 字节: 扩展消息 ID (我们的 ut_metadata ID，即 1)
 * - N 字节: Bencode 编码的字典 {'msg_type': 1, 'piece': 0, 'total_size': XXXX}
 * - M 字节: metadata piece contents (实际的 info 字典数据)
 * 
 * @param sock 已连接的 socket
 * @return std::string metadata 内容（info 字典的 bencode 编码）
 */
std::string recv_metadata_data(SOCKET sock)
{
    // 循环接收消息，直到收到 metadata data 消息 (ID=20, msg_type=1)
    while (true)
    {
        PeerMessage msg = recv_peer_message(sock);
        
        if (msg.keepalive) continue;
        
        // 检查是否是扩展消息 (ID=20)
        if (msg.id == 20 && !msg.payload.empty())
        {
            // 第一个字节是扩展消息 ID（应该是我们告诉对方的 ut_metadata ID = 1）
            uint8_t ext_msg_id = static_cast<uint8_t>(msg.payload[0]);
            
            // 我们在扩展握手中告诉对方我们的 ut_metadata ID 是 1
            if (ext_msg_id == 1)
            {
                // 剩余部分: bencode 字典 + metadata 内容
                std::string rest = msg.payload.substr(1);
                
                // 解析 bencode 字典，获取其结束位置
                size_t pos = 0;
                json dict = decode_bencoded_value(rest, pos);
                
                // 检查 msg_type 是否为 1 (data)
                if (dict.contains("msg_type") && dict["msg_type"].get<int>() == 1)
                {
                    // pos 现在指向 bencode 字典结束后的位置
                    // 剩余部分就是 metadata piece contents
                    std::string metadata = rest.substr(pos);
                    return metadata;
                }
            }
        }
        
        // 其他消息类型，继续等待
    }
}

// ============================================================================
// Peer 下载辅助函数（bitfield / interested / unchoke / request/piece）
// ============================================================================

bool bitfield_has_piece(const std::string& bitfield, int piece_index)
{
    if (piece_index < 0) return false;
    size_t byte_index = static_cast<size_t>(piece_index / 8);
    int bit_in_byte = 7 - (piece_index % 8);
    if (byte_index >= bitfield.size()) return false;

    unsigned char b = static_cast<unsigned char>(bitfield[byte_index]);
    return ((b >> bit_in_byte) & 1u) != 0;
}

std::string recv_bitfield_payload(SOCKET sock)
{
    while (true)
    {
        PeerMessage msg = recv_peer_message(sock);
        if (msg.keepalive) continue;
        if (msg.id == 5)
        {
            return msg.payload;
        }
        // 其他消息忽略（比如 have/unchoke/choke）
    }
}

bool wait_for_unchoke(SOCKET sock)
{
    bool choked = true;
    while (choked)
    {
        PeerMessage msg = recv_peer_message(sock);
        if (msg.keepalive) continue;
        if (msg.id == 1) choked = false;      // unchoke
        else if (msg.id == 0) choked = true;  // choke
        // 其他消息忽略
    }
    return true;
}

std::string download_piece_from_peer(SOCKET sock, int piece_index, int64_t piece_size)
{
    const int64_t block_size = 16 * 1024;

    std::string piece_data;
    piece_data.resize(static_cast<size_t>(piece_size));

    for (int64_t begin = 0; begin < piece_size; begin += block_size)
    {
        int64_t req_len = std::min(block_size, piece_size - begin);

        bool done = false;
        while (!done)
        {
            // request payload: index(4) + begin(4) + length(4)
            std::string payload;
            payload.reserve(12);
            append_u32_be(payload, static_cast<uint32_t>(piece_index));
            append_u32_be(payload, static_cast<uint32_t>(begin));
            append_u32_be(payload, static_cast<uint32_t>(req_len));
            send_peer_message(sock, 6, payload);

            bool choked = false;
            while (true)
            {
                PeerMessage msg = recv_peer_message(sock);
                if (msg.keepalive) continue;

                if (msg.id == 0)
                {
                    choked = true;
                    break;
                }
                if (msg.id == 1)
                {
                    // unchoke
                    continue;
                }

                if (msg.id != 7) continue;

                if (msg.payload.size() < 8)
                {
                    throw std::runtime_error("Invalid piece message payload");
                }

                uint32_t resp_index = read_u32_be(msg.payload, 0);
                uint32_t resp_begin = read_u32_be(msg.payload, 4);
                if (resp_index != static_cast<uint32_t>(piece_index) || resp_begin != static_cast<uint32_t>(begin))
                {
                    // 乱序/其他 piece 的数据，继续等
                    continue;
                }

                std::string block = msg.payload.substr(8);
                if (static_cast<int64_t>(block.size()) != req_len)
                {
                    throw std::runtime_error("Unexpected block length");
                }

                std::memcpy(&piece_data[static_cast<size_t>(begin)], block.data(), block.size());
                done = true;
                break;
            }

            if (choked)
            {
                // 被 choke 了，等再次 unchoke 后重发本 block 的 request
                wait_for_unchoke(sock);
            }
        }
    }

    return piece_data;
}

// ============================================================================
// 并发下载 work queue（download 命令用）
// ============================================================================

struct PieceWorkQueue
{
    std::mutex mu;
    std::vector<uint8_t> state; // 0=pending,1=in_progress,2=done
    std::atomic<int64_t> remaining{0};

    explicit PieceWorkQueue(int64_t num_pieces)
        : state(static_cast<size_t>(num_pieces), 0), remaining(num_pieces)
    {
    }
};

int acquire_next_piece(PieceWorkQueue& q, const std::string& bitfield, int64_t num_pieces)
{
    std::lock_guard<std::mutex> lock(q.mu);
    if (q.remaining.load() <= 0) return -1;

    for (int64_t i = 0; i < num_pieces; i++)
    {
        if (q.state[static_cast<size_t>(i)] != 0) continue;
        if (!bitfield.empty() && !bitfield_has_piece(bitfield, static_cast<int>(i))) continue;

        q.state[static_cast<size_t>(i)] = 1;
        return static_cast<int>(i);
    }

    return -1;
}

void mark_piece_done(PieceWorkQueue& q, int piece_index)
{
    std::lock_guard<std::mutex> lock(q.mu);
    if (piece_index < 0) return;
    size_t idx = static_cast<size_t>(piece_index);
    if (idx >= q.state.size()) return;

    if (q.state[idx] == 1)
    {
        q.state[idx] = 2;
        q.remaining.fetch_sub(1);
    }
}

void mark_piece_retry(PieceWorkQueue& q, int piece_index)
{
    std::lock_guard<std::mutex> lock(q.mu);
    if (piece_index < 0) return;
    size_t idx = static_cast<size_t>(piece_index);
    if (idx >= q.state.size()) return;

    if (q.state[idx] == 1)
    {
        q.state[idx] = 0;
    }
}

void download_worker(
    const std::string& peer_addr,
    const std::string& info_hash,
    const std::string& my_peer_id,
    int64_t total_length,
    int64_t piece_length,
    const std::string& pieces_blob,
    PieceWorkQueue* queue,
    std::vector<char>* out_buf)
{
    std::string peer_host;
    int peer_port = 0;
    parse_host_port(peer_addr, peer_host, peer_port);

    SOCKET sock = INVALID_SOCKET;
    int current_piece = -1;

    try
    {
        sock = tcp_connect(peer_host, peer_port);
        (void)perform_handshake(sock, info_hash, my_peer_id);

        std::string bitfield = recv_bitfield_payload(sock);
        send_peer_message(sock, 2, "");
        wait_for_unchoke(sock);

        int64_t num_pieces = static_cast<int64_t>(pieces_blob.size() / 20);

        while (queue->remaining.load() > 0)
        {
            current_piece = acquire_next_piece(*queue, bitfield, num_pieces);
            if (current_piece < 0)
            {
                // 这个 peer 没有可下载的 piece（或都被领走了）
                break;
            }

            int64_t piece_offset = static_cast<int64_t>(current_piece) * piece_length;
            int64_t piece_size = std::min(piece_length, total_length - piece_offset);
            if (piece_size < 0)
            {
                throw std::runtime_error("Invalid piece size");
            }

            std::string expected_piece_hash = pieces_blob.substr(static_cast<size_t>(current_piece) * 20, 20);

            std::string piece_data = download_piece_from_peer(sock, current_piece, piece_size);
            std::string actual_hash = SHA1::hash(piece_data);
            if (actual_hash != expected_piece_hash)
            {
                mark_piece_retry(*queue, current_piece);
                current_piece = -1;
                continue;
            }

            // 写入共享缓冲区（每个 piece 对应的区间互不重叠）
            if (piece_offset + piece_size > static_cast<int64_t>(out_buf->size()))
            {
                throw std::runtime_error("Output buffer overflow");
            }
            std::memcpy(out_buf->data() + piece_offset, piece_data.data(), static_cast<size_t>(piece_size));

            mark_piece_done(*queue, current_piece);
            current_piece = -1;
        }

        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    catch (...)
    {
        if (current_piece >= 0)
        {
            mark_piece_retry(*queue, current_piece);
        }
        if (sock != INVALID_SOCKET)
        {
            closesocket(sock);
        }
        throw;
    }
}


/**
 * @brief 从 tracker 响应中解析 peers 列表

 * 
 * Tracker 返回的 peers 是紧凑格式：每 6 字节表示一个 peer
 * - 前 4 字节: IP 地址（大端序）
 * - 后 2 字节: 端口号（大端序）
 * 
 * @param peers_data 紧凑格式的 peers 数据
 * @return std::vector<std::string> 解析后的 peer 列表（格式: "IP:port"）
 */
std::vector<std::string> parse_peers(const std::string& peers_data)
{
    std::vector<std::string> peers;
    
    // 每 6 字节是一个 peer
    for (size_t i = 0; i + 5 < peers_data.size(); i += 6)
    {
        // 提取 IP 地址（4 字节）
        unsigned char ip1 = static_cast<unsigned char>(peers_data[i]);
        unsigned char ip2 = static_cast<unsigned char>(peers_data[i + 1]);
        unsigned char ip3 = static_cast<unsigned char>(peers_data[i + 2]);
        unsigned char ip4 = static_cast<unsigned char>(peers_data[i + 3]);
        
        // 提取端口号（2 字节，大端序）
        uint16_t port = (static_cast<unsigned char>(peers_data[i + 4]) << 8) |
                        static_cast<unsigned char>(peers_data[i + 5]);
        
        // 格式化为 "IP:port"
        std::ostringstream peer;
        peer << static_cast<int>(ip1) << "."
             << static_cast<int>(ip2) << "."
             << static_cast<int>(ip3) << "."
             << static_cast<int>(ip4) << ":"
             << port;
        
        peers.push_back(peer.str());
    }
    
    return peers;
}

/**
 * @brief 程序主入口
 * 
 * 命令行用法:
 *   ./your_program decode <encoded_value>
 *   ./your_program info <torrent_file>
 * 
 * 示例:
 *   ./your_program decode "5:hello"              -> 输出: "hello"
 *   ./your_program decode "i52e"                 -> 输出: 52
 *   ./your_program decode "l5:helloi52ee"        -> 输出: ["hello",52]
 *   ./your_program decode "d3:foo3:bar5:helloi52ee" -> 输出: {"foo":"bar","hello":52}
 *   ./your_program info sample.torrent           -> 输出: Tracker URL 和 Length
 * 
 * @param argc 命令行参数数量
 * @param argv 命令行参数数组
 * @return int 程序退出码（0 表示成功，非 0 表示错误）
 */
int main(int argc, char* argv[]) 
{
    // 设置 stdout 和 stderr 为无缓冲模式
    // 确保每次输出后立即刷新，便于调试和测试
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // 检查是否提供了足够的命令行参数
    if (argc < 2) 
    {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;  // 返回错误码
    }

    // 获取用户指定的命令（第一个参数）
    std::string command = argv[1];

    // 处理 "decode" 命令
    if (command == "decode") 
    {
        // 确保提供了要解码的值
        if (argc < 3) 
        {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        
        // 调试日志输出到 stderr，不影响正常输出
        std::cerr << "Logs from your program will appear here!" << std::endl;

        // 获取要解码的 Bencode 编码值
        std::string encoded_value = argv[2];
        
        // 调用解码函数进行 Bencode 解码
        json decoded_value = decode_bencoded_value(encoded_value);
        
        // 将解码结果以 JSON 格式输出到 stdout
        // dump() 方法将 JSON 对象序列化为字符串
        std::cout << decoded_value.dump() << std::endl;
    }
    else if (command == "info")
    {
        // ================================================================
        // 处理 "info" 命令 - 解析 torrent 文件并输出元信息
        // ================================================================
        // torrent 文件结构（Bencode 编码的字典）:
        //   - announce: tracker URL（字符串）
        //   - info: 字典，包含:
        //       - length: 文件大小（字节）
        //       - name: 建议的文件名
        //       - piece length: 每个分片的大小
        //       - pieces: 所有分片的 SHA-1 哈希值拼接
        //
        // Info Hash 计算步骤:
        //   1. 提取 info 字典的原始 Bencode 编码数据
        //   2. 对该数据计算 SHA-1 哈希
        //   3. 输出 40 字符的十六进制字符串
        
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " info <torrent_file>" << std::endl;
            return 1;
        }
        
        // 读取 torrent 文件内容（二进制模式）
        std::string torrent_file = argv[2];
        std::string file_content = read_file(torrent_file);
        
        // 解析 Bencode 编码的 torrent 文件
        json torrent = decode_bencoded_value(file_content);
        
        // 提取并输出 Tracker URL
        std::string tracker_url = torrent["announce"].get<std::string>();
        std::cout << "Tracker URL: " << tracker_url << std::endl;
        
        // 提取并输出文件长度
        int64_t length = torrent["info"]["length"].get<int64_t>();
        std::cout << "Length: " << length << std::endl;
        
        // 计算并输出 Info Hash
        // 1. 提取 info 字典的原始 Bencode 数据
        std::string info_dict = extract_info_dict(file_content);
        // 2. 计算 SHA-1 哈希
        std::string info_hash = SHA1::hash(info_dict);
        // 3. 转换为十六进制并输出
        std::cout << "Info Hash: " << to_hex(info_hash) << std::endl;
        
        // 提取并输出 Piece Length（每个分片的字节数）
        int64_t piece_length = torrent["info"]["piece length"].get<int64_t>();
        std::cout << "Piece Length: " << piece_length << std::endl;
        
        // 提取并输出 Piece Hashes
        // pieces 字段是所有分片 SHA-1 哈希值的拼接（每个哈希 20 字节）
        std::string pieces = torrent["info"]["pieces"].get<std::string>();
        std::cout << "Piece Hashes:" << std::endl;
        
        // 每 20 字节是一个 SHA-1 哈希，遍历并转换为十六进制输出
        for (size_t i = 0; i < pieces.size(); i += 20)
        {
            std::string piece_hash = pieces.substr(i, 20);
            std::cout << to_hex(piece_hash) << std::endl;
        }
    }
    else if (command == "peers")
    {
        // ================================================================
        // 处理 "peers" 命令 - 从 tracker 获取 peers 列表
        // ================================================================
        // 向 tracker 发送 GET 请求，包含以下参数:
        //   - info_hash: torrent 的 info hash（20 字节，URL 编码）
        //   - peer_id: 客户端标识（20 字节）
        //   - port: 监听端口
        //   - uploaded/downloaded/left: 传输统计
        //   - compact: 使用紧凑格式
        
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " peers <torrent_file>" << std::endl;
            return 1;
        }
        
        // 读取并解析 torrent 文件
        std::string torrent_file = argv[2];
        std::string file_content = read_file(torrent_file);
        json torrent = decode_bencoded_value(file_content);
        
        // 获取 tracker URL
        std::string tracker_url = torrent["announce"].get<std::string>();
        
        // 获取文件长度
        int64_t length = torrent["info"]["length"].get<int64_t>();
        
        // 计算 info hash（20 字节二进制）
        std::string info_dict = extract_info_dict(file_content);
        std::string info_hash = SHA1::hash(info_dict);
        
        // 构建请求 URL
        std::ostringstream url;
        url << tracker_url;
        url << "?info_hash=" << url_encode(info_hash);
        url << "&peer_id=" << generate_peer_id();  // 随机生成的 20 字节 peer_id
        url << "&port=" << 6881;
        url << "&uploaded=" << 0;
        url << "&downloaded=" << 0;
        url << "&left=" << length;
        url << "&compact=" << 1;
        
        // 发送请求并获取响应
        std::string response = http_get(url.str());
        
        // 解析 Bencode 响应
        json tracker_response = decode_bencoded_value(response);
        
        // 获取 peers 数据并解析
        std::string peers_data = tracker_response["peers"].get<std::string>();
        std::vector<std::string> peers = parse_peers(peers_data);
        
        // 输出每个 peer
        for (const auto& peer : peers)
        {
            std::cout << peer << std::endl;
        }
    }
    else if (command == "handshake")
    {
        // ================================================================
        // 处理 "handshake" 命令 - 与 peer 建立 TCP 连接并完成握手
        // ================================================================
        // 命令行用法:
        //   ./your_program handshake <torrent_file> <peer_ip>:<peer_port>

        if (argc < 4)
        {
            std::cerr << "Usage: " << argv[0] << " handshake <torrent_file> <peer_ip>:<peer_port>" << std::endl;
            return 1;
        }

        std::string torrent_file = argv[2];
        std::string peer_addr = argv[3];

        // 读取 torrent 文件并计算 info_hash（二进制 20 字节）
        std::string file_content = read_file(torrent_file);
        std::string info_dict = extract_info_dict(file_content);
        std::string info_hash = SHA1::hash(info_dict);

        // 解析 peer 地址
        std::string peer_host;
        int peer_port = 0;
        parse_host_port(peer_addr, peer_host, peer_port);

        // 生成本地 peer_id（二进制 20 字节随机）
        std::string my_peer_id = generate_peer_id_bytes();

        SOCKET sock = INVALID_SOCKET;
        try
        {
            sock = tcp_connect(peer_host, peer_port);

            std::string received_peer_id = perform_handshake(sock, info_hash, my_peer_id);
            std::cout << "Peer ID: " << to_hex(received_peer_id) << std::endl;

            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        catch (...)
        {
            if (sock != INVALID_SOCKET)
            {
                closesocket(sock);
            }
            throw;
        }
    }
    else if (command == "download_piece")
    {
        // ================================================================
        // 处理 "download_piece" 命令 - 下载指定 piece 并写入文件
        // ================================================================
        // 用法:
        //   ./your_program download_piece -o <output_path> <torrent_file> <piece_index>

        if (argc < 6 || std::string(argv[2]) != "-o")
        {
            std::cerr << "Usage: " << argv[0] << " download_piece -o <output_path> <torrent_file> <piece_index>" << std::endl;
            return 1;
        }

        std::string output_path = argv[3];
        std::string torrent_file = argv[4];
        int piece_index = std::stoi(argv[5]);
        if (piece_index < 0)
        {
            throw std::runtime_error("Invalid piece_index");
        }

        // 读取并解析 torrent
        std::string file_content = read_file(torrent_file);
        json torrent = decode_bencoded_value(file_content);

        std::string tracker_url = torrent["announce"].get<std::string>();
        int64_t total_length = torrent["info"]["length"].get<int64_t>();
        int64_t piece_length = torrent["info"]["piece length"].get<int64_t>();
        std::string pieces_blob = torrent["info"]["pieces"].get<std::string>();

        // 计算 info_hash（二进制 20 字节）
        std::string info_dict = extract_info_dict(file_content);
        std::string info_hash = SHA1::hash(info_dict);

        // piece 边界检查 + 计算本 piece 实际长度
        int64_t num_pieces = static_cast<int64_t>(pieces_blob.size() / 20);
        if (piece_index >= num_pieces)
        {
            throw std::runtime_error("piece_index out of range");
        }

        int64_t piece_offset = static_cast<int64_t>(piece_index) * piece_length;
        if (piece_offset >= total_length)
        {
            throw std::runtime_error("piece_index out of file range");
        }

        int64_t piece_size = std::min(piece_length, total_length - piece_offset);
        std::string expected_piece_hash = pieces_blob.substr(static_cast<size_t>(piece_index) * 20, 20);

        // 为 tracker + handshake 统一使用同一个 20 字节 peer_id
        std::string my_peer_id = generate_peer_id();

        // tracker 请求 peers
        std::ostringstream url;
        url << tracker_url;
        url << "?info_hash=" << url_encode(info_hash);
        url << "&peer_id=" << my_peer_id;
        url << "&port=" << 6881;
        url << "&uploaded=" << 0;
        url << "&downloaded=" << 0;
        url << "&left=" << total_length;
        url << "&compact=" << 1;

        std::string tracker_resp_raw = http_get(url.str());
        json tracker_resp = decode_bencoded_value(tracker_resp_raw);

        std::string peers_data = tracker_resp["peers"].get<std::string>();
        std::vector<std::string> peers = parse_peers(peers_data);
        if (peers.empty())
        {
            throw std::runtime_error("No peers returned by tracker");
        }

        // 选择第一个 peer
        std::string peer_host;
        int peer_port = 0;
        parse_host_port(peers[0], peer_host, peer_port);

        SOCKET sock = INVALID_SOCKET;
        try
        {
            sock = tcp_connect(peer_host, peer_port);

            // handshake
            (void)perform_handshake(sock, info_hash, my_peer_id);

            // 1) 收 bitfield (id=5)
            std::string bitfield = recv_bitfield_payload(sock);
            (void)bitfield;

            // 2) 发送 interested (id=2)
            send_peer_message(sock, 2, "");

            // 3) 等 unchoke (id=1)
            wait_for_unchoke(sock);

            // 4) 下载 piece 数据（按 16KiB block 分段请求）
            std::string piece_data = download_piece_from_peer(sock, piece_index, piece_size);


            // 5) 校验 piece hash
            std::string actual_hash = SHA1::hash(piece_data);
            if (actual_hash != expected_piece_hash)
            {
                throw std::runtime_error("Piece hash mismatch");
            }

            // 6) 写入文件
            std::ofstream out(output_path, std::ios::binary);
            if (!out)
            {
                throw std::runtime_error("Failed to open output file: " + output_path);
            }
            out.write(piece_data.data(), static_cast<std::streamsize>(piece_data.size()));
            out.close();

            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        catch (...)
        {
            if (sock != INVALID_SOCKET)
            {
                closesocket(sock);
            }
            throw;
        }
    }
    else if (command == "download")
    {
        // ================================================================
        // 处理 "download" 命令 - 下载整个文件并写入输出路径
        // ================================================================
        // 用法:
        //   ./your_program download -o <output_path> <torrent_file>
        //
        // 示例:
        //   ./your_program download -o /tmp/test.txt sample.torrent
        //
        // 执行流程（并发下载版，work queue + 多 peer worker）：
        //   1) 读取并解析 torrent：拿到 announce(tracker_url)、length(total_length)、piece length(piece_length)、pieces(pieces_blob)
        //   2) 计算 info_hash：对 info 字典原始 bencode 做 SHA1（20 字节二进制）
        //   3) 请求 tracker：GET tracker_url?info_hash=...&peer_id=...&left=...&compact=1
        //   4) 解析 peers：tracker 返回 compact peers（每 6 字节一个 peer），得到 "ip:port" 列表
        //   5) 初始化下载目标：
        //      - 分配 file_data(total_length) 作为整文件缓冲区
        //      - 初始化 PieceWorkQueue：所有 piece 初始为 pending
        //   6) 启动多个 worker（每个 worker 绑定一个 peer 连接，最多 max_workers 个并发）：
        //      - TCP connect 到 peer
        //      - BitTorrent handshake：发送/接收 68 字节握手（包含 info_hash 和 peer_id）
        //      - 等待 bitfield：收到 id=5 的 bitfield 消息，得知该 peer 拥有哪些 pieces
        //      - 发送 interested：id=2
        //      - 等待 unchoke：id=1（若被 choke(id=0) 会继续等到 unchoke）
        //      - 循环领取任务：从 PieceWorkQueue 里找一个该 peer 拥有且尚未下载的 piece_index
        //      - 下载 piece：
        //          * 把 piece 切成 16KiB blocks
        //          * 对每个 block 发送 request(id=6, payload=index+begin+length)
        //          * 收到 piece(id=7, payload=index+begin+block) 后写入 piece_buffer 对应区间
        //      - 校验 piece：对 piece_buffer 做 SHA1，必须等于 pieces_blob 中对应的 20 字节哈希
        //      - 写入共享缓冲区：把 piece_buffer memcpy 到 file_data[piece_offset : piece_offset+piece_size]
        //      - 标记完成：PieceWorkQueue 把该 piece 标记为 done，remaining--
        //   7) 所有 pieces 完成后：把 file_data 一次性写入 -o 指定的输出文件
        //
        // 失败与重试：
        //   - 若某个 worker 下载/校验失败，会把当前 piece 放回队列（retry），并尝试继续领取别的 piece。
        //   - 若 peers 用尽但仍有 remaining piece，则报错 "Download incomplete"。


        if (argc < 5 || std::string(argv[2]) != "-o")
        {
            std::cerr << "Usage: " << argv[0] << " download -o <output_path> <torrent_file>" << std::endl;
            return 1;
        }

        std::string output_path = argv[3];
        std::string torrent_file = argv[4];

        // 读取并解析 torrent
        std::string file_content = read_file(torrent_file);
        json torrent = decode_bencoded_value(file_content);

        std::string tracker_url = torrent["announce"].get<std::string>();
        int64_t total_length = torrent["info"]["length"].get<int64_t>();
        int64_t piece_length = torrent["info"]["piece length"].get<int64_t>();
        std::string pieces_blob = torrent["info"]["pieces"].get<std::string>();

        // 计算 info_hash（二进制 20 字节）
        std::string info_dict = extract_info_dict(file_content);
        std::string info_hash = SHA1::hash(info_dict);

        int64_t num_pieces = static_cast<int64_t>(pieces_blob.size() / 20);
        if (num_pieces <= 0)
        {
            throw std::runtime_error("Invalid pieces field");
        }

        // 为 tracker + handshake 统一使用同一个 20 字节 peer_id
        std::string my_peer_id = generate_peer_id();

        // tracker 请求 peers
        std::ostringstream url;
        url << tracker_url;
        url << "?info_hash=" << url_encode(info_hash);
        url << "&peer_id=" << my_peer_id;
        url << "&port=" << 6881;
        url << "&uploaded=" << 0;
        url << "&downloaded=" << 0;
        url << "&left=" << total_length;
        url << "&compact=" << 1;

        std::string tracker_resp_raw = http_get(url.str());
        json tracker_resp = decode_bencoded_value(tracker_resp_raw);

        std::string peers_data = tracker_resp["peers"].get<std::string>();
        std::vector<std::string> peers = parse_peers(peers_data);
        if (peers.empty())
        {
            throw std::runtime_error("No peers returned by tracker");
        }

        // 为了支持并发写入，把整文件先装到内存缓冲区
        if (total_length < 0)
        {
            throw std::runtime_error("Invalid total length");
        }
        std::vector<char> file_data;
        file_data.resize(static_cast<size_t>(total_length));

        PieceWorkQueue queue(num_pieces);

        // 分批启动 worker：每个 worker 使用一个 peer 连接
        const size_t max_workers = 4;
        size_t next_peer = 0;
        std::string last_error;
        std::mutex err_mu;

        while (queue.remaining.load() > 0 && next_peer < peers.size())
        {
            size_t batch = std::min(max_workers, peers.size() - next_peer);
            std::vector<std::thread> threads;
            threads.reserve(batch);

            for (size_t i = 0; i < batch; i++)
            {
                const std::string peer_addr = peers[next_peer + i];
                threads.emplace_back([&, peer_addr]() {
                    try
                    {
                        download_worker(peer_addr, info_hash, my_peer_id, total_length, piece_length, pieces_blob, &queue, &file_data);
                    }
                    catch (const std::exception& e)
                    {
                        std::lock_guard<std::mutex> lock(err_mu);
                        if (last_error.empty()) last_error = e.what();
                    }
                    catch (...)
                    {
                        std::lock_guard<std::mutex> lock(err_mu);
                        if (last_error.empty()) last_error = "worker failed";
                    }
                });
            }

            for (auto& t : threads)
            {
                t.join();
            }

            next_peer += batch;
        }

        if (queue.remaining.load() > 0)
        {
            throw std::runtime_error(last_error.empty() ? "Download incomplete" : last_error);
        }

        // 所有 pieces 完成后写入文件
        std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            throw std::runtime_error("Failed to open output file: " + output_path);
        }
        out.write(file_data.data(), static_cast<std::streamsize>(file_data.size()));
        if (!out)
        {
            throw std::runtime_error("Failed to write output file");
        }
        out.close();

    }
    else if (command == "magnet_parse")
    {
        // ================================================================
        // 处理 "magnet_parse" 命令 - 解析磁力链接
        // ================================================================
        // 磁力链接格式: magnet:?xt=urn:btih:<info_hash>&dn=<name>&tr=<tracker_url>
        // - xt: info hash (40 字符十六进制)
        // - dn: 文件名 (可选)
        // - tr: tracker URL (URL 编码)
        
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " magnet_parse <magnet_link>" << std::endl;
            return 1;
        }
        
        std::string magnet_link = argv[2];
        std::string info_hash, tracker_url;
        
        // 解析磁力链接
        parse_magnet_link(magnet_link, info_hash, tracker_url);
        
        // 输出结果
        std::cout << "Tracker URL: " << tracker_url << std::endl;
        std::cout << "Info Hash: " << info_hash << std::endl;
    }
    else if (command == "magnet_handshake")
    {
        // ================================================================
        // 处理 "magnet_handshake" 命令 - 磁力链接握手
        // ================================================================
        // 1. 解析磁力链接获取 tracker URL 和 info hash
        // 2. 向 tracker 发送请求获取 peers
        // 3. 与 peer 建立 TCP 连接并进行握手（支持扩展）
        // 4. 输出对方的 peer id
        
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " magnet_handshake <magnet_link>" << std::endl;
            return 1;
        }
        
        std::string magnet_link = argv[2];
        std::string info_hash_hex, tracker_url;
        
        // 解析磁力链接
        parse_magnet_link(magnet_link, info_hash_hex, tracker_url);
        
        // 将十六进制 info hash 转换为 20 字节二进制
        std::string info_hash = from_hex(info_hash_hex);
        
        // 生成 peer_id
        std::string my_peer_id = generate_peer_id();
        
        // 构建 tracker 请求 URL
        // 注意：磁力链接没有 length 信息，使用一个非零值作为 left 参数
        std::ostringstream url;
        url << tracker_url;
        url << "?info_hash=" << url_encode(info_hash);
        url << "&peer_id=" << my_peer_id;
        url << "&port=" << 6881;
        url << "&uploaded=" << 0;
        url << "&downloaded=" << 0;
        url << "&left=" << 999;  // 必须大于 0 才能获取 peers
        url << "&compact=" << 1;
        
        // 发送 tracker 请求
        std::string response = http_get(url.str());
        json tracker_response = decode_bencoded_value(response);
        
        // 解析 peers
        std::string peers_data = tracker_response["peers"].get<std::string>();
        std::vector<std::string> peers = parse_peers(peers_data);
        
        if (peers.empty())
        {
            throw std::runtime_error("No peers found");
        }
        
        // 连接到第一个 peer
        std::string peer_addr = peers[0];
        std::string peer_host;
        int peer_port;
        parse_host_port(peer_addr, peer_host, peer_port);
        
        // 建立 TCP 连接
        SOCKET sock = tcp_connect(peer_host, peer_port);
        
        // 执行握手（支持扩展协议）
        bool peer_supports_extensions = false;
        std::string received_peer_id = perform_handshake(sock, info_hash, my_peer_id, true, &peer_supports_extensions);
        
        // 接收 bitfield 消息
        (void)recv_bitfield_payload(sock);
        
        // 如果对方支持扩展，发送扩展握手
        if (peer_supports_extensions)
        {
            send_extension_handshake(sock);
            
            // 接收对方的扩展握手消息
            json peer_ext_handshake = recv_extension_handshake(sock);
            
            // 提取对方的 ut_metadata ID
            int peer_metadata_id = peer_ext_handshake["m"]["ut_metadata"].get<int>();
            
            // 输出对方的 peer id 和 metadata extension ID
            std::cout << "Peer ID: " << to_hex(received_peer_id) << std::endl;
            std::cout << "Peer Metadata Extension ID: " << peer_metadata_id << std::endl;
        }
        
        closesocket(sock);
    }
    else if (command == "magnet_info")
    {
        // ================================================================
        // 处理 "magnet_info" 命令 - 从磁力链接获取 torrent 元数据
        // ================================================================
        // 1. 解析磁力链接获取 tracker URL 和 info hash
        // 2. 向 tracker 发送请求获取 peers
        // 3. 与 peer 建立连接并完成握手
        // 4. 发送/接收扩展握手
        // 5. 发送元数据请求
        // 6. 接收元数据数据消息并解析
        // 7. 验证 info hash 并输出 torrent 信息
        
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " magnet_info <magnet_link>" << std::endl;
            return 1;
        }
        
        std::string magnet_link = argv[2];
        std::string info_hash_hex, tracker_url;
        
        // 解析磁力链接
        parse_magnet_link(magnet_link, info_hash_hex, tracker_url);
        
        // 将十六进制 info hash 转换为 20 字节二进制
        std::string info_hash = from_hex(info_hash_hex);
        
        // 生成 peer_id
        std::string my_peer_id = generate_peer_id();
        
        // 构建 tracker 请求 URL
        std::ostringstream url;
        url << tracker_url;
        url << "?info_hash=" << url_encode(info_hash);
        url << "&peer_id=" << my_peer_id;
        url << "&port=" << 6881;
        url << "&uploaded=" << 0;
        url << "&downloaded=" << 0;
        url << "&left=" << 999;
        url << "&compact=" << 1;
        
        // 发送 tracker 请求
        std::string response = http_get(url.str());
        json tracker_response = decode_bencoded_value(response);
        
        // 解析 peers
        std::string peers_data = tracker_response["peers"].get<std::string>();
        std::vector<std::string> peers = parse_peers(peers_data);
        
        if (peers.empty())
        {
            throw std::runtime_error("No peers found");
        }
        
        // 连接到第一个 peer
        std::string peer_addr = peers[0];
        std::string peer_host;
        int peer_port;
        parse_host_port(peer_addr, peer_host, peer_port);
        
        // 建立 TCP 连接
        SOCKET sock = tcp_connect(peer_host, peer_port);
        
        // 执行基础握手（支持扩展协议）
        bool peer_supports_extensions = false;
        (void)perform_handshake(sock, info_hash, my_peer_id, true, &peer_supports_extensions);
        
        // 接收 bitfield 消息
        (void)recv_bitfield_payload(sock);
        
        if (!peer_supports_extensions)
        {
            closesocket(sock);
            throw std::runtime_error("Peer does not support extensions");
        }
        
        // 发送扩展握手
        send_extension_handshake(sock);
        
        // 接收对方的扩展握手
        json peer_ext_handshake = recv_extension_handshake(sock);
        int peer_metadata_id = peer_ext_handshake["m"]["ut_metadata"].get<int>();
        
        // 发送元数据请求 (msg_type=0, piece=0)
        send_metadata_request(sock, peer_metadata_id, 0);
        
        // 接收元数据数据消息
        std::string metadata = recv_metadata_data(sock);
        
        closesocket(sock);
        
        // 验证 info hash
        std::string computed_hash = SHA1::hash(metadata);
        if (computed_hash != info_hash)
        {
            throw std::runtime_error("Metadata hash mismatch");
        }
        
        // 解析 metadata（这是 info 字典的 bencode 编码）
        json info = decode_bencoded_value(metadata);
        
        // 输出 torrent 信息
        std::cout << "Tracker URL: " << tracker_url << std::endl;
        std::cout << "Length: " << info["length"].get<int64_t>() << std::endl;
        std::cout << "Info Hash: " << info_hash_hex << std::endl;
        std::cout << "Piece Length: " << info["piece length"].get<int64_t>() << std::endl;
        std::cout << "Piece Hashes:" << std::endl;
        
        // 输出每个 piece 的哈希值
        std::string pieces = info["pieces"].get<std::string>();
        for (size_t i = 0; i < pieces.size(); i += 20)
        {
            std::string piece_hash = pieces.substr(i, 20);
            std::cout << to_hex(piece_hash) << std::endl;
        }
    } 
    else 
    {
        // 未知命令，输出错误信息
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;  // 程序正常退出
}
