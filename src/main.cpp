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

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

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
    } 
    else 
    {
        // 未知命令，输出错误信息
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;  // 程序正常退出
}
