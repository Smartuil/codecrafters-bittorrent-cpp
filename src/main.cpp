/**
 * @file main.cpp
 * @brief BitTorrent 客户端 - Bencode 解码器实现
 * 
 * 本文件实现了 BitTorrent 协议中使用的 Bencode 编码格式的解码功能。
 * Bencode 是 BitTorrent 协议用于编码 .torrent 文件和 tracker 通信的数据格式。
 */

#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * @brief 解码 Bencode 编码的值
 * 
 * Bencode 支持四种数据类型：
 * 1. 字符串 (Strings): 格式为 "<长度>:<内容>"，例如 "5:hello" 表示字符串 "hello"
 * 2. 整数 (Integers): 格式为 "i<数字>e"，例如 "i52e" 表示整数 52（待实现）
 * 3. 列表 (Lists): 格式为 "l<元素>e"，例如 "l5:helloi52ee"（待实现）
 * 4. 字典 (Dictionaries): 格式为 "d<键值对>e"（待实现）
 * 
 * @param encoded_value Bencode 编码的字符串
 * @return json 解码后的 JSON 对象
 * @throws std::runtime_error 当遇到无效或不支持的编码格式时抛出异常
 */
json decode_bencoded_value(const std::string& encoded_value) 
{
    // 检查第一个字符是否为数字，判断是否为字符串类型
    // Bencode 字符串以长度数字开头
    if (std::isdigit(encoded_value[0])) 
    {
        // 解码 Bencode 字符串
        // 格式: "<长度>:<字符串内容>"
        // 示例: "5:hello" -> "hello"
        //       "10:helloworld" -> "helloworld"
        
        // 查找冒号分隔符的位置
        size_t colon_index = encoded_value.find(':');
        
        if (colon_index != std::string::npos) 
        {
            // 提取长度部分（冒号之前的数字字符串）
            std::string number_string = encoded_value.substr(0, colon_index);
            
            // 将长度字符串转换为 64 位整数
            // 使用 atoll 处理可能的大数值
            int64_t number = std::atoll(number_string.c_str());
            
            // 提取实际字符串内容（从冒号后开始，长度为 number）
            std::string str = encoded_value.substr(colon_index + 1, number);
            
            // 将字符串包装为 JSON 对象并返回
            return json(str);
        } 
        else 
        {
            // 字符串格式错误：缺少冒号分隔符
            throw std::runtime_error("Invalid encoded value: " + encoded_value);
        }
    } 
    else 
    {
        // 当前仅支持字符串类型
        // TODO: 添加对整数 (i...e)、列表 (l...e)、字典 (d...e) 的支持
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

/**
 * @brief 程序主入口
 * 
 * 命令行用法:
 *   ./your_program decode <encoded_value>
 * 
 * 示例:
 *   ./your_program decode "5:hello"    -> 输出: "hello"
 *   ./your_program decode "10:hello12345" -> 输出: "hello12345"
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
    else 
    {
        // 未知命令，输出错误信息
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;  // 程序正常退出
}
