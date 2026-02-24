#ifndef CAM_LOG_H
#define CAM_LOG_H

#include <iostream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <cstring>

#define CAM_LOG(level) CAM_LOG_##level

namespace Cam {
constexpr char CAM_LOG_LEVEL[] = "CAM_LOG_LEVEL";

struct LogLevel {
    static constexpr int TRACE = 0;
    static constexpr int DEBUG = 1;
    static constexpr int INFO = 2;
    static constexpr int WARN = 3;
    static constexpr int ERROR = 4;
};

// 定义一个辅助类，用于输出日志并在析构时自动添加换行
class Log {
public:
    Log()
    {}

    ~Log()
    {
        // 当对象析构时，输出整个缓存的内容，并添加换行
        std::cout << stream.str() << std::endl;
    }

    // 重载 << 操作符，用于接收日志内容
    template <typename T>
    Log &operator<<(const T &msg)
    {
        stream << msg;
        return *this;
    }
    static int GetLogLevel()
    {
        static int level = -1;
        if (level == -1) {
            const char *env_val = std::getenv(CAM_LOG_LEVEL);

            if (env_val == nullptr) {
                level = LogLevel::INFO;
            } else {
                std::string log_level_str = env_val;

                // Compare and convert to corresponding log level
                if (log_level_str == "TRACE") {
                    level = LogLevel::TRACE;
                } else if (log_level_str == "DEBUG") {
                    level = LogLevel::DEBUG;
                } else if (log_level_str == "INFO") {
                    level = LogLevel::INFO;
                } else if (log_level_str == "WARN") {
                    level = LogLevel::WARN;
                } else if (log_level_str == "ERROR") {
                    level = LogLevel::ERROR;
                }
            }
        }
        return level;
    }
    // Function to extract the filename from a path
    static const char *ExtractFileName(const char *path)
    {
        // Find the last '/' or '\\' in the path
        const char *file = strrchr(path, '/');
        if (!file) {
            file = strrchr(path, '\\');
        }
        // If no '/' or '\\' was found, return the original path
        return file ? file + 1 : path;
    }

private:
    std::ostringstream stream;
};

#define CAM_LOG_TRACE                                    \
    if (Cam::LogLevel::TRACE >= Cam::Log::GetLogLevel()) \
    Cam::Log() << "\033[36mTRACE \033[0m" << Cam::Log::ExtractFileName(__FILE__) << ":" << __LINE__ << " "
#define CAM_LOG_DEBUG                                    \
    if (Cam::LogLevel::DEBUG >= Cam::Log::GetLogLevel()) \
    Cam::Log() << "\033[32mDEBUG \033[0m" << Cam::Log::ExtractFileName(__FILE__) << ":" << __LINE__ << " "
#define CAM_LOG_INFO                                    \
    if (Cam::LogLevel::INFO >= Cam::Log::GetLogLevel()) \
    Cam::Log() << "\033[37mINFO \033[0m" << Cam::Log::ExtractFileName(__FILE__) << ":" << __LINE__ << " "
#define CAM_LOG_WARN                                    \
    if (Cam::LogLevel::WARN >= Cam::Log::GetLogLevel()) \
    Cam::Log() << "\033[33mWARN \033[0m" << Cam::Log::ExtractFileName(__FILE__) << ":" << __LINE__ << " "
#define CAM_LOG_ERROR                                    \
    if (Cam::LogLevel::ERROR >= Cam::Log::GetLogLevel()) \
    Cam::Log() << "\033[31mERROR \033[0m" << __FILE__ << ":" << __LINE__ << " "
}
#endif