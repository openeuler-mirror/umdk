#ifndef CAM_ENV_H
#define CAM_ENV_H

#include <cstdlib>

namespace Cam {
inline const char *GetEnv(const char *name)
{
    const char *env = std::getenv(name);
    return env;
}
}

#endif