cmake_minimum_required(VERSION 3.10)
project(sandbox VERSION 2.5.0)

set(CMAKE_CXX_STANDARD 17)

add_executable(sandbox main.cpp)
target_compile_definitions(sandbox PRIVATE SANDBOX_VERSION="${PROJECT_VERSION}")

target_link_libraries(sandbox cgroup)

install(TARGETS sandbox
        RUNTIME DESTINATION bin
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID
)