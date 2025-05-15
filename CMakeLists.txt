cmake_minimum_required(VERSION 3.16)
project(DistributedGUI)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wformat-nonliteral -Wcast-align -Wpointer-arith -Wmissing-declarations -Winline -Wundef -Wcast-qual -Wshadow -Wwrite-strings -Wno-unused-parameter -Wfloat-equal -pedantic -fsanitize=undefined -fsanitize=address -fsanitize=leak")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

FetchContent_Declare(
    seal
    GIT_REPOSITORY https://github.com/Microsoft/SEAL.git
    GIT_TAG main  
)

FetchContent_MakeAvailable(seal)

FetchContent_Declare(
    Matrix
    GIT_REPOSITORY https://github.com/SasZombie/Matrix.git
    GIT_TAG main  
)

FetchContent_MakeAvailable(Matrix)

find_package(Qt5 REQUIRED COMPONENTS Widgets)

add_executable(DistributedGUI main.cpp operations.cpp)

target_include_directories(DistributedGUI PRIVATE
    ${matrix_SOURCE_DIR}
)

target_link_libraries(DistributedGUI Qt5::Widgets SEAL::seal)