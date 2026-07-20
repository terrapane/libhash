add_executable(test_sha256 test_sha256.cpp)

target_link_libraries(test_sha256 Terra::libhash Terra::bitutil Terra::stf)

# Specify the C++ standard to observe
set_target_properties(test_sha256
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)

# Use the following compile options
target_compile_options(test_sha256
    PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wpedantic -Wextra -Wall -Werror -Wconversion -Wshadow>
        $<$<CXX_COMPILER_ID:GNU>:-Wpedantic -Wextra -Wall -Werror -Wconversion -Wshadow=local>
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>)

add_test(NAME test_sha256
         COMMAND test_sha256)
