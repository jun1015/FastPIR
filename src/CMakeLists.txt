
cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)
project(FastPIR VERSION 1.0 LANGUAGES CXX)
include_directories("/root/ljy/SEAL3.7.2/seallib/include/SEAL-3.7")
link_directories(/root/ljy/SEAL3.7.2/seallib/lib)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)


add_executable(fastpir main.cpp server.cpp client.cpp fastpirparams.cpp)

# Import Microsoft SEAL
#find_package(SEAL 3.7 REQUIRED)


# Link Microsoft SEAL
target_link_libraries(fastpir seal pthread)

add_executable(test_evaluate test_evaluate.cpp mserver.cpp mclient.cpp mfastpirparams.cpp)
target_link_libraries(test_evaluate seal pthread)

#add_executable(mtest mtest.cpp  mserver.cpp mclient.cpp mfastpirparams.cpp)
#target_link_libraries(mtest seal pthread)

add_executable(multi_query_test multi_query.cpp  mserver.cpp mclient.cpp mfastpirparams.cpp)
target_link_libraries(multi_query_test seal pthread)