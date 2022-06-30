
cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 17)
project(FastPIR VERSION 1.0 LANGUAGES CXX)
include_directories("/root/ljy/SEAL3.7.2/seallib/include/SEAL-3.7")             #include directory
include_directories("/root/ljy/SEAL3.7.2/seallib/include")
link_directories(/root/ljy/SEAL3.7.2/seallib/lib)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

set(CXX_FLAGS -fPIE)

add_executable(fastpir main.cpp server.cpp client.cpp fastpirparams.cpp)

# Import Microsoft SEAL
#find_package(SEAL 3.7 REQUIRED)


# Link Microsoft SEAL
target_link_libraries(fastpir seal pthread muduo_base muduo_net)

#add_executable(test_evaluate test_evaluate.cpp mserver.cpp mclient.cpp mfastpirparams.cpp)
#target_link_libraries(test_evaluate seal pthread)

add_executable(multi_query_test multi_query.cpp  mserver.cpp mclient.cpp mfastpirparams.cpp)
target_link_libraries(multi_query_test seal pthread)

add_executable(tcp_query_server tcp_query/tcp_query_server.cpp mserver.cpp mfastpirparams.cpp)
target_link_libraries(tcp_query_server muduo_net muduo_base seal pthread)

add_executable(tcp_query_client tcp_query/tcp_query_client.cpp mclient.cpp mfastpirparams.cpp)
target_link_libraries(tcp_query_client muduo_base muduo_net seal pthread)