# Задать минимальную версию CMake:
cmake_minimum_required(VERSION 3.0)

# Указать характеристики проекта:
project(mdns VERSION 1.0.0 LANGUAGES C++)

# Добавить в сборку исполняемый файл "MyProgram":
add_executable(mdns StartProgram.c)

# Установить исполняемый файл "MyProgram" в директорию "bin":
install(TARGETS MyProgram DESTINATION bin)
