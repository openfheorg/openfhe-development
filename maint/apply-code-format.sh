find ./ -type f -and \( -name '*.cpp' -or -name '*.c' -or -name '*.h' \) | xargs clang-format -i --assume-filename=.clang-format
