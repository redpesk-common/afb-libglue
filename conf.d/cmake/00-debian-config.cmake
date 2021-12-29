message(STATUS "Custom options: 00-debian-config.cmake --")
list(APPEND PKG_REQUIRED_LIST uthash)

# Libshell is not part of standard Linux Distro (https://libshell.org/)
set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/local/lib64/pkgconfig")
