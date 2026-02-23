FROM itsafeaturemythic/mythic_python_base:latest

# Install C build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    mingw-w64 \
    nasm \
    make \
    cmake \
    git \
    openjdk-11-jdk && \
    # Switch MinGW to posix threading model (required for std::mutex in libdatachannel)
    update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix && \
    update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix

RUN python3 -m pip install toml donut-shellcode brotli

# Cross-compile libdatachannel (data-channels-only) for MinGW-w64
# This builds: libdatachannel-static.a, libjuice-static.a, libusrsctp-static.a
# Also cross-compiles OpenSSL for MinGW target

# Step 1: Cross-compile OpenSSL
RUN cd /opt && \
    git clone --depth 1 --branch openssl-3.2.0 https://github.com/openssl/openssl.git openssl-src && \
    cd /opt/openssl-src && \
    ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/opt/openssl-mingw64 --libdir=lib no-shared no-tests no-docs && \
    make -j$(nproc) && \
    make install_sw && \
    rm -rf /opt/openssl-src

# Step 2: Create MinGW CMake toolchain file
# Include /opt/openssl-mingw64 in CMAKE_FIND_ROOT_PATH so CMake can find OpenSSL
RUN printf '%s\n' \
    'set(CMAKE_SYSTEM_NAME Windows)' \
    'set(CMAKE_SYSTEM_PROCESSOR x86_64)' \
    'set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)' \
    'set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)' \
    'set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)' \
    'set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32 /opt/openssl-mingw64)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' \
    > /opt/mingw-toolchain.cmake

# Step 3: Cross-compile libdatachannel (data channels only, no media/websocket)
RUN cd /opt && \
    git clone --depth 1 --branch v0.23.2 --recurse-submodules https://github.com/paullouisageneau/libdatachannel.git libdatachannel-src && \
    cd /opt/libdatachannel-src && \
    cmake -B build \
        -DCMAKE_TOOLCHAIN_FILE=/opt/mingw-toolchain.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DNO_MEDIA=ON \
        -DNO_WEBSOCKET=ON \
        -DNO_TESTS=ON \
        -DNO_EXAMPLES=ON \
        -DUSE_GNUTLS=OFF \
        -DOPENSSL_ROOT_DIR=/opt/openssl-mingw64 \
        -DOPENSSL_INCLUDE_DIR=/opt/openssl-mingw64/include \
        -DOPENSSL_CRYPTO_LIBRARY=/opt/openssl-mingw64/lib/libcrypto.a \
        -DOPENSSL_SSL_LIBRARY=/opt/openssl-mingw64/lib/libssl.a \
        -DCMAKE_INSTALL_PREFIX=/opt/libdatachannel \
        -DBUILD_SHARED_LIBS=OFF && \
    cmake --build build -j$(nproc) && \
    cmake --install build && \
    cp /opt/libdatachannel-src/build/deps/libjuice/libjuice-static.a /opt/libdatachannel/lib/ && \
    cp /opt/libdatachannel-src/build/deps/usrsctp/usrsctplib/libusrsctp-static.a /opt/libdatachannel/lib/ && \
    rm -rf /opt/libdatachannel-src

WORKDIR /Mythic/

CMD ["python3", "main.py"]
