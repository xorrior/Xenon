FROM itsafeaturemythic/mythic_python_base:latest

# Install C build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    mingw-w64 \
    nasm \
    make \
    cmake \
    git \
    openjdk-11-jdk

RUN python3 -m pip install toml donut-shellcode brotli

# Cross-compile libdatachannel (data-channels-only) for MinGW-w64
# This builds: libdatachannel-static.a, libjuice-static.a, libusrsctp-static.a
# Also cross-compiles OpenSSL for MinGW target
RUN mkdir -p /opt/libdatachannel/build && \
    cd /opt && \
    git clone --depth 1 --branch v0.23.2 --recurse-submodules https://github.com/paullouisageneau/libdatachannel.git libdatachannel-src && \
    cd /opt/libdatachannel-src && \
    # Create MinGW toolchain file \
    echo 'set(CMAKE_SYSTEM_NAME Windows)' > /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_SYSTEM_PROCESSOR x86_64)' >> /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)' >> /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)' >> /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)' >> /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)' >> /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' >> /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' >> /opt/mingw-toolchain.cmake && \
    echo 'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' >> /opt/mingw-toolchain.cmake && \
    # Cross-compile OpenSSL first \
    cd /opt && \
    git clone --depth 1 --branch openssl-3.2.0 https://github.com/openssl/openssl.git openssl-src && \
    cd /opt/openssl-src && \
    ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/opt/libdatachannel no-shared no-tests no-docs && \
    make -j$(nproc) && \
    make install_sw && \
    # Build libdatachannel with data channels only (no media) \
    cd /opt/libdatachannel-src && \
    cmake -B build \
        -DCMAKE_TOOLCHAIN_FILE=/opt/mingw-toolchain.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DNO_MEDIA=ON \
        -DNO_WEBSOCKET=ON \
        -DUSE_GNUTLS=OFF \
        -DOPENSSL_ROOT_DIR=/opt/libdatachannel \
        -DCMAKE_INSTALL_PREFIX=/opt/libdatachannel \
        -DBUILD_SHARED_LIBS=OFF && \
    cmake --build build -j$(nproc) && \
    cmake --install build && \
    # Cleanup source to save space \
    rm -rf /opt/libdatachannel-src /opt/openssl-src

WORKDIR /Mythic/

CMD ["python3", "main.py"]
