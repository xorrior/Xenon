FROM itsafeaturemythic/mythic_python_base:latest

# Install C build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    mingw-w64 \
    nasm \
    make \
    cmake \
    git \
    openjdk-11-jdk \
    meson \
    ninja-build \
    zstd \
    pkg-config && \
    # Switch MinGW to posix threading model (required for std::mutex in libdatachannel)
    update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix && \
    update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix

RUN python3 -m pip install toml donut-shellcode brotli

# ===========================================================================
# Cross-compile WebRTC dependencies for MinGW-w64 (TURN TCP requires libnice)
# ===========================================================================

# Step 1: Cross-compile OpenSSL
RUN cd /opt && \
    git clone --depth 1 --branch openssl-3.2.0 https://github.com/openssl/openssl.git openssl-src && \
    cd /opt/openssl-src && \
    ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/opt/openssl-mingw64 --libdir=lib no-shared no-tests no-docs && \
    make -j$(nproc) && \
    make install_sw && \
    rm -rf /opt/openssl-src

# Step 2: Download MSYS2 pre-built packages for glib2 + dependencies
# These provide static libraries (.a) and headers for mingw-w64 cross-compilation.
# We need glib2 for libnice; TURN TCP/TLS support requires libnice (libjuice doesn't support it).
ENV MSYS2_PREFIX=/opt/msys2-mingw64
RUN mkdir -p ${MSYS2_PREFIX} /tmp/msys2-pkgs && \
    cd /tmp/msys2-pkgs && \
    # glib2 and its dependencies
    curl -LO https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-glib2-2.82.4-1-any.pkg.tar.zst && \
    curl -LO https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-gettext-runtime-0.22.5-2-any.pkg.tar.zst && \
    curl -LO https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-libffi-3.4.6-1-any.pkg.tar.zst && \
    curl -LO https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-pcre2-10.44-2-any.pkg.tar.zst && \
    curl -LO https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-zlib-1.3.1-1-any.pkg.tar.zst && \
    curl -LO https://mirror.msys2.org/mingw/mingw64/mingw-w64-x86_64-libiconv-1.17-4-any.pkg.tar.zst && \
    # Extract all packages (files are rooted at mingw64/)
    for pkg in *.pkg.tar.zst; do \
        zstdcat "$pkg" | tar xf - -C ${MSYS2_PREFIX} --strip-components=1 2>/dev/null || true; \
    done && \
    # Fix pkg-config prefix from /mingw64 to actual install path
    sed -i "s|prefix=/mingw64|prefix=${MSYS2_PREFIX}|g" ${MSYS2_PREFIX}/lib/pkgconfig/*.pc && \
    ls -la ${MSYS2_PREFIX}/lib/pkgconfig/ && \
    rm -rf /tmp/msys2-pkgs

# Step 3: Create meson cross file for mingw-w64
RUN printf '%s\n' \
    '[binaries]' \
    "c = 'x86_64-w64-mingw32-gcc'" \
    "cpp = 'x86_64-w64-mingw32-g++'" \
    "ar = 'x86_64-w64-mingw32-ar'" \
    "strip = 'x86_64-w64-mingw32-strip'" \
    "windres = 'x86_64-w64-mingw32-windres'" \
    "pkgconfig = 'pkg-config'" \
    '' \
    '[properties]' \
    "pkg_config_libdir = ['${MSYS2_PREFIX}/lib/pkgconfig', '/opt/openssl-mingw64/lib/pkgconfig']" \
    '' \
    '[host_machine]' \
    "system = 'windows'" \
    "cpu_family = 'x86_64'" \
    "cpu = 'x86_64'" \
    "endian = 'little'" \
    > /opt/mingw-cross.ini

# Step 4: Cross-compile libnice from source (with OpenSSL, no gnutls)
RUN cd /opt && \
    git clone --depth 1 --branch 0.1.22 https://gitlab.freedesktop.org/libnice/libnice.git libnice-src && \
    cd /opt/libnice-src && \
    PKG_CONFIG_LIBDIR="${MSYS2_PREFIX}/lib/pkgconfig:/opt/openssl-mingw64/lib/pkgconfig" \
    meson setup build --cross-file=/opt/mingw-cross.ini \
        --prefix=/opt/libnice-mingw64 \
        --default-library=static \
        -Dcrypto-library=openssl \
        -Dgstreamer=disabled \
        -Dintrospection=disabled \
        -Dexamples=disabled \
        -Dtests=disabled && \
    ninja -C build -j$(nproc) && \
    ninja -C build install && \
    ls -la /opt/libnice-mingw64/lib/ && \
    rm -rf /opt/libnice-src

# Step 5: Create CMake toolchain file for libdatachannel
# Include all cross-compiled prefixes in CMAKE_FIND_ROOT_PATH
RUN printf '%s\n' \
    'set(CMAKE_SYSTEM_NAME Windows)' \
    'set(CMAKE_SYSTEM_PROCESSOR x86_64)' \
    'set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)' \
    'set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)' \
    'set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)' \
    'set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32 /opt/openssl-mingw64 /opt/libnice-mingw64 '"${MSYS2_PREFIX}"')' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)' \
    'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)' \
    > /opt/mingw-toolchain.cmake

# Step 6: Cross-compile libdatachannel with libnice backend (TURN TCP support)
RUN cd /opt && \
    git clone --depth 1 --branch v0.23.2 --recurse-submodules https://github.com/paullouisageneau/libdatachannel.git libdatachannel-src && \
    cd /opt/libdatachannel-src && \
    PKG_CONFIG_LIBDIR="${MSYS2_PREFIX}/lib/pkgconfig:/opt/openssl-mingw64/lib/pkgconfig:/opt/libnice-mingw64/lib/pkgconfig" \
    cmake -B build \
        -DCMAKE_TOOLCHAIN_FILE=/opt/mingw-toolchain.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DNO_MEDIA=ON \
        -DNO_WEBSOCKET=ON \
        -DNO_TESTS=ON \
        -DNO_EXAMPLES=ON \
        -DUSE_NICE=ON \
        -DUSE_GNUTLS=OFF \
        -DOPENSSL_ROOT_DIR=/opt/openssl-mingw64 \
        -DOPENSSL_INCLUDE_DIR=/opt/openssl-mingw64/include \
        -DOPENSSL_CRYPTO_LIBRARY=/opt/openssl-mingw64/lib/libcrypto.a \
        -DOPENSSL_SSL_LIBRARY=/opt/openssl-mingw64/lib/libssl.a \
        -DCMAKE_INSTALL_PREFIX=/opt/libdatachannel \
        -DBUILD_SHARED_LIBS=OFF && \
    cmake --build build -j$(nproc) && \
    cmake --install build && \
    find /opt/libdatachannel-src/build -name 'libusrsctp*.a' -exec cp {} /opt/libdatachannel/lib/ \; && \
    ls -la /opt/libdatachannel/lib/ && \
    rm -rf /opt/libdatachannel-src

WORKDIR /Mythic/

CMD ["python3", "main.py"]
