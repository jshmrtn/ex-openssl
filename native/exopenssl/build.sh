#!/bin/bash
set -e
PS4=':$LINENO+'

cd "`dirname $0`"

CRATE_NAME="exopenssl"
RUST_RELEASE="false"
TARGET_DIR="../../priv/native/"

LINK_STATIC_LIBS="-lSystem -lresolv -lc -lm"

WORK_DIR=`mktemp -d`
ERLANG_PATH=`erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell`

if $RUST_RELEASE
then
    FLAVOR_FLAGS="--release"
    FLAVOR_NAME="release"
else
    FLAVOR_FLAGS=""
    FLAVOR_NAME="debug"
fi

if [[ "$OSTYPE" == "darwin"* ]]
then
  export OPENSSL_LIB_DIR="$OPENSSL_DIR/lib"
  export OPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include"
  export OPENSSL_STATIC="yes"
fi

cat <<EOF > $WORK_DIR/wrapper.c
void* rustler_nif_init();
void* nif_init() {
    return rustler_nif_init();
}
EOF

cargo clean
cargo rustc $FLAVOR_FLAGS --features "rustler/alternative_nif_init_name alternative_nif_init_name" -- --print=native-static-libs --crate-type staticlib


cp "target/${FLAVOR_NAME}/lib${CRATE_NAME}.a" "$WORK_DIR/lib${CRATE_NAME}.so"

OLD_DIR=`pwd`
cd $WORK_DIR

gcc -c wrapper.c -I"$ERLANG_PATH" -fdata-sections -ffunction-sections
gcc -undefined dynamic_lookup -dynamiclib -o "lib${CRATE_NAME}.so" wrapper.o -L "." -l$CRATE_NAME $LINK_STATIC_LIBS
cp "lib${CRATE_NAME}.so" "$OLD_DIR/lib${CRATE_NAME}.so"

cd "$OLD_DIR"
cp "${WORK_DIR}/lib${CRATE_NAME}.so" "${TARGET_DIR}"
