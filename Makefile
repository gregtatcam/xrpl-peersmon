BASE=${HOME}/Documents/Projects
RIPPLED=${BASE}/rippled
BOOST=${BASE}/boost_1_70_0
BOOST_ROOT={BOOST}
SECP256K1=${RIPPLE}/src/secp256k1
DATE=${BASE}/date/include
LZ4=${BASE}/lz4/lib
FLAGS=--std=c++17 -I./ -I${RIPPLED}/src -I${RIPPLED}/src/ripple -I${BOOST} -I${DATE} -I${SECP256K1} \
	-I${LZ4} -L${RIPPLED}/build -L/${BOOST}/stage/lib -L${LZ4}
SRC=peersmon.cpp ripple.pb.cc Overlay.cpp Peer.cpp make_SSLContext.cpp Message.cpp
HDR=libbase58.h xd.h
HDR=
RIPPLE_LIBS=-lxrpl_core -led25519-donna -lsecp256k1
BOOST_LIBS=-lboost_chrono -lboost_container -lboost_context -lboost_coroutine -lboost_date_time \
	-lboost_filesystem -lboost_program_options -lboost_regex -lboost_system -lboost_thread -lpthread
LIBS=-lsecp256k1 -lsodium -lssl -lcrypto -lprotobuf -fpermissive -llz4

peermon: ${SRC} ${HDR}
	g++ -g -o peersmon ${FLAGS} ${SRC} ${LIBS} ${RIPPLE_LIBS} ${BOOST_LIBS} -Bstatic

ripple.pb.cc:
	protoc --cpp_out=. ripple.proto
