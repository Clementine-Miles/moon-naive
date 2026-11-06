# Source this file. Local dependencies are outside the checkout.
export ACME_LAB_HOME=${ACME_LAB_HOME:-/workspace/.moon-naive-acme-lab}
export PEBBLE_SOURCE=$ACME_LAB_HOME/tools/pebble-src
export PEBBLE_BIN=$ACME_LAB_HOME/tools/bin/pebble
export CHALLTESTSRV_BIN=$ACME_LAB_HOME/tools/bin/pebble-challtestsrv
export ACME_LAB_TCPDUMP=$ACME_LAB_HOME/apt/prefix/usr/bin/tcpdump
export ACME_LAB_TSHARK=$ACME_LAB_HOME/apt/prefix/usr/bin/tshark
export LD_LIBRARY_PATH=$ACME_LAB_HOME/apt/prefix/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export WIRESHARK_DATA_DIR=$ACME_LAB_HOME/apt/prefix/usr/share/wireshark
