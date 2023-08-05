# To setup a test to check for branches or memory accesses depending on secret data,
# using valgrind.

with_valgrind () {
    type valgrind >/dev/null || exit 77
    NETTLE_TEST_SIDE_CHANNEL=1 valgrind -q --error-exitcode=1 "$@"
}
