#!/bin/sh
# This script runs the valgrind program on honeybrid, to check any lost or leaked memory

G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind -v --tool=memcheck --leak-check=full --leak-resolution=high --num-callers=20 --time-stamp=yes --trace-children=yes --track-origins=yes "$@"

exit
