#!/bin/sh
# This file is part of the VMI-Honeymon project.
#
# 2012-2013 University of Connecticut (http://www.uconn.edu)
# Tamas K Lengyel (tamas.k.lengyel@gmail.com)
#
#  VMI-Honeymon is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, see <http://www.gnu.org/licenses/>.

# This script runs the valgrind program on honeybrid, to check any lost or leaked memory

G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind -v --tool=memcheck --leak-check=full --leak-resolution=high --gen-suppressions=yes --suppressions=/share/work/vmi-honeymon/scripts/valgrind.supp --num-callers=20 --time-stamp=yes --trace-children=yes --track-origins=yes "$@"

exit
