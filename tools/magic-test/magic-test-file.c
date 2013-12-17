/*
 * This file is part of the VMI-Honeymon project.
 *
 * 2012-2013 University of Connecticut (http://www.uconn.edu)
 * Tamas K Lengyel <tamas.k.lengyel@gmail.com>
 *
 * VMI-Honeymon is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#ifdef HAVE_MAGIC
#include <magic.h>
#endif

int main(int argc, char **argv)
{
#ifdef HAVE_MAGIC
    if(argc<=1) return 1;
    FILE *file;
    if(NULL == (file = fopen(argv[1], "r"))) {
	printf("File doesn't exist!\n");
	return 1;
	}

    fclose(file);
    printf("Checking file %s\n", argv[1]);



    char *actual_file = argv[1];
    const char *magic_full;
    magic_t magic_cookie;
    /*MAGIC_MIME tells magic to return a mime of the file, but you can specify different things*/
    magic_cookie = magic_open(MAGIC_MIME);
        if (magic_cookie == NULL) {
            printf("Unable to initialize magic library\n");
            return 1;
            }
        printf("Loading default magic database\n");
        if (magic_load(magic_cookie, NULL) != 0) {
            printf("Cannot load magic database - %s\n", magic_error(magic_cookie));
            magic_close(magic_cookie);
            return 1;
        }
    magic_full = magic_file(magic_cookie, actual_file);
    printf("%s\n", magic_full);
    magic_close(magic_cookie);
#endif
    return 0;
}
