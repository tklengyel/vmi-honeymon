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
