#!/usr/bin/env python
import sys, os

def main(folder):
    for path,dirs,files in os.walk(folder):
        count = 0;

        path = path.strip('/')
        print "#ifndef %s_H" % (path.upper())
        print "#define %s_H" % (path.upper())

        for fn in files:
            count = count + 1
            print "#include \"%s/%s\"" % (path, fn)

        if count > 0:
            count = count - 1

        print "static uint64_t %s_config_count = %u;" % (path,count)
        print "static struct config %s_configs[] = {" % path

        for fn in files:
            name = fn.partition(".")[0]
            print "\t{.name=\"%s\", .guids=%s, .syms=%s, .sym_count=&%s}," % ("%s_%s"%(path,name), "%s_%s_guid"%(path,name), "%s_%s"%(path,name), "%s_%s_count"%(path,name))

        print "};"
        print "#endif"

if __name__ == "__main__":
    main(sys.argv[1])

