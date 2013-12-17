import sys, os

def main(folder):
    for path,dirs,files in os.walk(folder):
        count = 0;

        print "#ifndef SYMCONFIG_H"
        print "#define SYMCONFIG_H"

        for fn in files:
            count = count + 1
            print "#include \"%s%s\"" % (path, fn)

        print "const uint64_t config_count = %u;" % count
        print "const struct config configs[] = {"

        for fn in files:
            name = fn.partition(".")[0]
            print "\t{.name=\"%s\", .guids=%s, .syms=%s, .sym_count=&%s}," % (name, "%s_guid"%(name), name, "%s_count"%(name))

        print "};"
        print "#endif"

if __name__ == "__main__":
    main(sys.argv[1])

