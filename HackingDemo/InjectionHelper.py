__author__ = 'omerturgeman'

def print_string_as_packet (headline, str_packet):
        import sys
        print headline + ":"
        new_line = True
        l = len(str_packet) + 2
        i = 0
        while i < l - 2:
            if not new_line:
                sys.stdout.write(" ")
            sys.stdout.write(str_packet[i:i+2])
            i += 2
            sys.stdout.write(" ")
            if i % 16 == 0:
                print ""
                new_line = True
            else:
                new_line = False
        print ""
        print "-------------------------"
        print ""

class InjectionHelper:
    MY_HEX_MIC = 0