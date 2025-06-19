import os

class DumpBT (gdb.Command):
    """Collect required info for a bug report"""
    def __init__(self):
        super(DumpBT, self).__init__("dumpbt", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        pagination = gdb.parameter("pagination")
        if pagination: gdb.execute("set pagination off")
        f = open("./dumpbt.txt", "w")
        f.write(gdb.execute("bt", to_string=True))
        f.close()
        if pagination: gdb.execute("set pagination on")

DumpBT()