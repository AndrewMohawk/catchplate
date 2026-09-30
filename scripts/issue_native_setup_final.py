"""Fixed isolated FD3/4/5 native Setup final authority; no arguments or paths."""
import os
import sys

if __name__=="__main__":
    try:
        if len(sys.argv)!=1 or not sys.flags.isolated or not sys.dont_write_bytecode:raise ValueError("fixed isolated entry required")
        from serverware.native_setup_final_authority import run
        run()
    except BaseException:os._exit(1)
